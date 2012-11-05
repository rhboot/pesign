
#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <nspr4/prtypes.h>
#include <nspr4/prerror.h>
#include <nspr4/prprf.h>

#include <nss3/nss.h>
#include <nss3/base64.h>
#include <nss3/cert.h>
#include <nss3/cryptohi.h>
#include <nss3/keyhi.h>
#include <nss3/secder.h>
#include <nss3/secerr.h>
#include <nss3/secport.h>
#include <nss3/secpkcs7.h>
#include <nss3/secoidt.h>
#include <nss3/pk11pub.h>

typedef struct {
	enum {
		PW_NONE = 0,
		PW_FROMFILE = 1,
		PW_PLAINTEXT = 2,
		PW_EXTERNAL = 3
	} source;
	char *data;
} secuPWData;

struct cbdata {
	CERTCertificate *cert;
	PK11SlotListElement *psle;
	secuPWData *pwdata;
};

static SECStatus
is_valid_cert(CERTCertificate *cert, void *data)
{
	struct cbdata *cbdata = (struct cbdata *)data;

	PK11SlotInfo *slot = cbdata->psle->slot;
	void *pwdata = cbdata->pwdata;

	SECKEYPrivateKey *privkey = NULL;

	privkey = PK11_FindPrivateKeyFromCert(slot, cert, pwdata);
	if (privkey != NULL) {
		cbdata->cert = cert;
		SECKEY_DestroyPrivateKey(privkey);
		return SECSuccess;
	}

	return SECFailure;
}

static void echoOff(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static void echoOn(int fd)
{
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
}

static PRBool SEC_BlindCheckPassword(char *cp)
{
    if (cp != NULL) {
	return PR_TRUE;
    }
    return PR_FALSE;
}

static char *SEC_GetPassword(FILE *input, FILE *output, char *prompt,
			       PRBool (*ok)(char *))
{
    int infd  = fileno(input);
    int isTTY = isatty(infd);
    char phrase[200] = {'\0'};      /* ensure EOF doesn't return junk */

    for (;;) {
	/* Prompt for password */
	if (isTTY) {
	    fprintf(output, "%s", prompt);
            fflush (output);
	    echoOff(infd);
	}

	fgets ( phrase, sizeof(phrase), input);

	if (isTTY) {
	    fprintf(output, "\n");
	    echoOn(infd);
	}

	/* stomp on newline */
	phrase[PORT_Strlen(phrase)-1] = 0;

	/* Validate password */
	if (!(*ok)(phrase)) {
	    /* Not weird enough */
	    if (!isTTY) return 0;
	    fprintf(output, "Password must be at least 8 characters long with one or more\n");
	    fprintf(output, "non-alphabetic characters\n");
	    continue;
	}
	return (char*) PORT_Strdup(phrase);
    }
}

static char consoleName[] = { "/dev/tty" };

static char *
SECU_GetPasswordString(void *arg, char *prompt)
{
    char *p = NULL;
    FILE *input, *output;

    /* open terminal */
    input = fopen(consoleName, "r");
    if (input == NULL) {
	fprintf(stderr, "Error opening input terminal for read\n");
	return NULL;
    }

    output = fopen(consoleName, "w");
    if (output == NULL) {
	fclose(input);
	fprintf(stderr, "Error opening output terminal for write\n");
	return NULL;
    }

    p = SEC_GetPassword (input, output, prompt, SEC_BlindCheckPassword);
        

    fclose(input);
    fclose(output);

    return p;
}

/*
 *  p a s s w o r d _ h a r d c o d e 
 *
 *  A function to use the password passed in the -f(pwfile) argument
 *  of the command line.  
 *  After use once, null it out otherwise PKCS11 calls us forever.?
 *
 */
static char *
SECU_FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    char *pwFile = arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;

    if (!pwFile)
	return 0;

    if (retry) {
	return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
        return 0; /* out of memory */
    }
 
    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
	fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
        PORT_Free(phrases);
	return NULL;
    }

    nb = PR_Read(fd, phrases, maxPwdFileSize);
  
    PR_Close(fd);

    if (nb == 0) {
        fprintf(stderr,"password file contains no data\n");
        PORT_Free(phrases);
        return NULL;
    }

    if (slot) {
        tokenName = PK11_GetTokenName(slot);
        if (tokenName) {
            tokenLen = PORT_Strlen(tokenName);
        }
    }
    i = 0;
    do
    {
        int startphrase = i;
        int phraseLen;

        /* handle the Windows EOL case */
        while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
        /* terminate passphrase */
        phrases[i++] = '\0';
        /* clean up any EOL before the start of the next passphrase */
        while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
            phrases[i++] = '\0';
        }
        /* now analyze the current passphrase */
        phrase = &phrases[startphrase];
        if (!tokenName)
            break;
        if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
        phraseLen = PORT_Strlen(phrase);
        if (phraseLen < (tokenLen+1)) continue;
        if (phrase[tokenLen] != ':') continue;
        phrase = &phrase[tokenLen+1];
        break;

    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

char *
get_password_passthrough(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	if (retry)
		return NULL;

	if (!arg)
		return arg;

	char *ret = strdup(arg);
	if (!ret) {
		fprintf(stderr, "Failed to allocate memory\n");
		exit(1);
	}
	return ret;
}

char *
get_password_fail(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	return NULL;
}

char *
SECU_GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg) 
{
    char prompt[255];
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };
    char *pw;

    if (pwdata == NULL)
	pwdata = &pwnull;

    if (PK11_ProtectedAuthenticationPath(slot)) {
	pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
	PR_fprintf(PR_STDERR, "Incorrect password/PIN entered.\n");
    	return NULL;
    }

    switch (pwdata->source) {
    case PW_NONE:
	sprintf(prompt, "Enter Password or Pin for \"%s\":",
	                 PK11_GetTokenName(slot));
	return SECU_GetPasswordString(NULL, prompt);
    case PW_FROMFILE:
	/* Instead of opening and closing the file every time, get the pw
	 * once, then keep it in memory (duh).
	 */
	pw = SECU_FilePasswd(slot, retry, pwdata->data);
	pwdata->source = PW_PLAINTEXT;
	pwdata->data = PL_strdup(pw);
	/* it's already been dup'ed */
	return pw;
    case PW_EXTERNAL:
	sprintf(prompt, 
	        "Press Enter, then enter PIN for \"%s\" on external device.\n",
		PK11_GetTokenName(slot));
	(void) SECU_GetPasswordString(NULL, prompt);
    	/* Fall Through */
    case PW_PLAINTEXT:
	return PL_strdup(pwdata->data);
    default:
	break;
    }

    PR_fprintf(PR_STDERR, "Password check failed:  No password found.\n");
    return NULL;
}

/* This is the dumbest function ever, but we need it anyway, because nss
 * is garbage. */
static void
PK11_DestroySlotListElement(PK11SlotList *slots, PK11SlotListElement **psle)
{
	while (psle && *psle)
		*psle = PK11_GetNextSafe(slots, *psle, PR_FALSE);
}

static int
find_cert(char *tokenname, char *nickname, CERTCertificate **ret)
{
	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = &pwdata_val;
	PK11_SetPasswordFunc(SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots)
		err(1, "could not find certificate \"%s:%s\": %s",
			tokenname, nickname,
			PORT_ErrorToString(PORT_GetError()));

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle)
		err(1, "could not find certificate \"%s:%s\": %s",
			tokenname, nickname,
			PORT_ErrorToString(PORT_GetError()));

	while (psle) {
		if (!strcmp(tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle)
		err(1, "could not find certificate \"%s:%s\": %s",
			tokenname, nickname,
			PORT_ErrorToString(PORT_GetError()));

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess)
			err(1, "could not find certificate \"%s:%s\": %s",
				tokenname, nickname,
				PORT_ErrorToString(PORT_GetError()));
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist) {
		PK11_DestroySlotListElement(slots, &psle);
		err(1, "could not find certificate \"%s:%s\": %s",
			tokenname, nickname,
			PORT_ErrorToString(PORT_GetError()));
	}

	SECItem nicknameitem = {
		.data = (void *)nickname,
		.len = strlen(nickname) + 1,
		.type = siUTF8String,
	};
	struct cbdata cbdata = {
		.cert = NULL,
		.psle = psle,
		.pwdata = pwdata,
	};

	status = PK11_TraverseCertsForNicknameInSlot(&nicknameitem, psle->slot,
						is_valid_cert, &cbdata);
	if (cbdata.cert == NULL)
		err(1, "could not find certificate \"%s:%s\": %s",
			tokenname, nickname,
			PORT_ErrorToString(PORT_GetError()));

	CERTCertificate *cert;
	cert = CERT_DupCertificate(cbdata.cert);
	*ret = cert;

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	CERT_DestroyCertList(certlist);

	return 0;
}

SEC_ASN1Template AlgorithmIDTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SECAlgorithmID),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(SECAlgorithmID, algorithm),
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_OPTIONAL |
		SEC_ASN1_ANY,
	.offset = offsetof(SECAlgorithmID, parameters),
	.sub = NULL,
	.size = 0,
	},
	{ 0, }
};

int
generate_algorithm_id(SECAlgorithmID *idp, SECOidTag tag)
{
	SECAlgorithmID id;

	if (!idp)
		return -1;

	SECOidData *oiddata;
	oiddata = SECOID_FindOIDByTag(tag);
	if (!oiddata) {
		PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
		return -1;
	}
	if (SECITEM_CopyItem(NULL, &id.algorithm, &oiddata->oid))
		return -1;

	SECITEM_AllocItem(NULL, &id.parameters, 2);
	if (id.parameters.data == NULL)
		goto err;
	id.parameters.data[0] = SEC_ASN1_NULL;
	id.parameters.data[1] = 0;
	id.parameters.type = siBuffer;

	memcpy(idp, &id, sizeof (id));
	return 0;

err:
	SECITEM_FreeItem(&id.algorithm, PR_FALSE);
	return -1;
}


typedef struct {
	SECItem data;
	SECAlgorithmID keytype;
	SECItem sig;
} SignedCert;

SEC_ASN1Template SignedCertTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof(SignedCert),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(SignedCert, data),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_INLINE,
	 .offset = offsetof(SignedCert, keytype),
	 .sub = &AlgorithmIDTemplate,
	 .size = sizeof (SECAlgorithmID),
	},
	{.kind = SEC_ASN1_OCTET_STRING,
	 .offset = offsetof(SignedCert, sig),
	 .sub = NULL,
	 .size = sizeof (SECItem),
	},
	{ 0, }
};

static int
bundle_signature(SECItem *sigder, SECItem *data, SECOidTag oid,
		SECItem *signature)
{
	SignedCert cert = {
		.data = {.data = data->data,
			 .len = data->len,
			 .type = data->type
		},
		.sig = {.data = calloc(1, signature->len + 1),
			.len = signature->len + 1,
			.type = signature->type
		}
	};

	memcpy((void *)cert.sig.data + 1, signature->data, signature->len);

	int rc = generate_algorithm_id(&cert.keytype, oid);
	if (rc < 0)
		err(1, "Could not generate algorithm ID: %s",
			PORT_ErrorToString(PORT_GetError()));

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, sigder, &cert, SignedCertTemplate);
	if (ret == NULL)
		errx(1, "Could not encode certificate: %s",
			PORT_ErrorToString(PORT_GetError()));

	sigder->data[sigder->len - 261] = DER_BIT_STRING;

	return 0;
}

typedef struct {
	SECItem keyid;
	SECItem keyusage;
	SECItem basic_constraints;
	SECItem auth_keyid;
} Extension;

SEC_ASN1Template ExtTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (Extension),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Extension, keyid),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Extension, keyusage),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Extension, basic_constraints),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Extension, auth_keyid),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 },
};

static int
generate_extensions(SECItem *der)
{
	Extension ext;

	ext.keyid.data = (unsigned char *)"\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16"
		"\x04\x14"
		"\x8c\xe3\xf6\xb8\x31\x42\x92\xfe\x6e\x2f"
		"\x80\xd5\x32\xe0\x94\x3a\x53\x93\x3d\xba";
	ext.keyid.len = 31;
	ext.keyid.type = siBuffer;

	ext.keyusage.data = (unsigned char *)"\x30\x0b\x06\x03"
		"\x55\x1d\x0f\x04\x04\x03\x02\x01\x86";
	ext.keyusage.len = 13;
	ext.keyusage.type = siBuffer;

	ext.basic_constraints.data = (unsigned char *)"\x30\x0f"
		"\x06\x03\x55\x1d\x13"
		"\x01\x01\xff"
		"\x04\x05\x30\x03\x01\x01\xff";
	ext.basic_constraints.len = 17;
	ext.basic_constraints.type = siBuffer;

	ext.auth_keyid.data = (unsigned char *)"\x30\x1f"
		"\x06\x03\x55\x1d\x23"
		"\x04\x18"
		"\x30\x16\x80\x14"
		"\x8c\xe3\xf6\xb8\x31\x42\x92\xfe\x6e\x2f"
		"\x80\xd5\x32\xe0\x94\x3a\x53\x93\x3d\xba";
	ext.auth_keyid.len = 33;
	ext.auth_keyid.type = siBuffer;

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, der, &ext, ExtTemplate);
	if (ret == NULL)
		errx(1, "Could not encode certificate extension data: %s",
			PORT_ErrorToString(PORT_GetError()));

	return 0;
}

static int
generate_extensions_wrapped(SECItem ***list)
{
	SECItem **extensions = NULL;

	extensions = PORT_ZAlloc(sizeof (SECItem *) * 2);
	if (!extensions)
		errx(1, "%d Could not allocate extension data: %s",
			__LINE__, PORT_ErrorToString(PORT_GetError()));

	SECItem *ext = PORT_ZAlloc(sizeof (SECItem));
	if (!ext)
		errx(1, "%d Could not allocate extension data: %s",
			__LINE__, PORT_ErrorToString(PORT_GetError()));

	int rc = generate_extensions(ext);
	if (rc < 0)
		errx(1, "Could not encode certificate extension data: %s",
			PORT_ErrorToString(PORT_GetError()));
	extensions[0] = ext;
	extensions[1] = NULL;

	*list = extensions;
	return 0;
}

typedef struct {
	SECItem firstblob;
	SECItem serial;
	SECItem oid;
	SECItem cn0;
	SECItem times;
	SECItem cn1;
	SECItem pubkey;
	SECItem **extensions;
} Cert;

SEC_ASN1Template CertTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof(Cert),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, firstblob),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, serial),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, oid),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, cn0),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, times),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, cn1),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Cert, pubkey),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_CONTEXT_SPECIFIC | 3 |
		 SEC_ASN1_CONSTRUCTED |
		 SEC_ASN1_OPTIONAL,
	 .offset = offsetof(Cert, extensions),
	 .sub = &SEC_SetOfAnyTemplate,
	 .size = sizeof (SECItem*),
	},
	{ 0 }
};

static int
generate_data(SECItem *der)
{
	Cert cert;

	cert.firstblob.data = (unsigned char *)"\xa0\x03\x02\x01\x02";
	cert.firstblob.len = 5;
	cert.firstblob.type = siBuffer;

	cert.serial.data = (unsigned char *)"\x02\x05\x00\x99\x76\xf2\xf4";
	cert.serial.len = 7;
	cert.serial.type = siBuffer;

	cert.oid.data = (unsigned char *)"\x30\x0d\x06\x09\x2a\x86\x48\x86"
					 "\xf7\x0d\x01\x01\x0b\x05\x00";
	cert.oid.len = 15;
	cert.oid.type = siBuffer;

#if 1
	cert.cn0.data = (unsigned char *)"\x30\x20"
					   "\x31\x1e"
					     "\x30\x1c"
					       "\x06\x03"
					         "\x55\x04\x03"
					       "\x13\x15"
					         "Fedora Secure Boot CA";
	cert.cn0.len = 34;
#else
	cert.cn0.data = (unsigned char *)"\x30\x12"
					   "\x31\x10"
					     "\x30\x0e"
					       "\x06\x03"
					         "\x55\x04\x03"
					       "\x13\x07"
					         "Test CA";
	cert.cn0.len = 20;
#endif
	cert.cn0.type = siBuffer;

	cert.times.data = (unsigned char *)"\x30\x1e\x17\x0d" "121010171458Z"
				          "\x17\x0d" "221010171458Z";
	cert.times.len = 32;

#if 1
	cert.cn1.data = (unsigned char *)"\x30\x20"
					   "\x31\x1e"
					     "\x30\x1c"
					       "\x06\x03"
					         "\x55\x04\x03"
					       "\x13\x15"
					         "Fedora Secure Boot CA";
	cert.cn1.len = 34;
#else
	cert.cn1.data = (unsigned char *)"\x30\x12"
					   "\x31\x10"
					     "\x30\x0e"
					       "\x06\x03"
					         "\x55\x04\x03"
					       "\x13\x07"
					         "Test CA";
	cert.cn1.len = 20;
#endif
	cert.cn1.type = siBuffer;

	cert.pubkey.data = (unsigned char *)
		"\x30\x82\x01\x22"
		  "\x30\x0d"
		    "\x06\x09"
		      "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
		    "\x05\x00"
		"\x03\x82\x01\x0f"
#if 1
		  "\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00"
		  "\xae\xf5\xf7\x52\x81\xa9\x5c\x3e\x2b\xf7"
		  "\x1d\x55\xf4\x5a\x68\x84\x2d\xbc\x8b\x76"
		  "\x96\x85\x0d\x27\xb8\x18\xa5\xcd\xc1\x83"
		  "\xb2\x8c\x27\x5d\x23\x0a\xd1\x12\x0a\x75"
		  "\x98\xa2\xe6\x5d\x01\x8a\xf4\xd9\x9f\xfc"
		  "\x70\xbc\xc3\xc4\x17\x7b\x02\xb5\x13\xc4"
		  "\x51\x92\xe0\xc0\x05\x74\xb9\x2e\x3d\x24"
		  "\x78\xa0\x79\x73\x94\xc0\xc2\x2b\xb2\x82"
		  "\xa7\xf4\xab\x67\x4a\x22\xf3\x64\xcd\xc3"
		  "\xf9\x0c\x26\x01\xbf\x1b\xd5\x3d\x39\xbf"
		  "\xc9\xfa\xfb\x5e\x52\xb9\xa4\x48\xfb\x13"
		  "\xbf\x87\x29\x0a\x64\xef\x21\x7b\xbc\x1e"
		  "\x16\x7b\x88\x4f\xf1\x40\x2b\xd9\x22\x15"
		  "\x47\x4e\x84\xf6\x24\x1c\x4d\x53\x16\x5a"
		  "\xb1\x29\xbb\x5e\x7d\x7f\xc0\xd4\xe2\xd5"
		  "\x79\xaf\x59\x73\x02\xdc\xb7\x48\xbf\xae"
		  "\x2b\x70\xc1\xfa\x74\x7f\x79\xf5\xee\x23"
		  "\xd0\x03\x05\xb1\x79\x18\x4f\xfd\x4f\x2f"
		  "\xe2\x63\x19\x4d\x77\xba\xc1\x2c\x8b\xb3"
		  "\xd9\x05\x2e\xd9\xd8\xb6\x51\x13\xbf\xce"
		  "\x36\x67\x97\xe4\xad\x58\x56\x07\xab\xd0"
		  "\x8c\x66\x12\x49\xdc\x91\x68\xb4\xc8\xea"
		  "\xdd\x9c\xc0\x81\xc6\x91\x5b\xdb\x12\x78"
		  "\xdb\xff\xc1\xaf\x08\x16\xfc\x70\x13\x97"
		  "\x5b\x57\xad\x6b\x44\x98\x7e\x1f\xec\xed"
		  "\x46\x66\x95\x0f\x05\x55\x02\x03\x01\x00"
		  "\x01";
#else
		  "\x00\x30\x82\x01\x0a\x02\x82\x01" 
		  "\x01\x00\xc3\x8d\xa5\x60\x0f\xea" 
		  "\xde\x7f\x6d\x9b\x61\xb9\x65\x38" 
		  "\x14\x9f\xaa\xbb\xf4\x97\xdf\x45" 
		  "\x1e\xd6\xb5\xec\x2c\xcc\xc3\xec" 
		  "\x03\x5e\xa9\x15\x96\xf2\xd2\xb2" 
		  "\x85\x77\x9e\xcc\x6d\xdc\x09\xf8" 
		  "\xc1\xb9\xd7\x18\x7b\xbe\x97\x2f" 
		  "\x6a\xb2\x2e\xb2\xf5\x72\xe2\xa4" 
		  "\xb4\xf9\x7d\x0a\x35\xdc\x36\x6e" 
		  "\x72\x53\x86\xef\xb0\xfc\x4a\x36" 
		  "\x89\xa5\x48\x88\xac\xb9\x4b\xff" 
		  "\x3d\x95\x3e\x14\x9b\x9f\x35\x21" 
		  "\x94\xc7\xb9\x91\x53\xbe\x23\xd1" 
		  "\x2f\xea\x22\x62\xe2\x01\x39\x0e" 
		  "\xd1\x37\x7c\x1b\xc6\x40\xe6\x9b" 
		  "\x85\x33\x72\xa2\xe1\x56\x24\x0f" 
		  "\xdb\xfd\x56\x65\x18\xd5\xe3\x5b" 
		  "\xf7\x27\x28\xb2\x25\xef\xcb\x68" 
		  "\xec\x2c\xde\x96\x65\x2c\xee\x9c" 
		  "\x3e\x40\x5c\xbd\xeb\x77\x28\xaa" 
		  "\x1d\xd1\x60\xea\x97\x7c\x22\xa4" 
		  "\x22\x5e\x22\x0c\x9f\x65\x89\x50" 
		  "\x33\xb8\x54\x7f\xe8\xf0\x16\x1c" 
		  "\x60\x46\xae\xae\x43\xe8\xbe\x02" 
		  "\xa3\x05\x94\xa2\x0a\xf5\xd0\x1b" 
		  "\x47\xb1\x6d\x52\x9d\x1a\xcb\xa2" 
		  "\x6b\xf1\x9c\x20\x5e\xd1\x3e\xf0" 
		  "\xaa\x2c\xac\x8c\x29\xc4\xe2\x79" 
		  "\x4c\x11\x1b\x22\x1e\x5b\x7c\x67" 
		  "\x33\x14\x43\x68\x8b\x32\x6c\x27" 
		  "\x93\x4b\xcc\x8f\x10\xf5\x2b\xe4" 
		  "\x60\x1e\x24\x26\x6c\xba\xa1\xc6" 
		  "\xdf\x19\x02\x03\x01\x00\x01";
#endif
	cert.pubkey.len = 294;
	cert.pubkey.type = siBuffer;

	int rc = generate_extensions_wrapped(&cert.extensions);
	if (rc < 0)
		errx(1, "Could not encode certificate extension data: %s",
			PORT_ErrorToString(PORT_GetError()));

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, der, &cert, CertTemplate);
	if (ret == NULL)
		errx(1, "Could not encode certificate data: %s",
			PORT_ErrorToString(PORT_GetError()));

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr,
			"usage: ./sign <token> <nickname> <output>\n");
		exit(1);
	}
	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
		printf("usage: ./sign <token> <nickname> <output>\n");
		exit(0);
	}

	SECStatus status = NSS_Init(".");
	if (status != SECSuccess)
		errx(1, "Could not initialize NSS: %s\n",
			PORT_ErrorToString(PORT_GetError()));
	CERTCertificate *cert = NULL;
	int rc = find_cert(argv[1], argv[2], &cert);

	SECItem certder = { 0, };
	rc = generate_data(&certder);
	if (rc < 0)
		errx(1, "Could not generate certificate\n");

	SECOidData *oid;
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
	if (!oid)
		errx(1, "Could not find OID for SHA256+RSA: %s\n",
			PORT_ErrorToString(PORT_GetError()));

	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = &pwdata_val;
	SECKEYPrivateKey *privkey = PK11_FindKeyByAnyCert(cert, pwdata);
	if (!privkey)
		errx(1, "Could not find private key: %s\n",
			PORT_ErrorToString(PORT_GetError()));

	SECItem signature;
	status = SEC_SignData(&signature, certder.data, certder.len,
				privkey, oid->offset);

	SECItem sigder = { 0, };
	bundle_signature(&sigder, &certder,
				SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
				&signature);

	int fd = open(argv[3], O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd < 0)
		err(1, "Could not open signed.cer");
	
	rc = write(fd, sigder.data, sigder.len);
	if (rc < 0)
		err(1, "Could not write to signed.cer");
	
	close(fd);

	NSS_Shutdown();
	return 0;
}
