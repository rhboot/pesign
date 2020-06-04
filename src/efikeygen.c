// SPDX-License-Identifier: GPLv2
/*
 * efikeygen.c - key generation with reasonable defaults for Secure Boot
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <prtypes.h>
#include <prerror.h>
#include <prprf.h>

#include <nss.h>
#include <base64.h>
#include <cert.h>
#include <cryptohi.h>
#include <keyhi.h>
#include <secder.h>
#include <secerr.h>
#include <secport.h>
#include <secpkcs7.h>
#include <secoidt.h>
#include <pk11pub.h>

#include <libdpe/libdpe.h>

#include "util.h"
#include "cms_common.h"
#include "errno-guard.h"
#include "oid.h"
#include "password.h"

enum {
	MODSIGN_EKU_NONE,
	MODSIGN_EKU_KERNEL,
	MODSIGN_EKU_MODULE,
	MODSIGN_EKU_CA
};

typedef struct {
	SECItem data;
	SECAlgorithmID keytype;
	SECItem sig;
} SignedCert;

static SEC_ASN1Template SignedCertTemplate[] = {
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
	 .sub = &SECOID_AlgorithmIDTemplate,
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
bundle_signature(cms_context *cms, SECItem *sigder, SECItem *data,
		SECOidTag oid, SECItem *signature)
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

	int rc = generate_algorithm_id(cms, &cert.keytype, oid);
	if (rc < 0)
		return -1;

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, sigder, &cert, SignedCertTemplate);
	if (ret == NULL)
		errx(1, "could not encode certificate: %s",
			PORT_ErrorToString(PORT_GetError()));

	sigder->data[sigder->len - 261] = DER_BIT_STRING;

	return 0;
}

static int
add_subject_key_id(cms_context *cms, void *extHandle, SECKEYPublicKey *pubkey)
{
	SECItem *pubkey_der = PK11_DEREncodePublicKey(pubkey);
	if (!pubkey_der)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	SECItem *encoded = PK11_MakeIDFromPubKey(pubkey_der);
	if (!encoded)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	/* for some reason PK11_MakeIDFromPubKey() doesn't generate the final
	 * wrapper for this... */
	SECItem wrapped = { 0 };
	int rc = generate_octet_string(cms, &wrapped, encoded);
	if (rc < 0)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	SECStatus status;
	status = CERT_AddExtension(extHandle, SEC_OID_X509_SUBJECT_KEY_ID,
					&wrapped, PR_FALSE, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	return 0;
}

static int
add_auth_key_id(cms_context *cms, void *extHandle, SECKEYPublicKey *pubkey)
{
	SECItem *pubkey_der = PK11_DEREncodePublicKey(pubkey);
	if (!pubkey_der)
		cmserr(-1, cms, "could not encode CA Key ID extension");

	SECItem *encoded = PK11_MakeIDFromPubKey(pubkey_der);
	if (!encoded)
		cmserr(-1, cms, "could not encode CA Key ID extension");

	SECItem cspecific = { 0 };
	int rc = make_context_specific(cms, 0, &cspecific, encoded);
	if (rc < 0)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	/* for some reason PK11_MakeIDFromPubKey() doesn't generate the final
	 * wrapper for this... */
	SECItem wrapped = { 0 };
	rc = wrap_in_seq(cms, &wrapped, &cspecific, 1);
	if (rc < 0)
		cmsreterr(-1, cms, "could not encode subject key id extension");

	SECStatus status;
	status = CERT_AddExtension(extHandle, SEC_OID_X509_AUTH_KEY_ID,
					&wrapped, PR_FALSE, PR_TRUE);
	if (status != SECSuccess)
		cmserr(-1, cms, "could not encode CA Key ID extension");
	return 0;
}


static int
add_key_usage(cms_context *cms, void *extHandle, int is_ca)
{
	SECCertificateUsage usage;
	SECItem bitStringValue;

	if (is_ca) {
		usage = KU_DIGITAL_SIGNATURE |
			KU_KEY_CERT_SIGN |
			KU_CRL_SIGN;
	} else {
		return 0;
		usage = KU_KEY_ENCIPHERMENT |
			KU_DATA_ENCIPHERMENT |
			KU_DIGITAL_SIGNATURE;
	}

	bitStringValue.data = (unsigned char *)&usage;
	bitStringValue.len = sizeof (usage);

	SECStatus status;
	status = CERT_EncodeAndAddBitStrExtension(extHandle,
				SEC_OID_X509_KEY_USAGE,
				&bitStringValue, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode key usage extension");

	return 0;
}

#if 0
static int
add_cert_type(cms_context *cms, void *extHandle, int is_ca)
{
	SECItem bitStringValue;
	int type = NS_CERT_TYPE_APP;

	if (is_ca)
		type |= NS_CERT_TYPE_SSL_CA |
			NS_CERT_TYPE_EMAIL_CA |
			NS_CERT_TYPE_OBJECT_SIGNING_CA;
	bitStringValue.data = (unsigned char *)&type;
	bitStringValue.len = sizeof (type);

	SECStatus status;
	status = CERT_EncodeAndAddBitStrExtension(extHandle,
				SEC_OID_NS_CERT_EXT_CERT_TYPE,
				&bitStringValue, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode certificate type extension");

	return 0;
}
#endif

static int
add_basic_constraints(cms_context *cms, void *extHandle, int is_ca)
{
	CERTBasicConstraints basicConstraint;
	basicConstraint.pathLenConstraint = CERT_UNLIMITED_PATH_CONSTRAINT;
	basicConstraint.isCA = is_ca ? PR_TRUE : PR_FALSE;

	SECStatus status;

	SECItem encoded;

	status = CERT_EncodeBasicConstraintValue(cms->arena, &basicConstraint,
					&encoded);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode basic constraints");

	status = CERT_AddExtension(extHandle, SEC_OID_X509_BASIC_CONSTRAINTS,
					&encoded, PR_TRUE, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode basic constraints");

	return 0;
}

static int
add_extended_key_usage(cms_context *cms, int modsign_eku, void *extHandle)
{
	SECItem values[3];
	SECItem wrapped = { 0 };
	SECStatus status;
	SECOidTag tag;
	int rc;
	size_t nvals = 0;

	if (modsign_eku == MODSIGN_EKU_CA)
		return 0;

	if (modsign_eku != MODSIGN_EKU_KERNEL
	    && modsign_eku != MODSIGN_EKU_MODULE)
		cmsreterr(-1, cms, "could not encode extended key usage");

	rc = make_eku_oid(cms, &values[nvals++], SEC_OID_EXT_KEY_USAGE_CODE_SIGN);
	if (rc < 0)
		cmsreterr(-1, cms, "could not encode extended key usage");


	if (modsign_eku == MODSIGN_EKU_MODULE) {
		tag = find_ms_oid_tag(SHIM_EKU_MODULE_SIGNING_ONLY);
		rc = make_eku_oid(cms, &values[nvals++], tag);
		if (rc < 0)
			cmsreterr(-1, cms, "could not encode extended key usage");
	}

	rc = wrap_in_seq(cms, &wrapped, values, nvals);
	if (rc < 0)
		cmsreterr(-1, cms, "could not encode extended key usage");

	status = CERT_AddExtension(extHandle, SEC_OID_X509_EXT_KEY_USAGE,
					&wrapped, PR_FALSE, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode extended key usage");

	return 0;
}

static int
add_auth_info(cms_context *cms, void *extHandle, char *url)
{
	SECItem value;
	int rc;

	rc = generate_auth_info(cms, &value, url);
	if (rc < 0)
		return rc;

	SECStatus status;

	status = CERT_AddExtension(extHandle, SEC_OID_X509_AUTH_INFO_ACCESS,
				&value, PR_FALSE, PR_TRUE);
	if (status != SECSuccess)
		cmsreterr(-1, cms, "could not encode key authority information "
				"access extension");

	return 0;
}

static int
add_extensions_to_crq(cms_context *cms, CERTCertificateRequest *crq,
			int is_ca, int is_self_signed, SECKEYPublicKey *pubkey,
			SECKEYPublicKey *spubkey,
			char *url, int modsign_eku)
{
	void *mark = PORT_ArenaMark(cms->arena);

	void *extHandle;
	int rc;
	extHandle = CERT_StartCertificateRequestAttributes(crq);
	if (!extHandle)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	rc = add_subject_key_id(cms, extHandle, pubkey);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	rc = add_basic_constraints(cms, extHandle, is_ca);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate "
				"extensions");

	rc = add_key_usage(cms, extHandle, is_ca);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	rc = add_extended_key_usage(cms, modsign_eku, extHandle);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

#if 0
	rc = add_cert_type(cms, extHandle, is_ca);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");
#endif

	if (is_self_signed)
		rc = add_auth_key_id(cms, extHandle, pubkey);
	else
		rc = add_auth_key_id(cms, extHandle, spubkey);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	if (url) {
		rc = add_auth_info(cms, extHandle, url);
		if (rc < 0)
			cmsreterr(-1, cms,
				"could not generate certificate extensions");
	}

	CERT_FinishExtensions(extHandle);
	CERT_FinishCertificateRequestAttributes(crq);
	PORT_ArenaUnmark(cms->arena, mark);
	return 0;
}

static int
populate_extensions(cms_context *cms, CERTCertificate *cert,
			CERTCertificateRequest *crq)
{
	CERTAttribute *attr = NULL;
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_EXTENSION_REQUEST);

	for (int i = 0; crq->attributes[i]; i++) {
		attr = crq->attributes[i];
		if (attr->attrType.len != oid->oid.len)
			continue;
		if (!memcmp(attr->attrType.data, oid->oid.data, oid->oid.len))
			break;
		attr = NULL;
	}

	if (!attr)
		cmsreterr(-1, cms, "could not find extension request");

	SECStatus rv;
	rv = SEC_QuickDERDecodeItem(cms->arena, &cert->extensions,
				CERT_SequenceOfCertExtensionTemplate,
				*attr->attrValue);
	if (rv != SECSuccess)
		cmsreterr(-1, cms, "could not decode certificate extensions");
	return 0;
}

static int
get_pubkey_from_file(char *pubfile, SECKEYPublicKey **pubkey)
{
	SECItem pubkey_item = {
		.type = siBuffer,
		.data = NULL,
		.len = -1
	};

	int pubfd = open(pubfile, O_RDONLY);
	if (pubfd < 0)
		libreterr(-1, "could not open \"%s\"", pubfile);

	char *data = NULL;
	size_t *len = (size_t *)&pubkey_item.len;

	int rc = read_file(pubfd, &data, len);
	if (rc < 0)
		libreterr(-1, "could not read public key");

	pubkey_item.data = (unsigned char *)data;
	*pubkey = SECKEY_ImportDERPublicKey(&pubkey_item, CKK_RSA);
	if (!*pubkey)
		nssreterr(-1, "could not decode public key");

	return 0;
}

static int
get_signer_private_key(cms_context *cms, SECKEYPrivateKey **privkey)
{
	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = &pwdata_val;
	SECKEYPrivateKey *sprivkey;
	sprivkey = PK11_FindKeyByAnyCert(cms->cert, pwdata);
	if (!sprivkey)
		cmsreterr(-1, cms, "could not find private key");

	*privkey = sprivkey;
	return 0;
}

static int
get_signer_public_key(cms_context *cms, SECKEYPublicKey **pubkey)
{
	SECKEYPublicKey *spubkey;
	spubkey = CERT_ExtractPublicKey(cms->cert);
	if (!spubkey)
		cmsreterr(-1, cms, "could not find public key");

	*pubkey = spubkey;
	return 0;
}

/* Of course this doesn't exist in 1990's crypto library. */
SECItem *
SEC_ASN1EncodeLongLong(PRArenaPool *poolp, SECItem *dest,
				unsigned long long value)
{
	unsigned long copy;
	unsigned char sign;
	int len = 0;

	copy = value;
	do {
		len++;
		sign = (unsigned char)(copy & 0x80);
		copy >>= 8;
	} while (copy);

	if (sign)
		len++;

	dest = SECITEM_AllocItem(poolp, dest, len);
	if (dest == NULL)
		return NULL;

	memset(dest->data, '\0', len);

	dest->len = len;
	while (len) {
		dest->data[--len] = value & 0xff;
		value >>= 8;
	}

	return dest;
}

static const struct {
	mode_t mode;
	int idx;
	char c;
} modebits[] = {
	{S_IRUSR, 0, 'r'},
	{S_IWUSR, 1, 'w'},
	{S_IXUSR, 2, 'x'},
	{S_ISUID, 2, 's'},
	{S_IXUSR|S_ISUID, 2, 'S'},
	{S_IRGRP, 3, 'r'},
	{S_IWGRP, 4, 'w'},
	{S_IXGRP, 5, 'x'},
	{S_ISGID, 5, 's'},
	{S_IXGRP|S_ISGID, 5, 'S'},
	{S_IROTH, 6, 'r'},
	{S_IWOTH, 7, 'w'},
	{S_IXOTH, 8, 'x'},
	{S_ISVTX, 8, 't'},
	{S_IXOTH|S_ISVTX, 8, 'T'},
	{0, 0, 0}
};

static void
format_file_mode(mode_t mode, char modestr[10])
{
	for (unsigned int i = 0; modebits[i].mode != 0; i++) {
		mode_t mask = ~modebits[i].mode;
		if (~(mode & mask) == modebits[i].mode)
			modestr[modebits[i].idx] = modebits[i].c;
	}
}

static void
enforce_file_mode(mode_t badmask, const char * filename, int fd)
{
	struct stat statbuf;
	xpfstat(filename, fd, &statbuf);
	if (!(statbuf.st_mode & badmask))
		return;

	char filemode[] = "---------";

	close(fd);
	format_file_mode(statbuf.st_mode, filemode);
	errx(1, "Password file \"%s\" has unsafe file mode %s; not proceeding.",
	     filename, filemode);
}

static void
get_pw_env(pk12_file_t *file, const char *arg)
{
	if (!file)
		errx(1, "--pk12-pw-env must be paired with --pk12-in or --pk12-out");
	file->pw = secure_getenv(arg);
	if (file->pw == NULL)
		errx(1, "Environment variable \"%s\" is not set.", arg);
	file->pw = xstrdup(file->pw);
	if (!file->pw)
		err(1, "Could not allocate memory");
}

static void
get_pw_file(pk12_file_t *file, const char *arg)
{
	int fd;
	int rc;
	int errno_guard;
	char *pw = NULL;
	size_t pwsize = 0;

	if (!file)
		errx(1, "--pk12-pw-file must be paired with --pk12-in or --pk12-out");

	fd = xopen(arg, O_RDONLY);
	enforce_file_mode(0077, arg, fd);
	rc = read_file(fd, &pw, &pwsize);
	errno = 0;
	set_errno_guard_with_override(&errno_guard);

	close(fd);

	if (rc < 0)
		err(1, "Could not read \"%s\"", arg);
	for (ssize_t i = pwsize; i >= 0; i--) {
		switch (pw[i]) {
		case '\r':
		case '\n':
			pw[i] = '\0';
			/* fall through */
		case '\0':
			continue;
		default:
			break;
		}
	}
	file->pw = pw;
}

void
popt_callback(poptContext con UNUSED,
	      enum poptCallbackReason reason UNUSED,
	      const struct poptOption *opt,
	      const char *arg, const void *data)
{
	cms_context *cms = (cms_context *)data;
	static pk12_file_t *prev = NULL;
	pk12_file_t *file = NULL;

	if (!opt)
		return;

	switch (opt->shortName) {
	case '\0':
		if (!strcmp(opt->longName, "pk12-pw-env")) {
			get_pw_env(prev, arg);
		} else if (!strcmp(opt->longName, "pk12-pw-file")) {
			get_pw_file(prev, arg);
		} else {
			errx(1,
			     "Unknown option \"%s\" - how did it come to this?",
			     opt->longName);
		}
		break;

	case 'P':
		file = xcalloc(1, sizeof(*file));
		file->path = xstrdup(arg);
		file->fd = xopen(arg, O_RDONLY);
		list_add(&file->list, &cms->pk12_ins);
		prev = file;
		break;

	case 'O':
		file = &cms->pk12_out;
		if (file->path)
			errx(1, "pk12 output is already set to \"%s\"", file->path);
		file->path = xstrdup(arg);
		file->fd = xopen(arg, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
		prev = file;
		break;

	default:
		errx(1, "How did it come to this?");
	}
}

static long verbose = 0;

long verbosity(void)
{
	return verbose;
}

int main(int argc, char *argv[])
{
	int is_ca = 0;
	int is_self_signed = -1;
	int modsign_eku = MODSIGN_EKU_NONE;
	char *tokenname = "NSS Certificate DB";
	char *signer = NULL;
	char *nickname = NULL;
	char *pubfile = NULL;
	char *cn = NULL;
	char *url = NULL;
	char *serial_str = NULL;
	char *issuer = NULL;
	char *dbdir = "/etc/pki/pesign";
	char *db_path = NULL, *dbx_path = NULL, *dbt_path = NULL;
	char *kek_nickname = NULL;
	unsigned long long serial = ULLONG_MAX;
	uuid_t serial_uuid;
	int rc;
	SECStatus status;
	char *not_valid_before = NULL, *not_valid_after = NULL;
	PRTime not_before = PR_Now();
	PRTime not_after;
	PRStatus prstatus;

	cms_context *cms = NULL;

	poptContext optCon;
	struct poptOption options[] = {
		{.argInfo = POPT_ARG_INTL_DOMAIN,
		 .arg = "pesign" },
		/* global nss-ish things */
		{.longName = "dbdir",
		 .shortName = 'd',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &dbdir,
		 .descrip = "Directory for nss database",
		 .argDescrip = "<directory>"},
		{.longName = "token",
		 .shortName = 't',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
		 .arg = &tokenname,
		 .descrip = "NSS token holding signing key",
		 .argDescrip = "<token>" },
		{.longName = "signer",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &signer,
		 .descrip = "Nickname for signing certificate",
		 .argDescrip = "<signer>" },

		/* type of thing we're creating */
		{.longName = "ca",
		 .shortName = 'C',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &is_ca,
		 .val = 1,
		 .descrip = "Generate a CA certificate" },
		{.longName = "self-sign",
		 .shortName = 'S',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &is_self_signed,
		 .val = 1,
		 .descrip = "Generate a self-signed certificate" },

		/* stuff about the generated key */
		{.longName = "kernel",
		 .shortName = 'k',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &modsign_eku,
		 .val = MODSIGN_EKU_KERNEL,
		 .descrip = "Generate a kernel-signing certificate" },
		{.longName = "module",
		 .shortName = 'm',
		 .argInfo = POPT_ARG_VAL|POPT_ARGFLAG_OR,
		 .arg = &modsign_eku,
		 .val = MODSIGN_EKU_MODULE,
		 .descrip = "Generate a module-signing certificate" },
		{.longName = "nickname",
		 .shortName = 'n',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &nickname,
		 .descrip = "Generated certificate's nickname",
		 .argDescrip = "<nickname>" },
		{.longName = "common-name",
		 .shortName = 'c',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &cn,
		 .descrip = "Common Name for generated certificate",
		 .argDescrip = "<cn>" },
		{.longName = "url",
		 .shortName = 'u',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &url,
		 .descrip = "Issuer URL",
		 .argDescrip = "<url>" },
		{.longName = "serial",
		 .shortName = 's',
		 .argInfo = POPT_ARG_STRING,
		 .arg = &serial_str,
		 .descrip = "Serial number (default: random)",
		 .argDescrip = "<serial>" },
		{.longName = "verbose",
		 .shortName = 'v',
		 .argInfo = POPT_ARG_VAL,
		 .arg = &verbose,
		 .val = 1,
		 .descrip = "Be more verbose" },
		{.longName = "debug",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_VAL|POPT_ARG_LONG|POPT_ARGFLAG_OPTIONAL,
		 .arg = &verbose,
		 .val = 2,
		 .descrip = "Be very verbose" },

		/* hidden things */
		{.longName = "pubkey",
		 .shortName = 'p',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &pubfile,
		 .descrip = "Use public key from file",
		 .argDescrip = "<pubkey>" },
		{.longName = "issuer-cn",
		 .shortName = 'i',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &issuer,
		 .descrip = "Issuer Common Name",
		 .argDescrip = "<issuer-cn>" },
		{.longName = "not-valid-before",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &not_valid_before,
		 .descrip = "\"Not Valid Before\" date",
		 .argDescrip = "<date>",
		},
		{.longName = "not-valid-after",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &not_valid_after,
		 .descrip = "\"Not Valid After\" date",
		 .argDescrip = "<date>",
		},

		/*
		 * The features below here are hidden because they're not
		 * really ready for consumption yet.
		 */
		{.longName = "pk12-in",
		 .shortName = 'P',
		 .argInfo = POPT_ARG_CALLBACK|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = (void *)popt_callback,
		 .descrip = (void *)cms,
		 .argDescrip = "<keydb.pk12>"},
		{.longName = "pk12-out",
		 .shortName = 'O',
		 .argInfo = POPT_ARG_CALLBACK|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = (void *)popt_callback,
		 .descrip = (void *)cms,
		 .argDescrip = "<out.pk12>"},
		{.longName = "pk12-pw-file",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_CALLBACK|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = (void *)popt_callback,
		 .descrip = (void *)cms,
		 .argDescrip = "<file.pw>"},
		{.longName = "pk12-pw-env",
		 .shortName = '\0',
		 .argInfo = POPT_ARG_CALLBACK|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = (void *)popt_callback,
		 .descrip = (void *)cms,
		 .argDescrip = "<ENVIRONMENT VARIABLE NAME>"},
		{.longName = "kek-nickname",
		 .shortName = 'K',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &kek_nickname,
		 .descrip = "Nickname of the KEK signing key (defaults to same as signer)",
		 .argDescrip = "<KEK nickname>"},
		{.longName = "make-efi-db",
		 .shortName = 'D',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &db_path,
		 .descrip = "File to store a signed DB append in",
		 .argDescrip = "<db.bin>"},
		{.longName = "make-efi-dbx",
		 .shortName = 'X',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &dbx_path,
		 .descrip = "File to store a signed DBX append in",
		 .argDescrip = "<dbx.bin>"},
		{.longName = "make-efi-dbt",
		 .shortName = 'T',
		 .argInfo = POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
		 .arg = &dbt_path,
		 .descrip = "File to store a signed DBT append in",
		 .argDescrip = "<dbt.bin>"},

		/* automatic stuff */
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);

	rc = cms_context_alloc(&cms);
	if (rc < 0)
		liberr(1, "could not allocate cms context");

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0 && !(rc == POPT_ERROR_ERRNO && errno == ENOENT))
		errx(1, "poptReadDefaultConfig failed: %s",
			poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "invalid argument: %s: %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "invalid Argument: \"%s\"",
			poptPeekArg(optCon));

	poptFreeContext(optCon);

	/*
	 * Scenarios that are okay (x == valid combination)
	 *
	 *		is_ca   is_self_signed  pubkey	modules	kernel
	 * i_c		x       x               x	o	o
	 * i_s_s	x       x               o	o	o
	 * pubkey	x       o               x	x	x
	 * modules	o	x		x	x	x
	 * kernel	o	x		x	x	x
	 */

	if (is_self_signed == -1)
		is_self_signed = is_ca && !signer ? 1 : 0;

	if (is_self_signed && signer)
		errx(1, "--self-sign and --signer cannot be "
			"used at the same time.");

	if (is_self_signed && pubfile)
		errx(1, "--self-sign and --pubkey cannot be "
			"used at the same time.");

	if (!cn)
		errx(1, "--common-name must be specified");

	if (!is_self_signed && !signer)
		errx(1, "signing certificate is required");

	if (tokenname) {
		cms->tokenname = strdup(tokenname);
		if (!cms->tokenname)
			err(1, "could not allocate cms context");
	}
	if (signer) {
		cms->certname = strdup(signer);
		if (!cms->certname)
			err(1, "could not allocate cms context");
	}

	if (is_ca) {
		if (modsign_eku != MODSIGN_EKU_NONE)
			errx(1, "CA certificates cannot have kernel or module signing credentials.");
		modsign_eku = MODSIGN_EKU_CA;
	} else if (modsign_eku != MODSIGN_EKU_KERNEL
		   && modsign_eku != MODSIGN_EKU_MODULE) {
		errx(1, "either --kernel or --module must be used");
	}

	if (!strcmp(dbdir, "-") && list_empty(&cms->pk12_ins) && !is_self_signed)
		errx(1, "'--dbdir -' requires either --pk12-in or --self-sign.");

	PK11_SetPasswordFunc(cms->func ? cms->func : readpw);
	if (strcmp(dbdir, "-")) {
		if (cms->pk12_out.fd >= 0)
			status = NSS_Init(dbdir);
		else
			status = NSS_InitReadWrite(dbdir);
	} else {
		status = NSS_NoDB_Init(dbdir);
	}
	if (status != SECSuccess)
		nsserr(1, "could not initialize NSS");
	atexit((void (*)(void))NSS_Shutdown);

	SECKEYPublicKey *spubkey = NULL;
	SECKEYPrivateKey *sprivkey = NULL;

	SECKEYPublicKey *pubkey = NULL;
	SECKEYPrivateKey *privkey = NULL;

	status = register_oids(cms);
	if (status != SECSuccess)
		nsserr(1, "Could not register OIDs");

	PK11SlotInfo *slot = NULL;
	if (pubfile) {
		rc = get_pubkey_from_file(pubfile, &pubkey);
	} else {
		rc = find_slot_for_token(cms, &slot);
		if (rc < 0)
			nsserr(1, "could not find NSS slot for token \"%s\"",
				cms->tokenname);

		rc = generate_keys(cms, slot, &privkey, &pubkey);
	}
	if (rc < 0)
		exit(1);

	CERTName *issuer_name = NULL;
	if (issuer) {
		issuer_name = CERT_AsciiToName(issuer);
	} else if (is_self_signed) {
		issuer_name = CERT_AsciiToName(cn);
	} else {
		rc = find_certificate(cms, 1);
		if (rc < 0)
			nsserr(1, "could not find signing certificate "
				"\"%s:%s\"", cms->tokenname, cms->certname);
		issuer_name = &cms->cert->subject;
	}
	if (!issuer_name)
		nsserr(1, "could not find issuer name");

	if (is_self_signed) {
		spubkey = pubkey;
		sprivkey = privkey;
	} else {
		rc = find_certificate(cms, 1);
		if (rc < 0)
			exit(1);

		rc = get_signer_private_key(cms, &sprivkey);
		if (rc < 0)
			exit(1);

		rc = get_signer_public_key(cms, &spubkey);
		if (rc < 0)
			exit(1);
	}

	errno = 0;
	if (serial_str) {
		serial = strtoull(serial_str, NULL, 0);
		if (errno == ERANGE && serial == ULLONG_MAX)
			liberr(1, "invalid serial number");
	}

	if (not_valid_before) {
		unsigned long timeul;
		char *endptr;

		errno = 0;
		timeul = strtoul(not_valid_before, &endptr, 0);
		dprintf("not_valid_before:%lu", timeul);
		if (errno == 0 && endptr && *endptr == 0) {
			dprintf("not_valid_before:%lu", timeul);
			not_before = (PRTime)timeul * PR_USEC_PER_SEC;
		} else {
			prstatus = PR_ParseTimeString(not_valid_before,
						PR_TRUE, &not_before);
			conderrx(prstatus != PR_SUCCESS, 1,
				 "could not parse date \"%s\"",
				 not_valid_before);
		}
		dprintf("not_before:%"PRId64, not_before);
	}

	if (not_valid_after) {
		unsigned long timeul;
		char *endptr;

		errno = 0;
		dprintf("not_valid_after:%s", not_valid_after);
		timeul = strtoul(not_valid_after, &endptr, 0);
		dprintf("not_valid_after:%lu", timeul);
		if (errno == 0 && endptr && *endptr == 0) {
			dprintf("not_valid_after:%lu", timeul);
			not_after = (PRTime)timeul * PR_USEC_PER_SEC;
		} else {
			prstatus = PR_ParseTimeString(not_valid_after, PR_TRUE,
						      &not_after);
			conderrx(prstatus != PR_SUCCESS, 1,
				 "could not parse date \"%s\"",
				 not_valid_after);
		}
	} else {
		// Mon Jan 19 03:14:07 GMT 2037, aka 0x7fffffff minus 1 year.
		time_t time = 0x7ffffffful - 60ul * 60 * 24 * 365;
		dprintf("not_valid_after:%lu", time);
		not_after = (PRTime)time * PR_USEC_PER_SEC;
	}
	dprintf("not_after:%"PRId64, not_after);

	CERTValidity *validity = NULL;
	validity = CERT_CreateValidity(not_before, not_after);
	if (!validity)
		nsserr(1, "could not generate validity");

	CERTName *name = CERT_AsciiToName(cn);
	if (!name)
		nsserr(1, "could not generate certificate name");

	CERTSubjectPublicKeyInfo *spki = NULL;
	spki = SECKEY_CreateSubjectPublicKeyInfo(pubkey);
	if (!spki)
		nsserr(1, "could not generate public key information");

	SECItem *attributes = NULL;

	CERTCertificateRequest *crq = NULL;
	crq = CERT_CreateCertificateRequest(name, spki, &attributes);

	rc = add_extensions_to_crq(cms, crq, is_ca, is_self_signed, pubkey,
					spubkey, url, modsign_eku);
	if (rc < 0)
		exit(1);

	CERTCertificate *cert = NULL;
	cert = CERT_CreateCertificate(0, issuer_name, validity, crq);
	*(cert->version.data) = 2;
	cert->version.len = 1;

	cert->subjectName = cn;
	cert->issuerName = is_self_signed ? cn : issuer;

	cert->serialNumber.data = NULL;
	cert->serialNumber.len = 0;

	memcpy(&cert->issuer, issuer_name, sizeof (cert->issuer));
	memcpy(&cert->subject, name, sizeof (cert->subject));

	if (serial == ULLONG_MAX && serial_str == NULL) {
		uuid_clear(serial_uuid);
		if (!uuid_is_null(serial_uuid))
			liberr(1, "Null serial number wasn't null");
		uuid_generate_random(serial_uuid);
		if (uuid_is_null(serial_uuid))
			liberr(1, "Random serial number was null");

		if (serial_uuid[0] & 0x80) {
			int type = cert->serialNumber.type;
			SECItem *ret;
			ret = SECITEM_AllocItem(cms->arena, &cert->serialNumber,
				sizeof(serial_uuid) + 1);
			if (!ret)
				nsserr(1, "Could not allocate serial number");
			cert->serialNumber.data[0] = '\0';
			memcpy(cert->serialNumber.data + 1, serial_uuid,
				sizeof (serial_uuid));
			cert->serialNumber.type = type;
		} else {
			cert->serialNumber.data = serial_uuid;
			cert->serialNumber.len = sizeof (serial_uuid);
		}
	} else {
		SECItem *ret = SEC_ASN1EncodeLongLong(cms->arena,
					&cert->serialNumber,
					serial);
		if (!ret)
			nsserr(1, "Could not allocate serial number");
	}

	rc = populate_extensions(cms, cert, crq);
	if (rc < 0)
		exit(1);

	rc = generate_algorithm_id(cms, &cert->signature, SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
	if (rc < 0)
		nsserr(1, "could not generate certificate type OID");

	SECItem certder;
	memset(&certder, '\0', sizeof (certder));

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, &certder, cert,
		CERT_CertificateTemplate);
	if (ret == NULL)
		nsserr(1, "could not encode certificate");

	if (is_self_signed) {
		cms->cert = cert;
#if 0
		status = SEC_QuickDERDecodeItem(cms->arena, &cms->cert,
			CERT_CertificateTemplate, &certder);
		if (status != SECSuccess)
			nsserr(1, "could not decode certificate");
#endif
	}

	SECOidData *oid;
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
	if (!oid)
		nsserr(1, "could not find OID for SHA256+RSA");

	SECItem signature;
	status = SEC_SignData(&signature, certder.data, certder.len,
				sprivkey, oid->offset);
	if (status != SECSuccess)
		nsserr(1, "could not create signature");

	SECItem sigder = { 0, };
	bundle_signature(cms, &sigder, &certder,
				SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
				&signature);

	status = PK11_ImportDERCert(slot, &sigder, CK_INVALID_HANDLE, nickname,
				PR_FALSE);
	if (status != SECSuccess)
		nsserr(1, "could not import signature");

	NSS_Shutdown();
	return 0;
}

// vim:fenc=utf-8:tw=75:noet
