/*
 * Copyright 2012-2013 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author(s): Peter Jones <pjones@redhat.com>
 */

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

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

#include "cms_common.h"
#include "util.h"

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
		usage = KU_KEY_CERT_SIGN |
			KU_CRL_SIGN |
			KU_DIGITAL_SIGNATURE;
	} else {
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

static int
add_cert_type(cms_context *cms, void *extHandle, int is_ca)
{
	SECItem bitStringValue;
	unsigned char type = NS_CERT_TYPE_APP;

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

static int
add_basic_constraints(cms_context *cms, void *extHandle)
{
	CERTBasicConstraints basicConstraint;
	basicConstraint.pathLenConstraint = CERT_UNLIMITED_PATH_CONSTRAINT;
	basicConstraint.isCA = PR_TRUE;

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
add_extended_key_usage(cms_context *cms, void *extHandle)
{
	SECItem value = {
		.data = (unsigned char *)"\x30\x0a\x06\x08\x2b\x06\x01"
					 "\x05\x05\x07\x03\x03",
		.len = 12,
		.type = siBuffer
	};


	SECStatus status;

	status = CERT_AddExtension(extHandle, SEC_OID_X509_EXT_KEY_USAGE,
					&value, PR_FALSE, PR_TRUE);
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
			char *url)
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

	if (is_ca) {
		rc = add_basic_constraints(cms, extHandle);
		if (rc < 0)
			cmsreterr(-1, cms, "could not generate certificate "
					"extensions");
	}

	rc = add_key_usage(cms, extHandle, is_ca);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	rc = add_extended_key_usage(cms, extHandle);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

	rc = add_cert_type(cms, extHandle, is_ca);
	if (rc < 0)
		cmsreterr(-1, cms, "could not generate certificate extensions");

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

	for (int i; crq->attributes[i]; i++) {
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

int main(int argc, char *argv[])
{
	int is_ca = 0;
	int is_self_signed = -1;
	char *tokenname = "NSS Certificate DB";
	char *signer = NULL;
	char *nickname = NULL;
	char *pubfile = NULL;
	char *cn = NULL;
	char *url = NULL;
	char *serial_str = NULL;
	char *issuer = NULL;
	char *dbdir = "/etc/pki/pesign";
	unsigned long serial = ULONG_MAX;

	cms_context *cms = NULL;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		/* global nss-ish things */
		{"dbdir", 'd', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&dbdir, 0, "Directory for nss database", "<directory>"},
		{"token", 't', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&tokenname, 0, "NSS token holding signing key",
			"<token>" },
		{"signer", '\0', POPT_ARG_STRING, &signer, 0,
			"Nickname for signing certificate", "<signer>" },

		/* type of thing we're creating */
		{"ca", 'C', POPT_ARG_VAL, &is_ca, 1,
			"Generate a CA certificate", NULL },
		{"self-sign", 'S', POPT_ARG_VAL,
			&is_self_signed, 1,
			"Generate a self-signed certificate", NULL },

		/* stuff about the generated key */
		{"nickname", 'n', POPT_ARG_STRING, &nickname, 0,
			"Generated certificate's nickname", "<nickname>" },
		{"common-name", 'c', POPT_ARG_STRING, &cn, 0,
			"Common Name for generated certificate", "<cn>" },
		{"url", 'u', POPT_ARG_STRING, &url, 0,
			"Issuer URL", "<url>" },
		{"serial", 's', POPT_ARG_STRING, &serial_str, 0,
			"Serial number", "<serial>" },

		/* hidden things */
		{"pubkey", 'p', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&pubfile, 0,
			"Use public key from file", "<pubkey>" },
		{"issuer-cn", 'i', POPT_ARG_STRING|POPT_ARGFLAG_DOC_HIDDEN,
			&issuer, 0,
			"Issuer Common Name", "<issuer-cn>" },

		/* automatic stuff */
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	int rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0)
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
	 *         is_ca        is_self_signed       pubkey
	 * i_c     x            x                    x
	 * i_s_s   x            x                    o
	 * pubkey  x            o                    o
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

	rc = cms_context_alloc(&cms);
	if (rc < 0)
		liberr(1, "could not allocate cms context");

	if (tokenname) {
		cms->tokenname = strdup(tokenname);
		if (!cms->tokenname)
			liberr(1, "could not allocate cms context");
	}
	if (signer) {
		cms->certname = strdup(signer);
		if (!cms->certname)
			liberr(1, "could not allocate cms context");
	}

	SECStatus status = NSS_InitReadWrite(dbdir);
	if (status != SECSuccess)
		nsserr(1, "could not initialize NSS");
	atexit((void (*)(void))NSS_Shutdown);

	SECKEYPublicKey *spubkey = NULL;
	SECKEYPrivateKey *sprivkey = NULL;

	SECKEYPublicKey *pubkey = NULL;
	SECKEYPrivateKey *privkey = NULL;

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
	serial = strtoul(serial_str, NULL, 0);
	if (errno == ERANGE && serial == ULLONG_MAX)
		liberr(1, "invalid serial number");

	CERTValidity *validity = NULL;
	PRTime not_before = time(NULL) * PR_USEC_PER_SEC;
	PRTime not_after = not_before + (3650ULL * 86400ULL * PR_USEC_PER_SEC);
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
					spubkey, url);
	if (rc < 0)
		exit(1);

	CERTCertificate *cert = NULL;
	cert = CERT_CreateCertificate(serial, issuer_name, validity, crq);
	*(cert->version.data) = 2;
	cert->version.len = 1;

	cert->subjectName = cn;
	cert->issuerName = is_self_signed ? cn : issuer;

	memcpy(&cert->issuer, issuer_name, sizeof (cert->issuer));
	memcpy(&cert->subject, name, sizeof (cert->subject));

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

	SECItem sigder = { 0, };
	bundle_signature(cms, &sigder, &certder,
				SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
				&signature);

	status = PK11_ImportDERCert(slot, &sigder, CK_INVALID_HANDLE, nickname,
				PR_FALSE);

	NSS_Shutdown();
	return 0;
}
