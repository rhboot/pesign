/* Copyright 2012 Red Hat, Inc.
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

#include "cms_common.h"

#if 0
typedef struct {
	SECItem data;
	SECItem keytype;
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
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(SignedCert, keytype),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
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

	generate_object_id(cms, &cert.keytype, oid);

	void *ret;
	ret = SEC_ASN1EncodeItem(NULL, sigder, &cert, SignedCertTemplate);
	if (ret == NULL)
		errx(1, "efikeygen: could not encode certificate: %s",
			PORT_ErrorToString(PORT_GetError()));

	sigder->data[sigder->len - 261] = DER_BIT_STRING;

	return 0;
}


#endif

int main(int argc, char *argv[])
{
	int is_ca = 0;
	int is_self_signed = -1;
	char *tokenname = "NSS Certificate DB";
	char *signer = NULL;
	char *outfile = NULL;
	char *cn = NULL;
	char *url = NULL;
	unsigned long serial = ULONG_MAX;

	cms_context *cms = NULL;

	poptContext optCon;
	struct poptOption options[] = {
		{NULL, '\0', POPT_ARG_INTL_DOMAIN, "pesign" },
		{"ca", 'C', POPT_ARG_VAL, &is_ca, 1,
			"Generate a CA certificate", NULL },
		{"self-sign", 'S', POPT_ARG_VAL, &is_self_signed, 1,
			"Generate a self-signed certificate", NULL },
		{"signer", 'c', POPT_ARG_STRING, &signer, 0,
			"Nickname for signing certificate", "<signer>" },
		{"token", 't', POPT_ARG_STRING|POPT_ARGFLAG_SHOW_DEFAULT,
			&tokenname, 0, "NSS token holding signing key",
			"<token>" },
		{"output", 'o', POPT_ARG_STRING, &outfile, 0,
			"Output file name", "<outfile>" },
		{"common-name", 'n', POPT_ARG_STRING, &cn, 0,
			"Common Name for generated certificate", "<cn>" },
		{"url", 'u', POPT_ARG_STRING, &url, 0,
			"Issuer URL", "<url>" },
		{"serial", 's', POPT_ARG_LONG, &serial, 0,
			"Serial number (from 0 to 4294967294)",
			"<serial>" },
		POPT_AUTOALIAS
		POPT_AUTOHELP
		POPT_TABLEEND
	};

	optCon = poptGetContext("pesign", argc, (const char **)argv, options,0);

	int rc = poptReadDefaultConfig(optCon, 0);
	if (rc < 0)
		errx(1, "efikeygen: poptReadDefaultConfig failed: %s",
			poptStrerror(rc));

	while ((rc = poptGetNextOpt(optCon)) > 0)
		;

	if (rc < -1)
		errx(1, "efikeygen: invalid argument: %s: %s",
			poptBadOption(optCon, 0), poptStrerror(rc));

	if (poptPeekArg(optCon))
		errx(1, "efikeygen: invalid Argument: \"%s\"",
			poptPeekArg(optCon));

	poptFreeContext(optCon);

	if (is_self_signed && signer)
		errx(1, "efikeygen: --self-sign and --signer cannot be "
			"used at the same time.");

	if (!cn)
		errx(1, "efikeygen: --common-name must be specified");

	if (is_ca && is_self_signed == -1)
		is_self_signed = 1;

	rc = cms_context_alloc(&cms);
	if (rc < 0)
		err(1, "efikeygen: %s:%d: could not allocate cms context:",
			__func__, __LINE__);

	if (tokenname) {
		cms->tokenname = strdup(tokenname);
		if (!cms->tokenname)
			err(1, "efikeygen: %s:%d could not allocate cms "
				"context:", __func__, __LINE__);
	}
	if (signer) {
		cms->certname = strdup(signer);
		if (!cms->certname)
			err(1, "efikeygen: %s:%d could not allocate cms "
				"context:", __func__, __LINE__);
	}

	SECStatus status = NSS_Init("/etc/pki/pesign");
	if (status != SECSuccess)
		errx(1, "efikeygen: could not initialize NSS: %s",
			PORT_ErrorToString(PORT_GetError()));
	atexit((void (*)(void))NSS_Shutdown);

	if (!is_self_signed) {
		rc = find_certificate(cms);
		if (rc < 0)
			errx(1, "efikeygen: could not find signing "
				"certificate \"%s:%s\"", cms->tokenname,
				cms->certname);
	}

	SECItem certder;
	rc = generate_signing_certificate(cms, &certder, cn, is_ca,
				is_self_signed, url, serial);
	if (rc < 0)
		errx(1, "efikeygen: could not generate certificate");

	SECOidData *oid;
	oid = SECOID_FindOIDByTag(SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION);
	if (!oid)
		errx(1, "efikeygen: could not find OID for SHA256+RSA: %s",
			PORT_ErrorToString(PORT_GetError()));

#if 0
	PK11SlotInfo *slot = NULL;
	if (!strcmp(tokenname, "NSS Certificate DB") ||
			tokenname == NULL || tokenname[0] == '\0')
		slot = PK11_GetInternalKeySlot();
	else
		slot = PK11_FindSlotByName(tokenname);

	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = &pwdata_val;
	SECKEYPrivateKey *privkey = PK11_FindKeyByAnyCert(signing_cert, pwdata);
	if (!privkey)
		errx(1, "efikeygen: could not find private key: %s",
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
		err(1, "efikeygen: could not open signed.cer");

	rc = write(fd, sigder.data, sigder.len);
	if (rc < 0)
		err(1, "efikeygen: could not write to signed.cer");

	close(fd);
#endif

	NSS_Shutdown();
	return 0;
}
