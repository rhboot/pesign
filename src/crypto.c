/*
 * Copyright 2011 Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pesign.h"

#include <nss3/nss.h>
#include <nss3/secpkcs7.h>
#include <nss3/secder.h>

int crypto_init(void)
{
	SECStatus status = NSS_InitReadWrite("/etc/pki/pesign");

	if (status == SECSuccess)
		return 0;
	return -1;
}

void crypto_fini(void)
{
	NSS_Shutdown();
}

/* read a cert generated with:
 * $ openssl req -new -key privkey.pem -out cert.csr
 * $ openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095
 */
int read_cert(int certfd, CERTCertificate **cert)
{
	struct stat statbuf;
	char *certstr = NULL;
	int rc;

	rc = fstat(certfd, &statbuf);
	if (rc < 0)
		return rc;

	int i = 0, j = statbuf.st_size;
	certstr = calloc(1, j + 1);
	if (!certstr)
		return -1;

	while (i < statbuf.st_size) {
		int x;
		x = read(certfd, certstr + i, j);
		if (x < 0) {
			free(certstr);
			return -1;
		}
		i += x;
		j -= x;
	}

	*cert = CERT_DecodeCertFromPackage(certstr, i);
	free(certstr);
	if (!*cert)
		return -1;
	return 0;
}

int pe_sign(pesign_context *ctx)
{
	//SEC_PKCS7ContentInfo *ci = NULL;

	Pe_Scn *scn = NULL;

	for (int i = 0 ; (scn = pe_getscn(ctx->inpe, i)) != NULL; i++) {
		printf("got section %d\n", i);
	}

	return 0;
}

static int saw_content;

static void
handle_bytes(void *arg, const char *buf, unsigned long len)
{
	saw_content = 1;
}

static PRBool
decryption_allowed(SECAlgorithmID *algid, PK11SymKey *key)
{
	return PR_TRUE;
}

int list_signatures(pesign_context *ctx)
{
	void *certs = NULL;
	size_t size = 0;
	int rc;
	int nsigs = 0;

	rc = pe_getdatadir(ctx->inpe, PE_DATA_DIR_CERTIFICATES, &certs, &size);
	if (rc < 0) {
		fprintf(stderr, "Could not find certificate table: %s\n",
			pe_errmsg(pe_errno()));
		return rc;
	}

	win_certificate *cert;
	for(size_t n = 0; n < size;) {
		cert = certs + n;
		uint32_t length = le32_to_cpu(cert->length);
		uint16_t rev = le16_to_cpu(cert->revision);

		if (rev != WIN_CERT_REVISION_2_0)
			goto next;

		nsigs++;
		void *data = (void *)cert + sizeof(*cert);
		size_t datalen = length - sizeof(*cert);

		SEC_PKCS7DecoderContext *dc = NULL;
		saw_content = 0;
		dc = SEC_PKCS7DecoderStart(handle_bytes, NULL, NULL, NULL,
					NULL, NULL, decryption_allowed);

		if (dc == NULL) {
			fprintf(stderr, "SEC_PKCS7DecoderStart failed\n");
			exit(1);
		}

		SECStatus status = SEC_PKCS7DecoderUpdate(dc, data, datalen);

		if (status != SECSuccess) {
			fprintf(stderr, "Found invalid certificate\n");
			goto next;
		}

		SEC_PKCS7ContentInfo *cinfo = SEC_PKCS7DecoderFinish(dc);

		if (cinfo == NULL) {
			fprintf(stderr, "Found invalid certificate\n");
			goto next;
		}

		printf("---------------------------------------------\n");
		printf("Content was%s encrypted.\n",
			SEC_PKCS7ContentIsEncrypted(cinfo) ? "" : " not");
		if (SEC_PKCS7ContentIsSigned(cinfo)) {
			char *signer_cname, *signer_ename;
			SECItem *signing_time;

			if (saw_content) {
				printf("Signature is ");
				PORT_SetError(0);
				if (SEC_PKCS7VerifySignature(cinfo,
						certUsageEmailSigner,
						PR_FALSE)) {
					printf("valid.\n");
				} else {
					printf("invalid (Reason: 0x%08x).\n",
						(uint32_t)PORT_GetError());
				}
			} else {
				printf("Content is detached; signature cannot "
					"be verified.\n");
			}

			signer_cname = SEC_PKCS7GetSignerCommonName(cinfo);
			if (signer_cname != NULL) {
				printf("The signer's common name is %s\n",
					signer_cname);
				PORT_Free(signer_cname);
			} else {
				printf("No signer common name.\n");
			}

			signer_ename = SEC_PKCS7GetSignerEmailAddress(cinfo);
			if (signer_ename != NULL) {
				printf("The signer's email address is %s\n",
					signer_ename);
				PORT_Free(signer_ename);
			} else {
				printf("No signer email address.\n");
			}

			signing_time = SEC_PKCS7GetSigningTime(cinfo);
			if (signing_time != NULL) {
				printf("Signing time: %s\n", DER_TimeChoiceDayToAscii(signing_time));
			} else {
				printf("No signing time included.\n");
			}

			printf("There were%s certs or crls included.\n",
				SEC_PKCS7ContainsCertsOrCrls(cinfo) ? "" : " no");

			SEC_PKCS7DestroyContentInfo(cinfo);
		}
next:
		n += length;
	}
	if (nsigs) {
		printf("---------------------------------------------\n");
	} else {
		printf("No signatures found.\n");
	}
	return 0;
}

int remove_signature(pesign_context *ctx, int signum)
{
	return 0;
}
