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
#include <nss3/base64.h>

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
	char *certstr = NULL;
	size_t certlen = 0;
	int rc;

	rc = read_file(certfd, &certstr, &certlen);
	if (rc < 0)
		return -1;

	*cert = CERT_DecodeCertFromPackage(certstr, certlen);
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

typedef struct {
	Pe *pe;
	off_t n;
	void *certs;
	size_t size;
} cert_iter;

static int
cert_iter_init(cert_iter *iter, Pe *pe)
{
	iter->pe = pe;
	iter->n = 0;

	int rc = pe_getdatadir(pe, PE_DATA_DIR_CERTIFICATES, &iter->certs,
				&iter->size);
	return rc;
}

static int
next_cert(cert_iter *iter, void **cert, ssize_t *cert_size)
{
	if (!iter)
		return -1;
	if (!iter->certs)
		return -1;

	if (iter->n >= iter->size) {
done:
		*cert = NULL;
		*cert_size = -1;
		return 0;
	}

	off_t n = iter->n;
	void *certs = iter->certs;
	size_t size = iter->size;

	while (1) {
		win_certificate *tmpcert;
		if (n + sizeof (*tmpcert) >= size)
			goto done;

		tmpcert = (win_certificate *)((uint8_t *)certs + n);

		/* length _includes_ the size of the structure. */
		uint32_t length = le32_to_cpu(tmpcert->length);

		if (length < sizeof (*tmpcert))
			return -1;

		n += sizeof (*tmpcert);
		length -= sizeof (*tmpcert);

		if (n + length > size)
			goto done;

		if (length == 0)
			continue;

		uint16_t rev = le16_to_cpu(tmpcert->revision);
		if (rev != WIN_CERT_REVISION_2_0)
			continue;

		if (cert)
			*cert = (uint8_t *)tmpcert + sizeof(*tmpcert);
		if (cert_size)
			*cert_size = length;

		iter->n = n;

		return 1;
	}
}

int
has_signatures(pesign_context *ctx)
{
	cert_iter iter;

	int rc = cert_iter_init(&iter, ctx->inpe);
	if (rc < 0)
		return 0;

	rc = next_cert(&iter, NULL, NULL);
	if (rc <= 0)
		return 0;
	return 1;
}

int
list_signatures(pesign_context *ctx)
{
	cert_iter iter;

	int rc = cert_iter_init(&iter, ctx->inpe);

	if (rc < 0) {
		printf("No certificate list found.\n");
		return rc;
	}

	void *data;
	ssize_t datalen;
	int nsigs = 0;

	rc = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

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
			continue;
		}

		SEC_PKCS7ContentInfo *cinfo = SEC_PKCS7DecoderFinish(dc);

		if (cinfo == NULL) {
			fprintf(stderr, "Found invalid certificate\n");
			continue;
		}

		nsigs++;
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
	}
	if (nsigs) {
		printf("---------------------------------------------\n");
	} else {
		printf("No signatures found.\n");
	}
	return rc;
}

static const char *sig_begin_marker ="-----BEGIN AUTHENTICODE SIGNATURE-----\n";
static const char *sig_end_marker = "\n-----END AUTHENTICODE SIGNATURE-----\n";

void
export_signature(pesign_context *ctx)
{
	cert_iter iter;

	int rc = cert_iter_init(&iter, ctx->inpe);

	if (rc < 0) {
		printf("No certificate list found.\n");
		return;
	}

	void *data;
	ssize_t datalen;
	int nsigs = 0;

	if (ctx->signum < 0)
		ctx->signum = 0;

	rc = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

		if (nsigs < ctx->signum) {
			nsigs++;
			continue;
		}

		if (ctx->ascii) {
			char *ascii = BTOA_DataToAscii(data, datalen);
			if (!ascii) {
				fprintf(stderr, "Error exporting signature\n");
failure:
				close(ctx->outsigfd);
				unlink(ctx->outsig);
				exit(1);
			}

			rc = write(ctx->outsigfd, sig_begin_marker,
					strlen(sig_begin_marker));
			if (rc < 0) {
				fprintf(stderr, "Error exporting signature: %m\n");
				goto failure;
			}

			rc = write(ctx->outsigfd, ascii, strlen(ascii));
			if (rc < 0) {
				fprintf(stderr, "Error exporting signature: %m\n");
				goto failure;
			}

			rc = write(ctx->outsigfd, sig_end_marker,
				strlen(sig_end_marker));
			if (rc < 0) {
				fprintf(stderr, "Error exporting signature: %m\n");
				goto failure;
			}

			PORT_Free(ascii);
		} else {
			rc = write(ctx->outsigfd, data, datalen);
			if (rc < 0) {
				fprintf(stderr, "Error exporting signature: %m\n");
				goto failure;
			}
		}
	}
}

void
parse_signature(pesign_context *ctx)
{
	int rc;
	char *sig;
	size_t siglen;

	rc = read_file(ctx->insigfd, &sig, &siglen);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not read signature.\n");
		exit(1);
	}
	close(ctx->insigfd);
	ctx->insigfd = -1;

	unsigned char *der;
	unsigned int derlen;
	

	/* XXX FIXME: ignoring length for now */
	char *base64 = strstr(sig, sig_begin_marker);
	if (base64) {
		base64 += strlen(sig_begin_marker);
		char *end = strstr(base64, sig_end_marker);
		if (!end) {
			fprintf(stderr, "pesign: Invalid signature.\n");
			exit(1);
		}
	
		derlen = end - base64;
		base64[derlen] = '\0';

		der = ATOB_AsciiToData(base64, &derlen);
	} else {
		der = PORT_Alloc(siglen);
		memmove(der, sig, siglen);
		derlen = siglen;
	}
	free(sig);

	SEC_PKCS7DecoderContext *dc = NULL;
	saw_content = 0;
	dc = SEC_PKCS7DecoderStart(handle_bytes, NULL, NULL, NULL, NULL, NULL,
				decryption_allowed);
	if (dc == NULL) {
decoder_error:
		fprintf(stderr, "pesign: Invalid signature.\n");
		PORT_Free(der);
		exit(1);
	}

	SECStatus status = SEC_PKCS7DecoderUpdate(dc, (char *)der, derlen);
	if (status != SECSuccess)
		goto decoder_error;

	SEC_PKCS7ContentInfo *cinfo = SEC_PKCS7DecoderFinish(dc);
	if (!cinfo)
		goto decoder_error;

	ctx->cinfo = cinfo;
	PORT_Free(der);
}

void
generate_signature(pesign_context *ctx)
{
	return;
}

int
import_signature(pesign_context *ctx)
{
	return 0;
}

int
remove_signature(pesign_context *ctx, int signum)
{
	return 0;
}
