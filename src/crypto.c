/*
 * Copyright 2011-2012 Red Hat, Inc.
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pesign.h"

#include <nspr4/prerror.h>

#include <nss3/nss.h>
#include <nss3/secport.h>
#include <nss3/secpkcs7.h>
#include <nss3/secder.h>
#include <nss3/base64.h>
#include <nss3/pk11pub.h>
#include <nss3/secerr.h>

int
cms_context_init(cms_context *ctx)
{
	SECStatus status;
	
	status = NSS_InitReadWrite("/etc/pki/pesign");
	if (status != SECSuccess)
		return -1;

	status = register_oids();
	if (status != SECSuccess)
		return -1;

	ctx->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!ctx->arena) {
		fprintf(stderr, "Could not create cryptographic arena: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

void
cms_context_fini(cms_context *ctx)
{
	if (ctx->cert) {
		CERT_DestroyCertificate(ctx->cert);
		ctx->cert = NULL;
	}

	if (ctx->privkey) {
		free(ctx->privkey);
		ctx->privkey = NULL;
	}

	if (ctx->algorithm_id) {
		free_poison(ctx->algorithm_id->algorithm.data,
			ctx->algorithm_id->algorithm.len);
		//SECITEM_FreeItem(&ctx->algorithm_id->algorithm, PR_FALSE);
		free_poison(ctx->algorithm_id->parameters.data,
			ctx->algorithm_id->parameters.len);
		//SECITEM_FreeItem(&ctx->algorithm_id->parameters, PR_FALSE);
		free_poison(ctx->algorithm_id, sizeof (*ctx->algorithm_id));
		free(ctx->algorithm_id);
		ctx->algorithm_id = NULL;
	}

	if (ctx->digest) {
		free_poison(ctx->digest->data, ctx->digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		ctx->digest = NULL;
	}

	PORT_FreeArena(ctx->arena, PR_TRUE);
	memset(ctx, '\0', sizeof(*ctx));

	NSS_Shutdown();
}

/* read a cert generated with:
 * $ openssl genrsa -out privkey.pem 2048
 * $ openssl req -new -key privkey.pem -out cert.csr
 * $ openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095
 * See also: http://www.openssl.org/docs/HOWTO/keys.txt
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

	data_directory *dd;

	int rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return -1;

	void *map;
	size_t map_size;

	map = pe_rawfile(pe, &map_size);
	if (!map)
		return -1;

	iter->certs = map + dd->certs.virtual_address;
	iter->size = dd->certs.size;

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

#define SHA1_DIGEST_SIZE	20
#define SHA256_DIGEST_SIZE	32
#define MAX_DIGEST_SIZE		SHA256_DIGEST_SIZE
#define HASH_TYPE		SEC_OID_SHA256

static int
setup_algorithm_id(cms_context *ctx)
{
	SECAlgorithmID *id;

	id = malloc(sizeof (*id));
	if (!id)
		return -1;

	SECOidData *oiddata;

	oiddata = SECOID_FindOIDByTag(SEC_OID_SHA256);
	if (!oiddata) {
		PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
		goto err;
	}
	if (SECITEM_CopyItem(ctx->arena, &id->algorithm, &oiddata->oid))
		goto err;

	SECITEM_AllocItem(ctx->arena, &id->parameters, 2);
	if (id->parameters.data == NULL)
		goto err_copy;
	id->parameters.data[0] = SEC_ASN1_NULL;
	id->parameters.data[1] = 0;
	id->parameters.type = siBuffer;

	ctx->algorithm_id = id;
	return 0;
err_copy:
	SECITEM_FreeItem(&id->algorithm, PR_FALSE);
err:
	free_poison(id, sizeof(*id));
	free(id);
	return -1;
}

static void
SignOut(void *arg, const char *buf, unsigned long len)
{
	FILE *out;

	out = (FILE *)arg;
	fwrite(buf, len, 1, out);
}

/* before you run this, you'll need to enroll your CA with:
 * certutil -A -n 'my CA' -d /etc/pki/pesign -t CT,CT,CT -i ca.crt
 * And you'll need to enroll the private key like this:
 * pk12util -d /etc/pki/pesign/ -i Peter\ Jones.p12 
 */
int
generate_signature(pesign_context *p_ctx)
{
	int rc = 0;
	cms_context *ctx = &p_ctx->cms_ctx;

	if (setup_algorithm_id(ctx) < 0) {
		fprintf(stderr, "Could not set up algorithm ID: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	assert(ctx->digest != NULL);

	SECItem ci_der;
	rc = generate_spc_content_info(&ci_der, ctx);
	if (rc < 0) {
		fprintf(stderr, "Could not create content info: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	SECItem si_der;
	rc = generate_spc_signer_info(&si_der, ctx);
	if (rc < 0) {
		fprintf(stderr, "Could not create signer info: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}
	
	SignOut(stdout, (char *)si_der.data, si_der.len);
	exit(1);

#if 0
	SECItem sd_der = { 0, };
	rc = generate_spc_signed_data(&sd_der, &ci, HASH_TYPE);

	SignOut(stdout, (char *)sd_der.data, sd_der.len);

#endif
	return 0;
#if 0
	SECStatus status;
	SEC_PKCS7ContentInfo *ci = NULL;
	SECItem digest;

	digest.data = (unsigned char *)ctx->digest;
	digest.len = ctx->digest_size;

	PORT_SetError(0);
	ci = SEC_PKCS7CreateSignedData(ctx->cert, certUsageObjectSigner,
		NULL, HASH_TYPE, NULL, NULL, NULL);
	if (!ci) {
		fprintf(stderr, "Could not create signed data: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}


	status = SEC_PKCS7SetContent(ci, ctx->digest, ctx->digest_size);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not set content info: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		rc = -1;
	}

	status = SEC_PKCS7AddSigningTime(ci);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not add signing time: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		rc = -1;
	}

	status = SEC_PKCS7IncludeCertChain(ci, NULL);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not include cert chain: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		rc = -1;
	}

	status = SEC_PKCS7Encode(ci, SignOut, stdout, NULL, NULL, &pwdata);
	if (status != SECSuccess) {
		fprintf(stderr, "Could not encode content: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		rc = -1;
	}

	if (ci)
		SEC_PKCS7DestroyContentInfo(ci);
#endif
	return rc;
}

int
generate_digest(pesign_context *ctx)
{
	unsigned char digest[MAX_DIGEST_SIZE];
	unsigned int digest_size = 0;
	void *hash_base;
	size_t hash_size;
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;
	PK11Context *pk11ctx;
	uint64_t hashed_bytes = 0;
	int rc = -1;

	Pe *pe = ctx->inpe;
	if (!pe)
		return -1;

	struct pe_hdr pehdr;
	if (pe_getpehdr(pe, &pehdr) == NULL)
		return -1;

	void *map = NULL;
	size_t map_size = 0;

	/* 1. Load the image header into memory - should be done
	 * 2. Initialize SHA hash context. */
	map = pe_rawfile(pe, &map_size);
	if (!map)
		return -1;

	pk11ctx = PK11_CreateDigestContext(HASH_TYPE);
	if (!pk11ctx)
		return -1;
	PK11_DigestBegin(pk11ctx);

	/* 3. Calculate the distance from the base of the image header to the
	 * image checksum.
	 * 4. Hash the image header from start to the beginning of the
	 * checksum. */
	hash_base = map;
	switch (pe_kind(pe)) {
	case PE_K_PE_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe32opthdr = opthdr;
		hash_size = (uint64_t)&pe32opthdr->csum - (uint64_t)hash_base;
		break;
	}
	case PE_K_PE64_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe64opthdr = opthdr;
		hash_size = (uint64_t)&pe64opthdr->csum - (uint64_t)hash_base;
		break;
	}
	default:
		goto error;
	}
	PK11_DigestOp(pk11ctx, hash_base, hash_size);

	/* 5. Skip over the image checksum
	 * 6. Get the address of the beginning of the cert dir entry
	 * 7. Hash from the end of the csum to the start of the cert dirent. */
	hash_base += hash_size;
	hash_base += pe32opthdr ? sizeof(pe32opthdr->csum)
				: sizeof(pe64opthdr->csum);
	data_directory *dd;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0 || !dd)
		goto error;

	hash_size = (uint64_t)&dd->certs - (uint64_t)hash_base;
	PK11_DigestOp(pk11ctx, hash_base, hash_size);

	/* 8. Skip over the crt dir
	 * 9. Hash everything up to the end of the image header. */
	hash_base = &dd->base_relocations;
	hash_size = (pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size) -
		((uint64_t)&dd->base_relocations - (uint64_t)map);
	PK11_DigestOp(pk11ctx, hash_base, hash_size);

	/* 10. Set SUM_OF_BYTES_HASHED to the size of the header. */
	hashed_bytes = pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size;

	struct section_header *shdrs = calloc(pehdr.sections, sizeof (*shdrs));
	if (!shdrs)
		goto error;
	Pe_Scn *scn = NULL;
	for (int i = 0; i < pehdr.sections; i++) {
		scn = pe_nextscn(pe, scn);
		if (scn == NULL)
			break;
		pe_getshdr(scn, &shdrs[i]);
	}
	sort_shdrs(shdrs, pehdr.sections - 1);

	for (int i = 0; i < pehdr.sections; i++) {
		hash_base = (void *)((uint64_t)map + shdrs[i].data_addr);
		hash_size = shdrs[i].raw_data_size;
		PK11_DigestOp(pk11ctx, hash_base, hash_size);

		hashed_bytes += hash_size;
	}

	if (map_size > hashed_bytes) {
		hash_base = (void *)((uint64_t)map + hashed_bytes);
		hash_size = map_size - dd->certs.size - hashed_bytes;
		PK11_DigestOp(pk11ctx, hash_base, hash_size);
	}

	PK11_DigestFinal(pk11ctx, digest, &digest_size, MAX_DIGEST_SIZE);

	if ((ctx->cms_ctx.digest = SECITEM_AllocItem(ctx->cms_ctx.arena,
			NULL, digest_size)) == NULL)
		goto error_shdrs;

	memcpy(ctx->cms_ctx.digest->data, digest, digest_size);

	rc = 0;
error_shdrs:
	if (shdrs)
		free(shdrs);
error:
	PK11_DestroyContext(pk11ctx, PR_TRUE);
	return rc;
}

int
import_signature(pesign_context *ctx)
{
	return 0;
}

int
remove_signature(pesign_context *ctx, int signum)
{
	/* XXX FIXME: right now we clear them all... */
	data_directory *dd;

	int rc = pe_getdatadir(ctx->inpe, &dd);
	if (rc < 0 || !dd)
		return -1;

	dd->certs.virtual_address = 0;
	dd->certs.size = 0;
	return 0;
}
