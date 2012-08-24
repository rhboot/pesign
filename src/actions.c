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

int
parse_signatures(pesign_context *ctx)
{
	cert_iter iter;
	int rc = cert_iter_init(&iter, ctx->inpe);
	if (rc < 0)
		return -1;

	void *data;
	ssize_t datalen;
	int nsigs = 0;

	rc = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;
		nsigs++;
	}

	if (nsigs == 0) {
		ctx->cms_ctx.num_signatures = 0;
		ctx->cms_ctx.signatures = NULL;
		return 0;
	}

	SECItem **signatures = calloc(nsigs, sizeof (SECItem *));
	if (!signatures)
		return -1;

	rc = cert_iter_init(&iter, ctx->inpe);
	if (rc < 0)
		goto err;

	int i = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

		signatures[i] = calloc(1, sizeof (SECItem *));
		if (!signatures[i])
			goto err;

		signatures[i]->data = calloc(1, datalen);
		if (!signatures[i]->data)
			goto err;

		memcpy(signatures[i]->data, data, datalen);
		signatures[i]->len = datalen;
		signatures[i]->type = siBuffer;
		i++;
	}

	ctx->cms_ctx.num_signatures = nsigs;
	ctx->cms_ctx.signatures = signatures;

	return 0;
err:
	if (signatures) {
		for (i = 0; i < nsigs; i++) {
			if (signatures[i]) {
				if (signatures[i]->data)
					free(signatures[i]->data);
				free(signatures[i]);
			}
		}
		free(signatures);
	}
	return -1;
}

int
insert_signature(pesign_context *ctx)
{
	SECItem *sig = &ctx->cms_ctx.newsig;

	if (ctx->signum == -1)
		ctx->signum = ctx->cms_ctx.num_signatures;

	SECItem **signatures = realloc(ctx->cms_ctx.signatures,
		sizeof (SECItem *) * ctx->cms_ctx.num_signatures + 1);
	if (!signatures)
		return -1;
	ctx->cms_ctx.signatures = signatures;
	if (ctx->signum != ctx->cms_ctx.num_signatures) {
		memmove(ctx->cms_ctx.signatures[ctx->signum+1],
			ctx->cms_ctx.signatures[ctx->signum],
			sizeof(SECItem *) * (ctx->cms_ctx.num_signatures -
						ctx->signum));
	}
	ctx->cms_ctx.signatures[ctx->signum] = sig;
	ctx->cms_ctx.num_signatures++;
	return 0;
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
export_pubkey(pesign_context *p_ctx)
{
	cms_context *ctx = &p_ctx->cms_ctx;
	int rc;

	SECItem derPublicKey = ctx->cert->derPublicKey;
	rc = write(p_ctx->outkeyfd, derPublicKey.data, derPublicKey.len);
	close(p_ctx->outkeyfd);
	if (rc == derPublicKey.len)
		exit(0);
	exit(1);
}

void
export_cert(pesign_context *p_ctx)
{
	cms_context *ctx = &p_ctx->cms_ctx;
	int rc;

	SECItem derCert = ctx->cert->derCert;
	rc = write(p_ctx->outcertfd, derCert.data, derCert.len);
	close(p_ctx->outcertfd);
	if (rc == derCert.len)
		exit(0);
	exit(1);
}


void
export_signature(pesign_context *p_ctx)
{
	int rc = 0;

	SECItem *sig = &p_ctx->cms_ctx.newsig;

	unsigned char *data = sig->data;
	int datalen = sig->len;
	if (p_ctx->ascii) {
		char *ascii = BTOA_DataToAscii(data, datalen);
		if (!ascii) {
			fprintf(stderr, "Error exporting signature\n");
failure:
			close(p_ctx->outsigfd);
			unlink(p_ctx->outsig);
			exit(1);
		}

		rc = write(p_ctx->outsigfd, sig_begin_marker,
				strlen(sig_begin_marker));
		if (rc < 0) {
			fprintf(stderr, "Error exporting signature: %m\n");
			goto failure;
		}

		rc = write(p_ctx->outsigfd, ascii, strlen(ascii));
		if (rc < 0) {
			fprintf(stderr, "Error exporting signature: %m\n");
			goto failure;
		}

		rc = write(p_ctx->outsigfd, sig_end_marker,
			strlen(sig_end_marker));
		if (rc < 0) {
			fprintf(stderr, "Error exporting signature: %m\n");
			goto failure;
		}

		PORT_Free(ascii);
	} else {
		rc = write(p_ctx->outsigfd, data, datalen);
		if (rc < 0) {
			fprintf(stderr, "Error exporting signature: %m\n");
			goto failure;
		}
	}
}

static void
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

	ctx->cms_ctx.newsig.data = der;
	ctx->cms_ctx.newsig.len = derlen;

#if 0
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
#endif
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

	assert(ctx->pe_digest != NULL);

	SECItem sd_der;
	memset(&sd_der, '\0', sizeof(sd_der));
	rc = generate_spc_signed_data(&sd_der, ctx);
	if (rc < 0) {
		fprintf(stderr, "Could not create signed data: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	memcpy(&ctx->newsig, &sd_der, sizeof (ctx->newsig));
	return 0;
}

void
import_raw_signature(pesign_context *pctx)
{
	if (pctx->rawsigfd < 0 || pctx->insattrsfd < 0) {
		fprintf(stderr, "pesign: raw signature and signed attributes "
			"must both be imported.\n");
		exit(1);
	}

	cms_context *ctx = &pctx->cms_ctx;

	ctx->raw_signature = SECITEM_AllocItem(ctx->arena, NULL, 0);
	ctx->raw_signature->type = siBuffer;
	int rc = read_file(pctx->rawsigfd,
				(char **)&ctx->raw_signature->data,
				(size_t *)&ctx->raw_signature->len);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not read raw signature: %m\n");
		exit(1);
	}

	ctx->raw_signed_attrs = SECITEM_AllocItem(ctx->arena, NULL, 0);
	ctx->raw_signed_attrs->type = siBuffer;
	rc = read_file(pctx->insattrsfd,
				(char **)&ctx->raw_signed_attrs->data,
				(size_t *)&ctx->raw_signed_attrs->len);
	if (rc < 0) {
		fprintf(stderr, "pesign: could not read raw signed attributes"
				": %m\n");
		exit(1);
	}
}

int
generate_sattr_blob(pesign_context *ctx)
{
	int rc;
	SECItem sa;

	rc = generate_signed_attributes(&ctx->cms_ctx, &sa);
	if (rc < 0) {
		fprintf(stderr, "Could not generate signed attributes: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		exit(1);
	}

	return write(ctx->outsattrsfd, sa.data, sa.len);
}

static int
check_pointer_and_size(Pe *pe, void *ptr, size_t size)
{
	void *map = NULL;
	size_t map_size = 0;

	map = pe_rawfile(pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	if ((uintptr_t)ptr < (uintptr_t)map)
		return 0;

	if ((uintptr_t)ptr + size > (uintptr_t)map + map_size)
		return 0;

	if (ptr <= map && size >= map_size)
		return 0;

	return 1;
}

int
generate_digest(pesign_context *ctx, Pe *pe)
{
	void *hash_base;
	size_t hash_size;
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;
	PK11Context *pk11ctx;
	unsigned long hashed_bytes = 0;
	int rc = -1;

	if (!pe) {
		fprintf(stderr, "pesign: no output pe ready\n");
		exit(1);
	}

	struct pe_hdr pehdr;
	if (pe_getpehdr(pe, &pehdr) == NULL) {
		fprintf(stderr, "pesign: invalid output file header\n");
		exit(1);
	}

	void *map = NULL;
	size_t map_size = 0;

	/* 1. Load the image header into memory - should be done
	 * 2. Initialize SHA hash context. */
	map = pe_rawfile(pe, &map_size);
	if (!map) {
		fprintf(stderr, "pesign: could not get raw output file address\n");
		exit(1);
	}

	pk11ctx = PK11_CreateDigestContext(ctx->cms_ctx.digest_oid_tag);
	if (!pk11ctx) {
		fprintf(stderr, "pesign: could not initialize digest\n");
		exit(1);
	}
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
		hash_size = (uintptr_t)&pe32opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	case PE_K_PE64_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe64opthdr = opthdr;
		hash_size = (uintptr_t)&pe64opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	default:
		goto error;
	}
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		fprintf(stderr, "Pe header is invalid.  Aborting.\n");
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
	if (rc < 0 || !dd || !check_pointer_and_size(pe, dd, sizeof(*dd))) {
		fprintf(stderr, "Data directory is invalid.  Aborting.\n");
		goto error;
	}

	hash_size = (uintptr_t)&dd->certs - (uintptr_t)hash_base;
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		fprintf(stderr, "Data directory is invalid.  Aborting.\n");
		goto error;
	}
	PK11_DigestOp(pk11ctx, hash_base, hash_size);

	/* 8. Skip over the crt dir
	 * 9. Hash everything up to the end of the image header. */
	hash_base = &dd->base_relocations;
	hash_size = (pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size) -
		((uintptr_t)&dd->base_relocations - (uintptr_t)map);

	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		fprintf(stderr, "Relocations table is invalid.  Aborting.\n");
		goto error;
	}
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
		if (shdrs[i].raw_data_size == 0)
			continue;

		hash_base = (void *)((uintptr_t)map + shdrs[i].data_addr);
		hash_size = shdrs[i].raw_data_size;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			fprintf(stderr, "Section \"%s\" has invalid address."
				"  Aborting.\n", shdrs[i].name);
			goto error_shdrs;
		}

		PK11_DigestOp(pk11ctx, hash_base, hash_size);

		hashed_bytes += hash_size;
	}

	if (map_size > hashed_bytes) {
		hash_base = (void *)((uintptr_t)map + hashed_bytes);
		hash_size = map_size - dd->certs.size - hashed_bytes;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			fprintf(stderr, "Invalid trailing data.  Aborting.\n");
			goto error_shdrs;
		}
		PK11_DigestOp(pk11ctx, hash_base, hash_size);
	}

	SECItem *digest = PORT_ArenaZAlloc(ctx->cms_ctx.arena,
					sizeof (SECItem));
	if (!digest)
		goto error_shdrs;

	digest->type = siBuffer;
	digest->data = PORT_ArenaZAlloc(ctx->cms_ctx.arena,
						ctx->cms_ctx.digest_size);
	digest->len = ctx->cms_ctx.digest_size;
	if (!digest->data)
		goto error_digest;

	PK11_DigestFinal(pk11ctx, digest->data, &digest->len,
						ctx->cms_ctx.digest_size);
	ctx->cms_ctx.pe_digest = digest;

	if (shdrs)
		free(shdrs);
	PK11_DestroyContext(pk11ctx, PR_TRUE);

	return 0;

error_digest:
	PORT_Free(digest->data);
error_shdrs:
	if (shdrs)
		free(shdrs);
error:
	PK11_DestroyContext(pk11ctx, PR_TRUE);
	fprintf(stderr, "pesign: could not digest file.\n");
	exit(1);
}

void
check_signature_space(pesign_context *ctx)
{
	parse_signature(ctx);

	ssize_t available = available_cert_space(ctx);

	if (available < ctx->cms_ctx.newsig.len) {
		fprintf(stderr, "Could not add new signature: insufficient space.\n");
		exit(1);
	}
}

int
import_signature(pesign_context *ctx)
{
	int rc = insert_signature(ctx);
	if (rc < 0) {
		fprintf(stderr, "Could not add new signature\n");
		exit(1);
	}

	return finalize_signatures(ctx);
}

void
allocate_signature_space(pesign_context *ctx, ssize_t sigspace)
{
	int rc;

	rc = pe_alloccert(ctx->outpe, sigspace);
	if (rc < 0) {
		fprintf(stderr, "Could not allocate space for signature: %m\n");
		exit(1);
	}
}

void
remove_signature(pesign_context *p_ctx)
{
	cms_context *ctx = &p_ctx->cms_ctx;

	if (p_ctx->signum < 0)
		p_ctx->signum = 0;

	free(ctx->signatures[p_ctx->signum]->data);
	free(ctx->signatures[p_ctx->signum]);
	if (p_ctx->signum != ctx->num_signatures - 1)
		memmove(ctx->signatures[p_ctx->signum],
			ctx->signatures[p_ctx->signum+1],
			sizeof(SECItem *) *
				(ctx->num_signatures - p_ctx->signum));

	ctx->num_signatures--;
}
