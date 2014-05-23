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
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "pesign.h"

#include <prerror.h>

#include <nss.h>
#include <secport.h>
#include <secpkcs7.h>
#include <secder.h>
#include <base64.h>
#include <pk11pub.h>
#include <secerr.h>

void
insert_signature(cms_context *cms, int signum)
{
	SECItem *sig = &cms->newsig;

	if (signum == -1)
		signum = cms->num_signatures;

	SECItem **signatures = realloc(cms->signatures,
		sizeof (SECItem *) * (cms->num_signatures + 1));
	if (!signatures) {
		cms->log(cms, LOG_ERR, "insert signature: could not allocate "
					"memory: %m");
		exit(1);
	}
	cms->signatures = signatures;
	if (signum != cms->num_signatures) {
		memmove(cms->signatures[signum+1],
			cms->signatures[signum],
			sizeof(SECItem) * (cms->num_signatures - signum));
	}
	cms->signatures[signum] = sig;
	cms->num_signatures++;
}

static const char *sig_begin_marker ="-----BEGIN AUTHENTICODE SIGNATURE-----\n";
static const char *sig_end_marker = "\n-----END AUTHENTICODE SIGNATURE-----\n";

void
export_pubkey(pesign_context *p_ctx)
{
	cms_context *ctx = p_ctx->cms_ctx;
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
	cms_context *ctx = p_ctx->cms_ctx;
	int rc;

	SECItem derCert = ctx->cert->derCert;
	rc = write(p_ctx->outcertfd, derCert.data, derCert.len);
	close(p_ctx->outcertfd);
	if (rc == derCert.len)
		exit(0);
	exit(1);
}

off_t
export_signature(cms_context *cms, int fd, int ascii_armor)
{
	off_t ret = 0;
	int rc = 0;

	SECItem *sig = &cms->newsig;

	unsigned char *data = sig->data;
	int datalen = sig->len;
	if (ascii_armor) {
		char *ascii = BTOA_DataToAscii(data, datalen);
		if (!ascii) {
			cms->log(cms, LOG_ERR, "error exporting signature");
failure:
			close(fd);
			return -1;
		}

		rc = write(fd, sig_begin_marker, strlen(sig_begin_marker));
		if (rc < 0) {
			cms->log(cms, LOG_ERR, "error exporting signature: %m");
			goto failure;
		}
		ret += rc;

		rc = write(fd, ascii, strlen(ascii));
		if (rc < 0) {
			cms->log(cms, LOG_ERR, "error exporting signature: %m");
			goto failure;
		}
		ret += rc;

		rc = write(fd, sig_end_marker, strlen(sig_end_marker));
		if (rc < 0) {
			cms->log(cms, LOG_ERR, "error exporting signature: %m");
			goto failure;
		}
		ret += rc;

		PORT_Free(ascii);
	} else {
		rc = write(fd, data, datalen);
		if (rc < 0) {
			cms->log(cms, LOG_ERR, "error exporting signature: %m");
			goto failure;
		}
		ret += rc;
	}
	return ret;
}

void
parse_signature(pesign_context *ctx)
{
	int rc;
	char *sig;
	size_t siglen;

	rc = read_file(ctx->insigfd, &sig, &siglen);
	if (rc < 0)
		errx(1, "Could not read signature");

	close(ctx->insigfd);
	ctx->insigfd = -1;

	unsigned char *der;
	unsigned int derlen;

	/* XXX FIXME: ignoring length for now */
	char *base64 = strstr(sig, sig_begin_marker);
	if (base64) {
		base64 += strlen(sig_begin_marker);
		char *end = strstr(base64, sig_end_marker);
		if (!end)
			errx(1, "Invalid signature");

		derlen = end - base64;
		base64[derlen] = '\0';

		der = ATOB_AsciiToData(base64, &derlen);
	} else {
		der = PORT_Alloc(siglen);
		memmove(der, sig, siglen);
		derlen = siglen;
	}
	free(sig);

	ctx->cms_ctx->newsig.data = der;
	ctx->cms_ctx->newsig.len = derlen;

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

void
import_raw_signature(pesign_context *pctx)
{
	if (pctx->rawsigfd < 0 || pctx->insattrsfd < 0)
		errx(1, "Raw signature and signed attributes "
			"must both be imported.");

	cms_context *ctx = pctx->cms_ctx;

	ctx->raw_signature = SECITEM_AllocItem(ctx->arena, NULL, 0);
	ctx->raw_signature->type = siBuffer;
	int rc = read_file(pctx->rawsigfd,
				(char **)&ctx->raw_signature->data,
				(size_t *)&ctx->raw_signature->len);
	if (rc < 0)
		err(1, "Could not read raw signature: %m");

	ctx->raw_signed_attrs = SECITEM_AllocItem(ctx->arena, NULL, 0);
	ctx->raw_signed_attrs->type = siBuffer;
	rc = read_file(pctx->insattrsfd,
				(char **)&ctx->raw_signed_attrs->data,
				(size_t *)&ctx->raw_signed_attrs->len);
	if (rc < 0)
		err(1, "Could not read raw signed attributes");
}

int
generate_sattr_blob(pesign_context *ctx)
{
	int rc;
	SECItem sa;
	SpcContentInfo ci;

	memset(&ci, '\0', sizeof (ci));
	rc = generate_spc_content_info(ctx->cms_ctx, &ci);
	if (rc < 0)
		nsserr(1, "Could not generate content info");

	rc = generate_signed_attributes(ctx->cms_ctx, &sa);
	if (rc < 0)
		nsserr(1, "Could not generate signed attributes");

	return write(ctx->outsattrsfd, sa.data, sa.len);
}

void
remove_signature(pesign_context *p_ctx)
{
	cms_context *ctx = p_ctx->cms_ctx;

	free(ctx->signatures[p_ctx->signum]->data);
	if (p_ctx->signum != ctx->num_signatures - 1)
		memmove(ctx->signatures[p_ctx->signum],
			ctx->signatures[p_ctx->signum+1],
			sizeof(SECItem) *
				(ctx->num_signatures - 1));

	ctx->num_signatures--;
}
