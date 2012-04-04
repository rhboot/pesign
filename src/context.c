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

#include <unistd.h>

#include "pesign.h"

#include <nss3/nss.h>
#include <nss3/secitem.h>

int
pesign_context_new(pesign_context **ctx)
{
	pesign_context *context = NULL;
	int rc = 0;

	if (ctx == NULL)
		return -1;

	context = malloc(sizeof (*context));
	if (!context)
		return -1;

	pesign_context_init(context);
	context->flags |= PESIGN_C_ALLOCATED;

	*ctx = context;
	return rc;
}

int
pesign_context_init(pesign_context *ctx)
{
	if (!ctx)
		return -1;
	memset(ctx, '\0', sizeof (*ctx));

	ctx->infd = -1;
	ctx->outfd = -1;
	ctx->outmode = 0644;

	ctx->insigfd = -1;
	ctx->outsigfd = -1;

	ctx->signum = -1;

	ctx->ascii = 0;
	ctx->hashgaps = 1;
	ctx->sign = 0;
	ctx->hash = 0;

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
		SECITEM_FreeItem(&ctx->algorithm_id->algorithm, PR_FALSE);
		free_poison(ctx->algorithm_id->parameters.data,
			ctx->algorithm_id->parameters.len);
		SECITEM_FreeItem(&ctx->algorithm_id->parameters, PR_FALSE);
		free_poison(ctx->algorithm_id, sizeof (*ctx->algorithm_id));
		free(ctx->algorithm_id);
		ctx->algorithm_id = NULL;
	}

	if (ctx->digest) {
		free_poison(ctx->digest->data, ctx->digest->len);
		free(ctx->digest->data);
		free_poison(ctx->digest, sizeof (*ctx->digest));
		free(ctx->digest);
		ctx->digest = NULL;
	}

	PORT_FreeArena(ctx->arena, PR_TRUE);

	memset(ctx, '\0', sizeof(*ctx));
}

void
pesign_context_fini(pesign_context *ctx)
{
	if (!ctx)
		return;

	cms_context_fini(&ctx->cms_ctx);

	xfree(ctx->certfile);
	xfree(ctx->privkeyfile);

	if (ctx->outpe) {
		pe_end(ctx->outpe);
		ctx->outpe = NULL;
	}

	if (ctx->inpe) {
		pe_end(ctx->inpe);
		ctx->inpe = NULL;
	}

	xfree(ctx->outfile);
	xfree(ctx->infile);

	xfree(ctx->insig);
	xfree(ctx->outsig);

	if (ctx->insigfd >= 0) {
		close(ctx->insigfd);
		ctx->insigfd = -1;
	}

	if (ctx->outsigfd >= 0) {
		close(ctx->outsigfd);
		ctx->outsigfd = -1;
	}

	if (ctx->cinfo) {
		SEC_PKCS7DestroyContentInfo(ctx->cinfo);
		ctx->cinfo = NULL;
	}

	if (ctx->outfd >= 0) {
		close(ctx->outfd);
		ctx->outfd = -1;
	}

	if (ctx->infd >= 0) {
		close(ctx->infd);
		ctx->infd = -1;
	}

	ctx->signum = -1;

	if (!(ctx->flags & PESIGN_C_ALLOCATED))
		pesign_context_init(ctx);

}

void
pesign_context_free_private(pesign_context **ctx_ptr)
{
	pesign_context *ctx;
	if (!ctx_ptr || !*ctx_ptr)
		return;

	ctx = *ctx_ptr;
	pesign_context_fini(ctx);

	if (ctx->flags & PESIGN_C_ALLOCATED)
		xfree(*ctx_ptr);
}
