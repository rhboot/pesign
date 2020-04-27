// SPDX-License-Identifier: GPLv2
/*
 * pesign_context.c - context setup and teardown for pesign
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include <unistd.h>

#include "pesign.h"

#include <nss.h>
#include <secitem.h>

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

	rc = pesign_context_init(context);
	if (rc < 0) {
		free(context);
		return rc;
	}
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

	ctx->rawsigfd = -1;
	ctx->insattrsfd = -1;
	ctx->outsattrsfd = -1;

	ctx->insigfd = -1;
	ctx->outsigfd = -1;
	ctx->outkeyfd = -1;
	ctx->outcertfd = -1;

	ctx->signum = -1;

	ctx->ascii = 0;
	ctx->sign = 0;
	ctx->hash = 0;

	int rc = cms_context_alloc(&ctx->cms_ctx);
	if (rc < 0)
		return rc;

	return 0;
}

void
pesign_context_fini(pesign_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->cms_ctx) {
		cms_context_fini(ctx->cms_ctx);
		ctx->cms_ctx = NULL;
	}

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

	xfree(ctx->rawsig);
	xfree(ctx->insattrs);
	xfree(ctx->outsattrs);

	xfree(ctx->insig);
	xfree(ctx->outsig);

	xfree(ctx->outkey);
	xfree(ctx->outcert);

	if (ctx->rawsigfd >= 0) {
		close(ctx->rawsigfd);
		ctx->rawsigfd = -1;
	}
	if (ctx->insattrsfd >= 0) {
		close(ctx->insattrsfd);
		ctx->insattrsfd = -1;
	}
	if (ctx->outsattrsfd >= 0) {
		close(ctx->outsattrsfd);
		ctx->outsattrsfd = -1;
	}

	if (ctx->insigfd >= 0) {
		close(ctx->insigfd);
		ctx->insigfd = -1;
	}

	if (ctx->outsigfd >= 0) {
		close(ctx->outsigfd);
		ctx->outsigfd = -1;
	}

	if (ctx->outkeyfd >= 0) {
		close(ctx->outkeyfd);
		ctx->outkeyfd = -1;
	}

	if (ctx->outcertfd >= 0) {
		close(ctx->outcertfd);
		ctx->outcertfd = -1;
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
