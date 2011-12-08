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

	ctx->hashgaps = 1;
	return 0;
}

void
pesign_context_fini(pesign_context *ctx)
{
	if (!ctx)
		return;

	if (ctx->cert) {
		CERT_DestroyCertificate(ctx->cert);
		ctx->cert = NULL;
	}

	xfree(ctx->certfile);

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

	if (ctx->outfd >= 0) {
		close(ctx->outfd);
		ctx->outfd = -1;
	}

	if (ctx->infd >= 0) {
		close(ctx->infd);
		ctx->infd = -1;
	}

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
