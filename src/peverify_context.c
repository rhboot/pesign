/*
 * Copyright 2012 Red Hat, Inc.
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

#include <sys/mman.h>
#include <unistd.h>

#include "peverify.h"

#include <nss.h>
#include <secitem.h>

int
peverify_context_new(peverify_context **ctx)
{
	peverify_context *context = NULL;
	int rc = 0;

	if (ctx == NULL)
		return -1;

	context = malloc(sizeof (*context));
	if (!context)
		return -1;

	peverify_context_init(context);
	context->flags |= PEVERIFY_C_ALLOCATED;

	*ctx = context;
	return rc;
}

int
peverify_context_init(peverify_context *ctx)
{
	if (!ctx)
		return -1;
	memset(ctx, '\0', sizeof (*ctx));

	ctx->infd = -1;

	int rc = cms_context_init(&ctx->cms_ctx);
	if (rc < 0)
		return rc;

	return 0;
}

void
peverify_context_fini(peverify_context *ctx)
{
	if (!ctx)
		return;

	cms_context_fini(&ctx->cms_ctx);

	xfree(ctx->infile);

	if (ctx->inpe) {
		pe_end(ctx->inpe);
		ctx->inpe = NULL;
	}

	if (!(ctx->flags & PEVERIFY_C_ALLOCATED))
		peverify_context_init(ctx);

	while (ctx->db) {
		dblist *db = ctx->db;

		munmap(db->map, db->size);
		close(db->fd);
		ctx->db = db->next;
		free(db);
	}
	while (ctx->dbx) {
		dblist *db = ctx->dbx;

		munmap(db->map, db->size);
		close(db->fd);
		ctx->dbx = db->next;
		free(db);
	}
	while (ctx->hashes) {
		hashlist *hashes = ctx->hashes;
		free(hashes->data);
		ctx->hashes = hashes->next;
		free(hashes);
	}
}

void
peverify_context_free_private(peverify_context **ctx_ptr)
{
	peverify_context *ctx;
	if (!ctx_ptr || !*ctx_ptr)
		return;

	ctx = *ctx_ptr;
	peverify_context_fini(ctx);

	if (ctx->flags & PEVERIFY_C_ALLOCATED)
		xfree(*ctx_ptr);
}
