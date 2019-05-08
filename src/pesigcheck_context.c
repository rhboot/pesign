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

#include "fix_coverity.h"

#include <sys/mman.h>
#include <unistd.h>

#include "pesigcheck.h"

#include <nss.h>
#include <secitem.h>

int
pesigcheck_context_new(pesigcheck_context **ctx)
{
	pesigcheck_context *context = NULL;
	int rc = 0;

	if (ctx == NULL)
		return -1;

	context = malloc(sizeof (*context));
	if (!context)
		return -1;

	pesigcheck_context_init(context);
	context->flags |= pesigcheck_C_ALLOCATED;

	*ctx = context;
	return rc;
}

int
pesigcheck_context_init(pesigcheck_context *ctx)
{
	if (!ctx)
		return -1;
	memset(ctx, '\0', sizeof (*ctx));

	ctx->infd = -1;

	int rc = cms_context_alloc(&ctx->cms_ctx);
	if (rc < 0)
		return rc;

	return 0;
}

void
pesigcheck_context_fini(pesigcheck_context *ctx)
{
	if (!ctx)
		return;

	cms_context_fini(ctx->cms_ctx);

	xfree(ctx->infile);

	if (ctx->inpe) {
		pe_end(ctx->inpe);
		ctx->inpe = NULL;
	}

	if (!(ctx->flags & pesigcheck_C_ALLOCATED))
		pesigcheck_context_init(ctx);

	while (ctx->db) {
		dblist *db = ctx->db;

		if (db->type == DB_CERT)
			free(db->data);
		munmap(db->map, db->size);
		close(db->fd);
		ctx->db = db->next;
		free(db->path);
		free(db);
	}
	while (ctx->dbx) {
		dblist *db = ctx->dbx;

		if (db->type == DB_CERT)
			free(db->data);
		munmap(db->map, db->size);
		free(db->path);
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
pesigcheck_context_free_private(pesigcheck_context **ctx_ptr)
{
	pesigcheck_context *ctx;
	if (!ctx_ptr || !*ctx_ptr)
		return;

	ctx = *ctx_ptr;
	pesigcheck_context_fini(ctx);

	if (ctx->flags & pesigcheck_C_ALLOCATED)
		xfree(*ctx_ptr);
}
