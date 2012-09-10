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
#ifndef peverify_context_H
#define peverify_context_H 1

#include <nss3/cert.h>
#include <nss3/secpkcs7.h>

enum {
	PEVERIFY_C_ALLOCATED = 1,
};

struct peverify_context;

typedef int (*get_wincert_list)(struct peverify_context *ctx, void **list, size_t *size);

typedef struct peverify_context {
	int flags;

	char *infile;
	int infd;
	Pe *inpe;

	int quiet;

	char *dbfile;
	int dbfd;

	char *dbxfile;
	int dbxfd;

	get_wincert_list getdb;
	get_wincert_list getdbx;

	cms_context cms_ctx;
} peverify_context;

extern int peverify_context_new(peverify_context **ctx);
extern void peverify_context_free_private(peverify_context **ctx_ptr);
extern int peverify_context_init(peverify_context *ctx);
extern void peverify_context_fini(peverify_context *ctx);
#define peverify_context_free(ctx) peverify_context_free_private(&(ctx))

#endif /* peverify_context_H */
