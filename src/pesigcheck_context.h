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
#ifndef pesigcheck_CONTEXT_H
#define pesigcheck_CONTEXT_H 1

#include <cert.h>
#include <secpkcs7.h>

enum {
	pesigcheck_C_ALLOCATED = 1,
};

typedef enum {
	DB_FILE,
	DB_EFIVAR,
	DB_CERT,
} db_f_type;

struct dblist {
	db_f_type type;
	char *path;
	int fd;
	struct dblist *next;
	size_t size;
	void *map;
	size_t datalen;
	void *data;
};

typedef struct dblist dblist;

struct hashlist {
	efi_guid_t *hash_type;
	void *data;
	size_t datalen;
	struct hashlist *next;
};
typedef struct hashlist hashlist;

typedef struct pesigcheck_context {
	int flags;

	char *infile;
	int infd;
	Pe *inpe;

	int quiet;

	hashlist *hashes;

	dblist *db;
	dblist *dbx;

	cms_context *cms_ctx;
} pesigcheck_context;

extern int pesigcheck_context_new(pesigcheck_context **ctx);
extern void pesigcheck_context_free_private(pesigcheck_context **ctx_ptr);
extern int pesigcheck_context_init(pesigcheck_context *ctx);
extern void pesigcheck_context_fini(pesigcheck_context *ctx);
#define pesigcheck_context_free(ctx) pesigcheck_context_free_private(&(ctx))

#endif /* pesigcheck_CONTEXT_H */
