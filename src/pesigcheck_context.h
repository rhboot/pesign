// SPDX-License-Identifier: GPLv2
/*
 * pesigcheck_context.h - context setup and teardown for pesigcheck
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef pesigcheck_CONTEXT_H
#define pesigcheck_CONTEXT_H 1

#include <cert.h>
#include <efivar.h>
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
	long verbose;

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
