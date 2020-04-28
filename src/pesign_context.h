// SPDX-License-Identifier: GPLv2
/*
 * pesign_context.h - context setup and teardown for pesign
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PESIGN_CONTEXT_H
#define PESIGN_CONTEXT_H 1

#include <cert.h>
#include <secpkcs7.h>

enum {
	PESIGN_C_ALLOCATED = 1,
};

typedef enum {
	FORMAT_PE_BINARY,
	FORMAT_KERNEL_MODULE,
} file_format;

typedef struct {
	union {
		int infd;
		int inkmodfd;
	};
	union {
		int outfd;
		int outkmodfd;
	};
	union {
		char *infile;
		char *inkmod;
	};
	union {
		char *outfile;
		char *outkmod;
	};
	size_t inlength;
	mode_t outmode;

	int force;
	long verbose;

	char *rawsig;
	int rawsigfd;
	char *insattrs;
	int insattrsfd;
	char *outsattrs;
	int outsattrsfd;

	char *insig;
	int insigfd;
	SEC_PKCS7ContentInfo *cinfo;
	char *outsig;
	int outsigfd;

	char *outkey;
	int outkeyfd;

	char *outcert;
	int outcertfd;

	Pe *inpe;
	Pe *outpe;

	cms_context *cms_ctx;

	int flags;

	int signum;

	int ascii;
	int sign;
	int hash;
} pesign_context;

extern int pesign_context_new(pesign_context **ctx);
extern void pesign_context_free_private(pesign_context **ctx_ptr);
extern int pesign_context_init(pesign_context *ctx);
extern void pesign_context_fini(pesign_context *ctx);
#define pesign_context_free(ctx) pesign_context_free_private(&(ctx))

#endif /* PESIGN_CONTEXT_H */
