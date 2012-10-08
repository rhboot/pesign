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
#ifndef PESIGN_CONTEXT_H
#define PESIGN_CONTEXT_H 1

#include <nss3/cert.h>
#include <nss3/secpkcs7.h>

enum {
	PESIGN_C_ALLOCATED = 1,
};

typedef struct {
	int infd;
	int outfd;
	char *infile;
	char *outfile;
	mode_t outmode;

	int force;

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

	char *privkeyfile;
	char *certname;
	cms_context cms_ctx;

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
