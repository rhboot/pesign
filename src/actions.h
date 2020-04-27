// SPDX-License-Identifier: GPLv2
/*
 * actions.h - helpers for our high-level actions
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PESIGN_CRYPTO_H
#define PESIGN_CRYPTO_H 1

#include <cert.h>
#include <secpkcs7.h>

#include "wincert.h"

extern int list_signatures(pesign_context *ctx);
extern void check_signature_space(pesign_context *ctx);
extern void allocate_signature_space(Pe *pe, ssize_t sigspace);
extern ssize_t export_signature(cms_context *cms, int fd, int ascii_armor);
extern void import_raw_signature(pesign_context *pctx);
extern void remove_signature(pesign_context *ctx);
extern void export_pubkey(pesign_context *ctx);
extern void export_cert(pesign_context *ctx);
extern int generate_sattr_blob(pesign_context *pctx);
extern void parse_signature(pesign_context *ctx);
extern void insert_signature(cms_context *cms, int signum);

#endif /* PESIGN_CRYPTO_H */
