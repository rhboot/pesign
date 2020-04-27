// SPDX-License-Identifier: GPLv2
/*
 * signed_data.h - types and decls to implement the authenticode
 *                 signed_data structure
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef SIGNED_DATA_H
#define SIGNED_DATA_H 1

extern int generate_spc_signed_data(cms_context *cms, SECItem *sdp);
extern int generate_authvar_signed_data(cms_context *cms, SECItem *sdp);

#endif /* SIGNED_DATA_H */
