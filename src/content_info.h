// SPDX-License-Identifier: GPLv2
/*
 * content_info.h - types and decls to implement the authenticode
 *                  content_info structure
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef CONTENT_INFO_H
#define CONTENT_INFO_H 1

#include <secder.h>
#include <secoid.h>
#include <secasn1.h>

#include <stdint.h>

struct SpcContentInfo {
	SECItem contentType;
	SECItem content;
};
typedef struct SpcContentInfo SpcContentInfo;
extern const SEC_ASN1Template SpcContentInfoTemplate[];

extern int generate_spc_content_info(cms_context *cms, SpcContentInfo *cip);
extern void free_spc_content_info(cms_context *cms, SpcContentInfo *cip);
extern int register_content_info(void);
extern int generate_authvar_content_info(cms_context *cms, SpcContentInfo *cip);

#endif /* CONTENT_INFO_H */
