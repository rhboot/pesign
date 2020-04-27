// SPDX-License-Identifier: GPLv2
/*
 * content_info_priv.h - private types and decls to implement the authenticode
 *                       content_info structure
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef CONTENT_INFO_PRIV_H
#define CONTENT_INFO_PRIV_H 1

typedef struct {
	SECItem flags;
} SpcPeImageFlags;
extern SEC_ASN1Template SpcAttributeTypeAndOptionalValueTemplate[];

typedef struct {
	SECItem flags;
	SpcLink link;
} SpcPeImageData;

typedef struct _SpcAttributeTypeAndOptionalValue {
	SECItem contentType;
	SECItem value;
} SpcAttributeTypeAndOptionalValue;

typedef struct {
	SECAlgorithmID digestAlgorithm;
	SECItem digest;
} DigestInfo;
extern SEC_ASN1Template DigestInfoTemplate[];

typedef struct {
	SECItem data;
	SECItem messageDigest;
} SpcIndirectDataContent;
extern SEC_ASN1Template SpcIndirectDataContentTemplate[];

#endif /* CONTENT_INFO_PRIV_H */
