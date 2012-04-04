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
#ifndef CONTENT_INFO_H
#define CONTENT_INFO_H 1

#include <nss3/secder.h>
#include <nss3/secoid.h>
#include <nss3/secasn1.h>

#include <stdint.h>

typedef struct {
	SECItem flags;
} SpcPeImageFlags;
extern SEC_ASN1Template SpcAttributeTypeAndOptionalValueTemplate[];

typedef struct {
	/* L"<<<Obsolete>>>" no nul */
	SECItem unicode;
} SpcString;

typedef struct {
	SECItem file;
} SpcLink;

typedef struct {
	SECItem flags;
	SECItem link;
} SpcPeImageData;

typedef struct _SpcAttributeTypeAndOptionalValue {
	SECItem contentType;
	SECItem value;
} SpcAttributeTypeAndOptionalValue;

typedef struct {
	SECAlgorithmID digestAlgorithm;
	SECItem digest;
} DigestInfo;
extern SEC_ASN1Template AlgorithmIDTemplate[];
extern SEC_ASN1Template DigestInfoTemplate[];

typedef struct {
	SECItem data;
	SECItem messageDigest;
} SpcIndirectDataContent;
extern SEC_ASN1Template SpcIndirectDataContentTemplate[];

typedef struct {
	SECItem contentType;
	SECItem content;
} SpcContentInfo;
extern const SEC_ASN1Template SpcContentInfoTemplate[];

extern int generate_spc_content_info(SECItem *cip, cms_context *ctx);
extern int register_content_info(void);

#endif /* CONTENT_INFO_H */
