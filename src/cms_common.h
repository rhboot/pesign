/*
 * Copyright 2011-2012 Red Hat, Inc.
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
#ifndef CMS_COMMON_H
#define CMS_COMMON_H 1

#include <nss3/cert.h>
#include <nss3/secpkcs7.h>

struct digest {
	PK11Context *pk11ctx;
	SECItem *pe_digest;
};

typedef struct {
	PRArenaPool *arena;
	void *privkey;

	char *tokenname;
	char *certname;
	CERTCertificate *cert;

	struct digest *digests;
	int selected_digest;

	SECItem newsig;

	SECItem *ci_digest;

	SECItem *raw_signed_attrs;
	SECItem *raw_signature;

	int num_signatures;
	SECItem **signatures;
} cms_context;

typedef struct {
	/* L"<<<Obsolete>>>" no nul */
	SECItem unicode;
} SpcString;
extern SEC_ASN1Template SpcStringTemplate[];

typedef enum {
	SpcLinkYouHaveFuckedThisUp = 0,
	SpcLinkTypeUrl = 1,
	SpcLinkTypeFile = 2,
} SpcLinkType;

typedef struct {
	SpcLinkType type;
	union {
		SECItem url;
		SECItem file;
	};
} SpcLink;
extern SEC_ASN1Template SpcLinkTemplate[];

extern int cms_context_init(cms_context *ctx);
extern void cms_context_fini(cms_context *ctx);

extern int generate_octet_string(cms_context *ctx, SECItem *encoded,
				SECItem *original);
extern int generate_object_id(cms_context *ctx, SECItem *encoded,
				SECOidTag tag);
extern int generate_empty_sequence(cms_context *ctx, SECItem *encoded);
extern int generate_time(cms_context *ctx, SECItem *encoded, time_t when);

extern SEC_ASN1Template AlgorithmIDTemplate[];
extern int generate_algorithm_id(cms_context *ctx, SECAlgorithmID *idp,
				SECOidTag tag);
extern int generate_spc_link(PRArenaPool *arena, SpcLink *slp,
				SpcLinkType link_type, void *link_data,
				size_t link_data_size);

extern int generate_spc_string(PRArenaPool *arena, SECItem *ssp,
				char *str, int len);
extern int generate_digest(cms_context *cms, Pe *pe);

extern int find_certificate(cms_context *ctx);

extern SECOidTag digest_get_digest_oid(cms_context *cms);
extern SECOidTag digest_get_encryption_oid(cms_context *cms);
extern SECOidTag digest_get_signature_oid(cms_context *cms);
extern int digest_get_digest_size(cms_context *cms);

extern int set_digest_parameters(cms_context *ctx, char *name);

typedef struct {
	enum {
		PW_NONE = 0,
		PW_FROMFILE = 1,
		PW_PLAINTEXT = 2,
		PW_EXTERNAL = 3
	} source;
	char *data;
} secuPWData;

#endif /* CMS_COMMON_H */
