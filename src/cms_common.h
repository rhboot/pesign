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

#include <stdarg.h>
#include <nss3/cert.h>
#include <nss3/secpkcs7.h>

struct digest {
	PK11Context *pk11ctx;
	SECItem *pe_digest;
};

struct cms_context;

typedef int (*cms_common_logger)(struct cms_context *, int priority,
		char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));

typedef struct cms_context {
	PRArenaPool *arena;
	PRArenaPool *arenab;
	void *privkey;

	char *tokenname;
	char *certname;
	CERTCertificate *cert;
	PK11PasswordFunc func;
	void *pwdata;

	struct digest *digests;
	int selected_digest;

	SECItem newsig;

	SECItem *ci_digest;

	SECItem *raw_signed_attrs;
	SECItem *raw_signature;

	int num_signatures;
	SECItem **signatures;

	cms_common_logger log;
	void *log_priv;
} cms_context;

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

extern int cms_context_alloc(cms_context **ctxp);
extern int cms_context_init(cms_context *ctx);
extern void cms_context_fini(cms_context *ctx);

extern void teardown_digests(cms_context *ctx);

extern int generate_octet_string(cms_context *ctx, SECItem *encoded,
				SECItem *original);
extern int generate_object_id(cms_context *ctx, SECItem *encoded,
				SECOidTag tag);
extern int generate_empty_sequence(cms_context *ctx, SECItem *encoded);
extern int generate_time(cms_context *ctx, SECItem *encoded, time_t when);
extern int generate_integer(cms_context *cms, SECItem *der, unsigned long integer);
extern int generate_string(cms_context *cms, SECItem *der, char *str);
extern int wrap_in_set(cms_context *cms, SECItem *der, SECItem **items);
extern int wrap_in_seq(cms_context *cms, SECItem *der,
			SECItem *items, int num_items);
extern int generate_validity(cms_context *cms, SECItem *der, time_t start,
				time_t end);
extern int generate_common_name(cms_context *cms, SECItem *der, char *cn);
extern int generate_auth_info(cms_context *cms, SECItem *der, char *url);
extern int generate_algorithm_id(cms_context *ctx, SECAlgorithmID *idp,
				SECOidTag tag);
extern int generate_spc_link(cms_context *cms, SpcLink *slp,
				SpcLinkType link_type, void *link_data,
				size_t link_data_size);

extern int generate_spc_string(cms_context *cms, SECItem *ssp, char *str,
				int len);
extern int generate_digest(cms_context *cms, Pe *pe);
extern int generate_signature(cms_context *ctx);
extern int unlock_nss_token(cms_context *ctx);
extern int find_certificate(cms_context *ctx);
extern int generate_keys(cms_context *cms, SECKEYPrivateKey **privkey,
		SECKEYPublicKey **pubkey);

extern SECOidTag digest_get_digest_oid(cms_context *cms);
extern SECOidTag digest_get_encryption_oid(cms_context *cms);
extern SECOidTag digest_get_signature_oid(cms_context *cms);
extern int digest_get_digest_size(cms_context *cms);
extern void cms_set_pw_callback(cms_context *cms, PK11PasswordFunc func);
extern void cms_set_pw_data(cms_context *cms, void *pwdata);

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
