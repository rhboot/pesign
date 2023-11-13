// SPDX-License-Identifier: GPLv2
/*
 * cms_common.h - decls for common parts pf PKCS7 that we need
 *                regardless of the target file type.
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef CMS_COMMON_H
#define CMS_COMMON_H 1

#include <cert.h>
#include <secpkcs7.h>

#include <errno.h>
#include <efivar.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "util.h"
#include "password.h"

#define save_port_err() \
	for (error_t saved_errno_0_ = 0, saved_errno_1_ = PORT_GetError(); saved_errno_0_ < 1; saved_errno_0_++, PORT_SetError(saved_errno_1_))

#define for_each_cert(cl, node) \
	for (CERTCertListNode *node = CERT_LIST_HEAD(cl); !CERT_LIST_END(node, cl); node = CERT_LIST_NEXT(node))

#define cmsreterr(rv, cms, fmt, args...) ({			\
		(cms)->log((cms), LOG_ERR, "%s:%s:%d: " fmt,	\
			__FILE__, __func__, __LINE__ - 2,	\
			## args);				\
		return rv;					\
	})
#define cmsgotoerr(errlabel, cms, fmt, args...) ({		\
		(cms)->log((cms), LOG_ERR, "%s:%s:%d: " fmt,	\
			__FILE__, __func__, __LINE__ - 2,	\
			## args);				\
		goto errlabel;					\
	})
#define cnreterr(rv, cms, fmt, args...) ({				\
		(cms)->log((cms), LOG_ERR, "%s:%s:%d: " fmt ":%s:%s",	\
			__FILE__, __func__, __LINE__ - 2, ## args,	\
			PORT_ErrorToName(PORT_GetError()),		\
			PORT_ErrorToString(PORT_GetError()));		\
		return rv;						\
	})
#define cngotoerr(errlabel, cms, fmt, args...) ({			\
		(cms)->log((cms), LOG_ERR, "%s:%s:%d: " fmt ":%s:%s",	\
			__FILE__, __func__, __LINE__ - 2, ## args,	\
			PORT_ErrorToName(PORT_GetError()),		\
			PORT_ErrorToString(PORT_GetError()));		\
		goto errlabel;						\
	})

struct digest {
	PK11Context *pk11ctx;
	SECItem *pe_digest;
};

#define DIGEST_PARAM_SHA256	0
#define DIGEST_PARAM_SHA1	1
#define DEFAULT_DIGEST_PARAM	DIGEST_PARAM_SHA256

struct digest_param {
	char *name;
	SECOidTag digest_tag;
	SECOidTag signature_tag;
	SECOidTag digest_encryption_tag;
	const efi_guid_t *efi_guid;
	int size;
};

extern const struct digest_param digest_params[2];
extern const unsigned int n_digest_params;

typedef struct pk12_file {
	char *path;
	int fd;
	char *pw;
	struct list_head list;
} pk12_file_t;

struct token_pass {
	char *token;
	char *pass;
};

struct pw_database {
	struct token_pass *phrases;
	size_t nphrases;
};

typedef enum {
	// used only for bounds checking
	PW_SOURCE_INVALID = 0,
	// prompt the user (pwdata->data is NULL)
	PW_PROMPT = 1,
	// prompt the user to use a device (pwdata->data is NULL)
	PW_DEVICE = 2,
	// pwdata->data is plain text
	PW_PLAINTEXT = 3,
	// pwdata->data is a filename for a database
	PW_FROMFILEDB = 4,
	// pwdata->data is the database data
	PW_DATABASE = 5,
	// pwdata->data is the name of an environment variable
	PW_FROMENV = 6,
	// pwdata->data is the path of a file
	PW_FROMFILE = 7,
	// pwdata->intdata is a file descriptor
	PW_FROMFD = 8,

	// used only for bounds checking
	PW_SOURCE_MAX
} pw_source_t;

typedef struct {
	pw_source_t source;
	pw_source_t orig_source;

	struct pw_database pwdb;
	char *data;
	long intdata;
} secuPWData;

struct cms_context;

typedef int (*cms_common_logger)(struct cms_context *, int priority,
		char *fmt, ...) PRINTF(3, 4);

typedef struct cms_context {
	PRArenaPool *arena;
	void *privkey;

	char *tokenname;
	char *certname;
	CERTCertificate *cert;
	PK11SlotListElement *psle;
	PK11PasswordFunc func;
	secuPWData pwdata;

	list_t pk12_ins;
	pk12_file_t pk12_out;
	int db_out, dbx_out, dbt_out;

	struct digest *digests;
	unsigned int selected_digest;
	int omit_vendor_cert;

	SECItem newsig;

	SECItem *ci_digest;

	SECItem *raw_signed_attrs;
	SECItem *raw_signature;

	int num_signatures;
	SECItem **signatures;

	int authbuf_len;
	void *authbuf;

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
extern int generate_string(cms_context *cms, SECItem *der, char *str);
extern int wrap_in_set(cms_context *cms, SECItem *der, SECItem **items);
extern int wrap_in_seq(cms_context *cms, SECItem *der,
			SECItem *items, int num_items);
extern int make_context_specific(cms_context *cms, int ctxt, SECItem *encoded,
			SECItem *original);
extern int make_eku_oid(cms_context *cms, SECItem *encoded, SECOidTag oid_tag);
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

extern int generate_digest(cms_context *cms, Pe *pe, int padded);
extern int generate_signature(cms_context *ctx);
extern int unlock_nss_token(cms_context *ctx);
extern int find_certificate(cms_context *ctx, int needs_private_key);
extern int generate_keys(cms_context *cms, PK11SlotInfo *slot,
		SECKEYPrivateKey **privkey, SECKEYPublicKey **pubkey,
		int key_bits, unsigned long exponent);
extern int is_issuer_of(CERTCertificate *c0, CERTCertificate *c1);

typedef int (find_cert_match_t)(CERTCertificate *cert, void *cbdata);
extern int find_certificate_by_callback(cms_context *cms,
					find_cert_match_t *match, void *cbdata,
					CERTCertificate **cert);

extern int find_named_certificate(cms_context *cms, char *name,
				CERTCertificate **cert);
extern int find_certificate_by_issuer_and_sn(cms_context *cms,
					     CERTIssuerAndSN *ias,
					     CERTCertificate **cert);

extern int find_slot_for_token(cms_context *cms, PK11SlotInfo **slot);

extern SECOidTag digest_get_digest_oid(cms_context *cms);
extern SECOidTag digest_get_encryption_oid(cms_context *cms);
extern SECOidTag digest_get_signature_oid(cms_context *cms);
extern int digest_get_digest_size(cms_context *cms);
extern void cms_set_pw_callback(cms_context *cms, PK11PasswordFunc func);
extern void cms_set_pw_data(cms_context *cms, secuPWData *pwdata);

extern int set_digest_parameters(cms_context *ctx, char *name);

extern int generate_digest_begin(cms_context *cms);
extern void generate_digest_step(cms_context *cms, void *data, size_t len);
extern int generate_digest_finish(cms_context *cms);

#endif /* CMS_COMMON_H */
// vim:fenc=utf-8:tw=75:noet
