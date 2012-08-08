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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pesign.h"

#include <nspr4/prerror.h>

#include <nss3/nss.h>
#include <nss3/secport.h>
#include <nss3/secpkcs7.h>
#include <nss3/secder.h>
#include <nss3/base64.h>
#include <nss3/pk11pub.h>
#include <nss3/secerr.h>

struct digest_param {
	char *name;
	SECOidTag digest_tag;
	SECOidTag signature_tag;
	SECOidTag digest_encryption_tag;
	int size;
};

static struct digest_param digest_params[] = {
	{.name = "sha256",
	 .digest_tag = SEC_OID_SHA256,
	 .signature_tag = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
	 .digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
	 .size = 32
	},
	{.name = "sha1",
	 .digest_tag = SEC_OID_SHA1,
	 .signature_tag = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION,
	 .digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
	 .size = 20
	},
	{NULL,}
};

int
cms_context_init(cms_context *ctx)
{
	SECStatus status;
	
	status = NSS_Init("/etc/pki/pesign");
	if (status != SECSuccess)
		return -1;

	status = register_oids();
	if (status != SECSuccess)
		return -1;

	memset(ctx, '\0', sizeof (*ctx));

	ctx->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!ctx->arena) {
		fprintf(stderr, "Could not create cryptographic arena: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

void
cms_context_fini(cms_context *ctx)
{
	if (ctx->cert) {
		CERT_DestroyCertificate(ctx->cert);
		ctx->cert = NULL;
	}

	if (ctx->privkey) {
		free(ctx->privkey);
		ctx->privkey = NULL;
	}

	if (ctx->newsig.data) {
		free_poison(ctx->newsig.data, ctx->newsig.len);
		memset(&ctx->newsig, '\0', sizeof (ctx->newsig));
	}

	if (ctx->pe_digest) {
		free_poison(ctx->pe_digest->data, ctx->pe_digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		ctx->pe_digest = NULL;
	}

	if (ctx->ci_digest) {
		free_poison(ctx->ci_digest->data, ctx->ci_digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		ctx->ci_digest = NULL;
	}

#if 0
	for (int i = 0; i < ctx->num_signatures; i++) {
		if (ctx->signatures[i]) {
			if (ctx->signatures[i]->data)
				free(ctx->signatures[i]->data);
			free(ctx->signatures[i]);
		}
	}
	free(ctx->signatures);
#endif
	ctx->signatures = NULL;


	PORT_FreeArena(ctx->arena, PR_TRUE);
	memset(ctx, '\0', sizeof(*ctx));

	NSS_Shutdown();
}

int
set_digest_parameters(cms_context *ctx, char *name)
{
	if (strcmp(name, "help")) {
		for (int i = 0; digest_params[i].name != NULL; i++) {
			if (!strcmp(name, digest_params[i].name)) {
				ctx->digest_oid_tag = digest_params[i].digest_tag;
				ctx->digest_size = digest_params[i].size;
				ctx->signature_oid_tag =
					digest_params[i].signature_tag;
				ctx->digest_encryption_oid_tag =
					digest_params[i].digest_encryption_tag;
				return 0;
			}
		}
	} else {
		printf("Supported digests: ");
		for (int i = 0; digest_params[i].name != NULL; i++) {
			printf("%s ", digest_params[i].name);
		}
		printf("\n");
	}
	return -1;
}

int
find_certificate(cms_context *ctx)
{
	if (!ctx->certname || !*ctx->certname)
		return -1;

	typedef struct {
		enum {
			PW_NONE = 0,
			PW_FROMFILE = 1,
			PW_PLAINTEXT = 2,
			PW_EXTERNAL = 3
		} source;
		char *data;
	} secuPWData;
	secuPWData pwdata = { 0, 0 };
	CERTCertificate *cert = NULL;

	cert = CERT_FindUserCertByUsage(CERT_GetDefaultCertDB(), ctx->certname,
		certUsageObjectSigner, PR_FALSE, &pwdata);
	if (cert == NULL) {
		fprintf(stderr, "Could not find certificate\n");
		exit(1);
	}
	
	ctx->cert = cert;
	return 0;
}

static SEC_ASN1Template EmptySequenceTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = 0
	},
	{ 0, }
};

int
generate_time(cms_context *ctx, SECItem *encoded, time_t when)
{
	static char timebuf[32];
	SECItem whenitem = {.type = SEC_ASN1_UTC_TIME,
			 .data = (unsigned char *)timebuf,
			 .len = 0
	};
	struct tm *tm;

	tm = gmtime(&when);

	whenitem.len = snprintf(timebuf, 32, "%02d%02d%02d%02d%02d%02dZ",
		tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
	if (whenitem.len == 32)
		return -1;

	if (SEC_ASN1EncodeItem(ctx->arena, encoded, &whenitem,
			SEC_UTCTimeTemplate) == NULL) {
		return -1;
	}
	return 0;
}

int
generate_empty_sequence(cms_context *ctx, SECItem *encoded)
{
	SECItem empty = {.type = SEC_ASN1_SEQUENCE,
			 .data = NULL,
			 .len = 0
	};
	if (SEC_ASN1EncodeItem(ctx->arena, encoded, &empty,
			EmptySequenceTemplate) == NULL)
		return -1;
	return 0;
}

int
generate_octet_string(cms_context *ctx, SECItem *encoded, SECItem *original)
{
	if (SEC_ASN1EncodeItem(ctx->arena, encoded, original,
			SEC_OctetStringTemplate) == NULL)
		return -1;
	return 0;
}

int
generate_object_id(cms_context *ctx, SECItem *encoded, SECOidTag tag)
{
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(tag);
	if (!oid)
		return -1;

	if (SEC_ASN1EncodeItem(ctx->arena, encoded, &oid->oid,
			SEC_ObjectIDTemplate) == NULL)
		return -1;
	return 0;
}

SEC_ASN1Template AlgorithmIDTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SECAlgorithmID),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(SECAlgorithmID, algorithm),
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_OPTIONAL |
		SEC_ASN1_ANY,
	.offset = offsetof(SECAlgorithmID, parameters),
	.sub = NULL,
	.size = 0,
	},
	{ 0, }
};

int
generate_algorithm_id(cms_context *ctx, SECAlgorithmID *idp, SECOidTag tag)
{
	SECAlgorithmID id;

	if (!idp)
		return -1;

	SECOidData *oiddata;
	oiddata = SECOID_FindOIDByTag(tag);
	if (!oiddata) {
		PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
		return -1;
	}
	if (SECITEM_CopyItem(ctx->arena, &id.algorithm, &oiddata->oid))
		return -1;

	SECITEM_AllocItem(ctx->arena, &id.parameters, 2);
	if (id.parameters.data == NULL)
		goto err;
	id.parameters.data[0] = SEC_ASN1_NULL;
	id.parameters.data[1] = 0;
	id.parameters.type = siBuffer;

	memcpy(idp, &id, sizeof (id));
	return 0;

err:
	SECITEM_FreeItem(&id.algorithm, PR_FALSE);
	return -1;
}

/* Generate DER for SpcString, which is always "<<<Obsolete>>>" in UCS-2.
 * Irony abounds. Needs to decode like this:
 *        [0]  (28)
 *           00 3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00
 *           6c 00 65 00 74 00 65 00 3e 00 3e 00 3e
 */
SEC_ASN1Template SpcStringTemplate[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0,
	.offset = offsetof(SpcString, unicode),
	.sub = &SEC_BMPStringTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

int
generate_spc_string(PRArenaPool *arena, SECItem *ssp, char *str, int len)
{
	SpcString ss;
	memset(&ss, '\0', sizeof (ss));

	SECITEM_AllocItem(arena, &ss.unicode, len);
	if (!ss.unicode.data && len != 0)
		return -1;

	memcpy(ss.unicode.data, str, len);
	ss.unicode.type = siBMPString;

	if (SEC_ASN1EncodeItem(arena, ssp, &ss, SpcStringTemplate) == NULL) {
		fprintf(stderr, "Could not encode SpcString: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

/* Generate the SpcLink DER. Awesomely, this needs to decode as:
 *                      C-[2]  (30)
 * That is all.
 */
SEC_ASN1Template SpcLinkTemplate[] = {
	{
	.kind = SEC_ASN1_CHOICE,
	.offset = offsetof(SpcLink, type),
	.sub = NULL,
	.size = sizeof (SpcLink)
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(SpcLink, url),
	.sub = &SEC_AnyTemplate,
	.size = SpcLinkTypeUrl,
	},
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 2,
	.offset = offsetof(SpcLink, file),
	.sub = &SpcStringTemplate,
	.size = SpcLinkTypeFile,
	},
	{ 0, }
};

int
generate_spc_link(PRArenaPool *arena, SpcLink *slp, SpcLinkType link_type,
		void *link_data, size_t link_data_size)
{
	SpcLink sl;
	memset(&sl, '\0', sizeof (sl));

	sl.type = link_type;
	switch (sl.type) {
	case SpcLinkTypeFile:
		if (generate_spc_string(arena, &sl.file, link_data,
				link_data_size) < 0) {
			fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
			return -1;
		}
		break;
	case SpcLinkTypeUrl:
		sl.url.type = siBuffer;
		sl.url.data = link_data;
		sl.url.len = link_data_size;
		break;
	default:
		fprintf(stderr, "Invalid SpcLinkType\n");
		return -1;
	};

	memcpy(slp, &sl, sizeof (sl));
	return 0;
}

