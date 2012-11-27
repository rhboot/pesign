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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "pesign.h"

#include <nspr4/prerror.h>
#include <nss3/nss.h>
#include <nss3/secport.h>
#include <nss3/secpkcs7.h>
#include <nss3/secder.h>
#include <nss3/keyhi.h>
#include <nss3/base64.h>
#include <nss3/pk11pub.h>
#include <nss3/secerr.h>

struct digest_param {
	char *name;
	SECOidTag digest_tag;
	SECOidTag signature_tag;
	SECOidTag digest_encryption_tag;
	efi_guid_t efi_guid;
	int size;
};

static struct digest_param digest_params[] = {
	{.name = "sha256",
	 .digest_tag = SEC_OID_SHA256,
	 .signature_tag = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
	 .digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
	 .efi_guid = EFI_CERT_SHA256_GUID,
	 .size = 32
	},
#if 1
	{.name = "sha1",
	 .digest_tag = SEC_OID_SHA1,
	 .signature_tag = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION,
	 .digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
	 .efi_guid = EFI_CERT_SHA1_GUID,
	 .size = 20
	},
#endif
};
static int n_digest_params = sizeof (digest_params) / sizeof (digest_params[0]);

SECOidTag
digest_get_digest_oid(cms_context *cms)
{
	int i = cms->selected_digest;
	return digest_params[i].digest_tag;
}

SECOidTag
digest_get_encryption_oid(cms_context *cms)
{
	int i = cms->selected_digest;
	return digest_params[i].digest_encryption_tag;
}

SECOidTag
digest_get_signature_oid(cms_context *cms)
{
	int i = cms->selected_digest;
	return digest_params[i].signature_tag;
}

int
digest_get_digest_size(cms_context *cms)
{
	int i = cms->selected_digest;
	return digest_params[i].size;
}

void
teardown_digests(cms_context *ctx)
{
	struct digest *digests = ctx->digests;

	if (!digests)
		return;

	for (int i = 0; i < n_digest_params; i++) {
		if (digests[i].pk11ctx) {
			PK11_Finalize(digests[i].pk11ctx);
			PK11_DestroyContext(digests[i].pk11ctx, PR_TRUE);
		}
		if (digests[i].pe_digest) {
			free_poison(digests[i].pe_digest->data,
				    digests[i].pe_digest->len);
			/* XXX sure seems like we should be freeing it here,
			 * but that's segfaulting, and we know it'll get
			 * cleaned up with PORT_FreeArena a couple of lines
			 * down.
			 */
			digests[i].pe_digest = NULL;
		}
	}
	free(digests);
	ctx->digests = NULL;
}

static int
__attribute__ ((format (printf, 3, 4)))
cms_common_log(cms_context *ctx, int priority, char *fmt, ...)
{
	va_list ap;
	FILE *out = priority & LOG_ERR ? stderr : stdout;

	va_start(ap, fmt);
	int rc = vfprintf(out, fmt, ap);
	fprintf(out, "\n");

	va_end(ap);
	return rc;
}

int
cms_context_init(cms_context *cms)
{
	memset(cms, '\0', sizeof (*cms));

	cms->log = cms_common_log;

	cms->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!cms->arena)
		cmsreterr(-1, cms, "could not create cryptographic arena");

	cms->selected_digest = -1;

	return 0;
}

void
cms_context_fini(cms_context *cms)
{
	if (cms->cert) {
		CERT_DestroyCertificate(cms->cert);
		cms->cert = NULL;
	}

	if (cms->privkey) {
		free(cms->privkey);
		cms->privkey = NULL;
	}

	/* These were freed when the arena was destroyed */
	if (cms->tokenname)
		cms->tokenname = NULL;
	if (cms->certname)
		cms->certname = NULL;

	if (cms->newsig.data) {
		free_poison(cms->newsig.data, cms->newsig.len);
		memset(&cms->newsig, '\0', sizeof (cms->newsig));
	}

	teardown_digests(cms);
	cms->selected_digest = -1;

	if (cms->ci_digest) {
		free_poison(cms->ci_digest->data, cms->ci_digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		cms->ci_digest = NULL;
	}

	if (cms->raw_signed_attrs) {
		free_poison(cms->raw_signed_attrs->data,
				cms->raw_signed_attrs->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		cms->raw_signed_attrs = NULL;
	}

	if (cms->raw_signature) {
		free_poison(cms->raw_signature->data,
				cms->raw_signature->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		cms->raw_signature = NULL;
	}

	for (int i = 0; i < cms->num_signatures; i++) {
		/* signature[i] and signature[i]->data() are freed when
		 * the nss arena is cleaned up */
		cms->signatures[i] = NULL;
	}

	xfree(cms->signatures);
	cms->num_signatures = 0;

	PORT_FreeArena(cms->arena, PR_TRUE);
	memset(cms, '\0', sizeof(*cms));
	xfree(cms);
}

int
cms_context_alloc(cms_context **cmsp)
{
	cms_context *cms = calloc(1, sizeof (*cms));
	if (!cms)
		return -1;

	int rc = cms_context_init(cms);
	if (rc < 0) {
		save_errno(free(cms));
		return -1;
	}
	*cmsp = cms;
	return 0;
}

void cms_set_pw_callback(cms_context *cms, PK11PasswordFunc func)
{
	cms->func = func;
}

void cms_set_pw_data(cms_context *cms, void *pwdata)
{
	cms->pwdata = pwdata;
}

int
set_digest_parameters(cms_context *cms, char *name)
{
	if (strcmp(name, "help")) {
		for (int i = 0; i < n_digest_params; i++) {
			if (!strcmp(name, digest_params[i].name)) {
				cms->selected_digest = i;
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

struct cbdata {
	CERTCertificate *cert;
	PK11SlotListElement *psle;
	secuPWData *pwdata;
};

static SECStatus
is_valid_cert(CERTCertificate *cert, void *data)
{
	struct cbdata *cbdata = (struct cbdata *)data;

	PK11SlotInfo *slot = cbdata->psle->slot;
	void *pwdata = cbdata->pwdata;

	SECKEYPrivateKey *privkey = NULL;
	privkey = PK11_FindPrivateKeyFromCert(slot, cert, pwdata);
	if (privkey != NULL) {
		cbdata->cert = cert;
		SECKEY_DestroyPrivateKey(privkey);
		return SECSuccess;
	}
	return SECFailure;
}

int
is_issuer_of(CERTCertificate *c0, CERTCertificate *c1)
{
	if (c0->derSubject.len != c1->derIssuer.len)
		return 0;

	if (memcmp(c0->derSubject.data, c1->derIssuer.data, c0->derSubject.len))
		return 0;
	return 1;
}

/* This is the dumbest function ever, but we need it anyway, because nss
 * is garbage. */
static void
PK11_DestroySlotListElement(PK11SlotList *slots, PK11SlotListElement **psle)
{
	while (psle && *psle)
		*psle = PK11_GetNextSafe(slots, *psle, PR_FALSE);
}

int
unlock_nss_token(cms_context *cms)
{
	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = cms->pwdata ? cms->pwdata : &pwdata_val;
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots)
		cmsreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(cms->tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cms->log(cms, LOG_ERR, "could not find token \"%s\"",
			cms->tokenname);
		return -1;
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) &&
			!PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess) {
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots);
			cms->log(cms, LOG_ERR, "authentication failed for "
				"token \"%s\"", cms->tokenname);
			return -1;
		}
	}

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	return 0;
}

int
find_certificate(cms_context *cms)
{
	if (!cms->certname || !*cms->certname) {
		cms->log(cms, LOG_ERR, "no certificate name specified");
		return -1;
	}

	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = cms->pwdata ? cms->pwdata : &pwdata_val;
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots)
		cmsreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(cms->tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cms->log(cms, LOG_ERR, "could not find token \"%s\"",
			cms->tokenname);
		return -1;
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess) {
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots);
			cms->log(cms, LOG_ERR, "authentication failed for "
				"token \"%s\"", cms->tokenname);
			return -1;
		}
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist) {
		save_port_err(
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not get certificate list");
	}

	SECItem nickname = {
		.data = (void *)cms->certname,
		.len = strlen(cms->certname) + 1,
		.type = siUTF8String,
	};
	struct cbdata cbdata = {
		.cert = NULL,
		.psle = psle,
		.pwdata = pwdata,
	};

	status = PK11_TraverseCertsForNicknameInSlot(&nickname, psle->slot,
						is_valid_cert, &cbdata);
	if (cbdata.cert == NULL) {
		save_port_err(
			CERT_DestroyCertList(certlist);
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not find certificate in list");
	}

	cms->cert = CERT_DupCertificate(cbdata.cert);

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	CERT_DestroyCertList(certlist);

	return 0;
}

int
find_named_certificate(cms_context *cms, char *name, CERTCertificate **cert)
{
	if (!name) {
		cms->log(cms, LOG_ERR, "no certificate name specified");
		return -1;
	}

	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = cms->pwdata ? cms->pwdata : &pwdata_val;
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots)
		cmsreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(cms->tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err(PK11_FreeSlotList(slots));
		cms->log(cms, LOG_ERR, "could not find token \"%s\"",
			cms->tokenname);
		return -1;
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess) {
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots);
			cms->log(cms, LOG_ERR, "authentication failed for "
				"token \"%s\"", cms->tokenname);
			return -1;
		}
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist) {
		save_port_err(
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots));
		cmsreterr(-1, cms, "could not get certificate list");
	}

	CERTCertListNode *node = NULL;
        for (node = CERT_LIST_HEAD(certlist); !CERT_LIST_END(node,certlist);
						node = CERT_LIST_NEXT(node)) {
		if (!strcmp(node->cert->subjectName, name))
			break;
	}
	if (!node) {
		PK11_DestroySlotListElement(slots, &psle);
		PK11_FreeSlotList(slots);
		CERT_DestroyCertList(certlist);

		return -1;
	}

	*cert = CERT_DupCertificate(node->cert);

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	CERT_DestroyCertList(certlist);

	return 0;
}

int
generate_string(cms_context *cms, SECItem *der, char *str)
{
	SECItem input;

	input.data = (void *)str;
	input.len = strlen(str);
	input.type = siBMPString;

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, der, &input,
						SEC_PrintableStringTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode string");
	return 0;
}

static SEC_ASN1Template IntegerTemplate[] = {
	{.kind = SEC_ASN1_INTEGER,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof(long),
	},
	{ 0 },
};

int
generate_integer(cms_context *cms, SECItem *der, unsigned long integer)
{
	void *ret;

	uint32_t u32;

	SECItem input = {
		.data = (void *)&integer,
		.len = sizeof(integer),
		.type = siUnsignedInteger,
	};

	if (integer < 0x100000000) {
		u32 = integer & 0xffffffffUL;
		input.data = (void *)&u32;
		input.len = sizeof(u32);
	}

	ret = SEC_ASN1EncodeItem(cms->arena, der, &input, IntegerTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode data");
	return 0;
}

int
generate_time(cms_context *cms, SECItem *encoded, time_t when)
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
		cmsreterr(-1, cms, "could not encode timestamp");

	if (SEC_ASN1EncodeItem(cms->arena, encoded, &whenitem,
			SEC_UTCTimeTemplate) == NULL)
		cmsreterr(-1, cms, "could not encode timestamp");
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
generate_empty_sequence(cms_context *cms, SECItem *encoded)
{
	SECItem empty = {.type = SEC_ASN1_SEQUENCE,
			 .data = NULL,
			 .len = 0
	};
	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, encoded, &empty,
							EmptySequenceTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode empty sequence");
	return 0;
}

static SEC_ASN1Template ContextSpecificSequence[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | SEC_ASN1_EXPLICIT,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0 }
};

int
make_context_specific(cms_context *cms, int ctxt, SECItem *encoded,
			SECItem *original)
{
	void *rv;
	ContextSpecificSequence[0].kind = SEC_ASN1_EXPLICIT |
					  SEC_ASN1_CONTEXT_SPECIFIC | ctxt;

	rv = SEC_ASN1EncodeItem(cms->arena, encoded, original,
				ContextSpecificSequence);
	if (rv == NULL)
		cmsreterr(-1, cms, "could not encode context specific data");
	return 0;
}

int
generate_octet_string(cms_context *cms, SECItem *encoded, SECItem *original)
{
	if (content_is_empty(original->data, original->len)) {
		cms->log(cms, LOG_ERR, "content is empty, not encoding");
		return -1;
	}
	if (SEC_ASN1EncodeItem(cms->arena, encoded, original,
			SEC_OctetStringTemplate) == NULL)
		cmsreterr(-1, cms, "could not encode octet string");

	return 0;
}

int
generate_object_id(cms_context *cms, SECItem *der, SECOidTag tag)
{
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(tag);
	if (!oid)
		cmsreterr(-1, cms, "could not find OID");

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, der, &oid->oid,
						SEC_ObjectIDTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode ODI");
	return 0;
}

int
generate_algorithm_id(cms_context *cms, SECAlgorithmID *idp, SECOidTag tag)
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
	if (SECITEM_CopyItem(cms->arena, &id.algorithm, &oiddata->oid))
		return -1;

	SECITEM_AllocItem(cms->arena, &id.parameters, 2);
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

int
encode_algorithm_id(cms_context *cms, SECItem *der, SECOidTag tag)
{
	SECAlgorithmID id;

	int rc = generate_algorithm_id(cms, &id, tag);
	if (rc < 0)
		return rc;

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, der, &id,
						SECOID_AlgorithmIDTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode Algorithm ID");

	return 0;
}

typedef struct {
	/* L"<<<Obsolete>>>" no nul */
	SECItem unicode;
} SpcString;

/* Generate DER for SpcString, which is always "<<<Obsolete>>>" in UCS-2.
 * Irony abounds. Needs to decode like this:
 *        [0]  (28)
 *           00 3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00
 *           6c 00 65 00 74 00 65 00 3e 00 3e 00 3e
 */
static SEC_ASN1Template SpcStringTemplate[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0,
	.offset = offsetof(SpcString, unicode),
	.sub = &SEC_BMPStringTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

int
generate_spc_string(cms_context *cms, SECItem *ssp, char *str, int len)
{
	SpcString ss;
	memset(&ss, '\0', sizeof (ss));

	SECITEM_AllocItem(cms->arena, &ss.unicode, len);
	if (len != 0) {
		if (!ss.unicode.data)
			cmsreterr(-1, cms, "could not allocate memory");

		memcpy(ss.unicode.data, str, len);
	}
	ss.unicode.type = siBMPString;

	if (SEC_ASN1EncodeItem(cms->arena, ssp, &ss, SpcStringTemplate) == NULL)
		cmsreterr(-1, cms, "could not encode SpcString");

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
generate_spc_link(cms_context *cms, SpcLink *slp, SpcLinkType link_type,
		void *link_data, size_t link_data_size)
{
	SpcLink sl;
	memset(&sl, '\0', sizeof (sl));

	sl.type = link_type;
	switch (sl.type) {
	case SpcLinkTypeFile: {
		int rc = generate_spc_string(cms, &sl.file, link_data,
					link_data_size);
		if (rc < 0)
			return rc;
		break;
	}
	case SpcLinkTypeUrl:
		sl.url.type = siBuffer;
		sl.url.data = link_data;
		sl.url.len = link_data_size;
		break;
	default:
		cms->log(cms, LOG_ERR, "Invalid SpcLinkType");
		return -1;
	};

	memcpy(slp, &sl, sizeof (sl));
	return 0;
}

static int
check_pointer_and_size(Pe *pe, void *ptr, size_t size)
{
	void *map = NULL;
	size_t map_size = 0;

	map = pe_rawfile(pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	if ((uintptr_t)ptr < (uintptr_t)map)
		return 0;

	if ((uintptr_t)ptr + size > (uintptr_t)map + map_size)
		return 0;

	if (ptr <= map && size >= map_size)
		return 0;

	return 1;
}

int
generate_digest_begin(cms_context *cms)
{
	struct digest *digests = NULL;

	if (cms->digests) {
		digests = cms->digests;
	} else {
		digests = PORT_ArenaZAlloc(cms->arena, n_digest_params * sizeof (*digests));
		if (digests == NULL)
			cmsreterr(-1, cms, "could not allocate digest context");
	}

	for (int i = 0; i < n_digest_params; i++) {
		digests[i].pk11ctx = PK11_CreateDigestContext(
						digest_params[i].digest_tag);
		if (!digests[i].pk11ctx) {
			cms->log(cms, LOG_ERR, "%s:%s:%d could not create "
				"digest context: %s",
				__FILE__, __func__, __LINE__,
				PORT_ErrorToString(PORT_GetError()));
			goto err;
		}

		PK11_DigestBegin(digests[i].pk11ctx);
	}

	cms->digests = digests;
	return 0;

err:
	for (int i = 0; i < n_digest_params; i++) {
		if (digests[i].pk11ctx)
			PK11_DestroyContext(digests[i].pk11ctx, PR_TRUE);
	}

	free(digests);
	return -1;
}

void
generate_digest_step(cms_context *cms, void *data, size_t len)
{
	for (int i = 0; i < n_digest_params; i++)
		PK11_DigestOp(cms->digests[i].pk11ctx, data, len);
}

int
generate_digest_finish(cms_context *cms)
{
	void *mark = PORT_ArenaMark(cms->arena);

	for (int i = 0; i < n_digest_params; i++) {
		SECItem *digest = PORT_ArenaZAlloc(cms->arena,sizeof (SECItem));
		if (digest == NULL) {
			cms->log(cms, LOG_ERR, "%s:%s:%d could not allocate "
				"memory: %s", __FILE__, __func__, __LINE__,
				PORT_ErrorToString(PORT_GetError()));
			goto err;
		}

		digest->type = siBuffer;
		digest->len = digest_params[i].size;
		digest->data = PORT_ArenaZAlloc(cms->arena, digest_params[i].size);
		if (digest->data == NULL) {
			cms->log(cms, LOG_ERR, "%s:%s:%d could not allocate "
				"memory: %s", __FILE__, __func__, __LINE__,
				PORT_ErrorToString(PORT_GetError()));
			goto err;
		}

		PK11_DigestFinal(cms->digests[i].pk11ctx,
			digest->data, &digest->len, digest_params[i].size);
		PK11_Finalize(cms->digests[i].pk11ctx);
		PK11_DestroyContext(cms->digests[i].pk11ctx, PR_TRUE);
		cms->digests[i].pk11ctx = NULL;
		/* XXX sure seems like we should be freeing it here,
		 * but that's segfaulting, and we know it'll get
		 * cleaned up with PORT_FreeArena a couple of lines
		 * down.
		 */
		cms->digests[i].pe_digest = digest;
	}

	PORT_ArenaUnmark(cms->arena, mark);
	return 0;
err:
	for (int i = 0; i < n_digest_params; i++) {
		if (cms->digests[i].pk11ctx)
			PK11_DestroyContext(cms->digests[i].pk11ctx, PR_TRUE);
	}
	PORT_ArenaRelease(cms->arena, mark);
	return -1;
}

int
generate_digest(cms_context *cms, Pe *pe)
{
	void *hash_base;
	size_t hash_size;
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;
	unsigned long hashed_bytes = 0;
	int rc = -1;

	if (!pe) {
		cms->log(cms, LOG_ERR, "no output pe ready");
		return -1;
	}

	rc = generate_digest_begin(cms);
	if (rc < 0)
		return rc;

	struct pe_hdr pehdr;
	if (pe_getpehdr(pe, &pehdr) == NULL)
		pereterr(-1, "invalid PE file header");

	void *map = NULL;
	size_t map_size = 0;

	/* 1. Load the image header into memory - should be done
	 * 2. Initialize SHA hash context. */
	map = pe_rawfile(pe, &map_size);
	if (!map)
		pereterr(-1, "could not get raw output file address");

	/* 3. Calculate the distance from the base of the image header to the
	 * image checksum.
	 * 4. Hash the image header from start to the beginning of the
	 * checksum. */
	hash_base = map;
	switch (pe_kind(pe)) {
	case PE_K_PE_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe32opthdr = opthdr;
		hash_size = (uintptr_t)&pe32opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	case PE_K_PE64_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe64opthdr = opthdr;
		hash_size = (uintptr_t)&pe64opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	default:
		goto error;
	}
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE header is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}
	generate_digest_step(cms, hash_base, hash_size);

	/* 5. Skip over the image checksum
	 * 6. Get the address of the beginning of the cert dir entry
	 * 7. Hash from the end of the csum to the start of the cert dirent. */
	hash_base += hash_size;
	hash_base += pe32opthdr ? sizeof(pe32opthdr->csum)
				: sizeof(pe64opthdr->csum);
	data_directory *dd;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0 || !dd || !check_pointer_and_size(pe, dd, sizeof(*dd))) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE data directory is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}

	hash_size = (uintptr_t)&dd->certs - (uintptr_t)hash_base;
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE data directory is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}
	generate_digest_step(cms, hash_base, hash_size);

	/* 8. Skip over the crt dir
	 * 9. Hash everything up to the end of the image header. */
	hash_base = &dd->base_relocations;
	hash_size = (pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size) -
		((uintptr_t)&dd->base_relocations - (uintptr_t)map);

	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE relocations table is "
			"invalid", __FILE__, __func__, __LINE__);
		goto error;
	}
	generate_digest_step(cms, hash_base, hash_size);

	/* 10. Set SUM_OF_BYTES_HASHED to the size of the header. */
	hashed_bytes = pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size;

	struct section_header *shdrs = calloc(pehdr.sections, sizeof (*shdrs));
	if (!shdrs)
		goto error;
	Pe_Scn *scn = NULL;
	for (int i = 0; i < pehdr.sections; i++) {
		scn = pe_nextscn(pe, scn);
		if (scn == NULL)
			break;
		pe_getshdr(scn, &shdrs[i]);
	}
	sort_shdrs(shdrs, pehdr.sections - 1);

	for (int i = 0; i < pehdr.sections; i++) {
		if (shdrs[i].raw_data_size == 0)
			continue;

		hash_base = (void *)((uintptr_t)map + shdrs[i].data_addr);
		hash_size = shdrs[i].raw_data_size;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			cms->log(cms, LOG_ERR, "%s:%s:%d PE section \"%s\" "
				"has invalid address",
				__FILE__, __func__, __LINE__, shdrs[i].name);
			goto error_shdrs;
		}

		generate_digest_step(cms, hash_base, hash_size);

		hashed_bytes += hash_size;
	}

	if (map_size > hashed_bytes) {
		hash_base = (void *)((uintptr_t)map + hashed_bytes);
		hash_size = map_size - dd->certs.size - hashed_bytes;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			cms->log(cms, LOG_ERR, "%s:%s:%d PE has invalid "
				"trailing data", __FILE__, __func__, __LINE__);
			goto error_shdrs;
		}
		generate_digest_step(cms, hash_base, hash_size);
	}

	rc = generate_digest_finish(cms);
	if (rc < 0)
		goto error_shdrs;

	if (shdrs) {
		free(shdrs);
		shdrs = NULL;
	}

	return 0;

error_shdrs:
	if (shdrs)
		free(shdrs);
error:
	return -1;
}

/* before you run this, you'll need to enroll your CA with:
 * certutil -A -n 'my CA' -d /etc/pki/pesign -t CT,CT,CT -i ca.crt
 * And you'll need to enroll the private key like this:
 * pk12util -d /etc/pki/pesign/ -i Peter\ Jones.p12
 */
int
generate_signature(cms_context *cms)
{
	int rc = 0;

	if (cms->digests[cms->selected_digest].pe_digest == NULL) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE digest has not been "
			"allocated", __FILE__, __func__, __LINE__);
		return -1;
	}

	if (content_is_empty(cms->digests[cms->selected_digest].pe_digest->data,
			cms->digests[cms->selected_digest].pe_digest->len)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE binary has not been "
			"digested", __FILE__, __func__, __LINE__);
		return -1;
	}

	SECItem sd_der;
	memset(&sd_der, '\0', sizeof(sd_der));
	rc = generate_spc_signed_data(cms, &sd_der);
	if (rc < 0)
		cmsreterr(-1, cms, "could not create signed data");

	memcpy(&cms->newsig, &sd_der, sizeof (cms->newsig));
	return 0;
}

typedef struct {
	SECItem start;
	SECItem end;
} Validity;

static SEC_ASN1Template ValidityTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (Validity),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Validity, start),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(Validity, end),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

int
generate_validity(cms_context *cms, SECItem *der, time_t start, time_t end)
{
	Validity validity;
	int rc;

	rc = generate_time(cms, &validity.start, start);
	if (rc < 0)
		return rc;

	rc = generate_time(cms, &validity.end, end);
	if (rc < 0)
		return rc;

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, der, &validity, ValidityTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode validity");
	return 0;
}

static SEC_ASN1Template SetTemplate = {
	.kind = SEC_ASN1_SET_OF,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem **)
	};

int
wrap_in_set(cms_context *cms, SECItem *der, SECItem **items)
{
	void *ret;

	ret = SEC_ASN1EncodeItem(cms->arena, der, &items, &SetTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode set");
	return 0;
}

static SEC_ASN1Template SeqTemplateTemplate = {
	.kind = SEC_ASN1_ANY,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	};

static SEC_ASN1Template SeqTemplateHeader = {
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SECItem)
	};

int
wrap_in_seq(cms_context *cms, SECItem *der, SECItem *items, int num_items)
{
	void *ret;

	void *mark = PORT_ArenaMark(cms->arena);

	SEC_ASN1Template tmpl[num_items+2];

	memcpy(&tmpl[0], &SeqTemplateHeader, sizeof(*tmpl));
	tmpl[0].size = sizeof (SECItem) * num_items;

	for (int i = 0; i < num_items; i++) {
		memcpy(&tmpl[i+1], &SeqTemplateTemplate, sizeof(SEC_ASN1Template));
		tmpl[i+1].offset = (i) * sizeof (SECItem);
	}
	memset(&tmpl[num_items + 1], '\0', sizeof(SEC_ASN1Template));

	int rc = 0;
	ret = SEC_ASN1EncodeItem(cms->arena, der, items, tmpl);
	if (ret == NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode set");
	}
	PORT_ArenaUnmark(cms->arena, mark);
	return rc;
}

typedef struct {
	SECItem oid;
	SECItem string;
} CommonName;

static SEC_ASN1Template CommonNameTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (CommonName),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(CommonName, oid),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(CommonName, string),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

int
generate_common_name(cms_context *cms, SECItem *der, char *cn_str)
{
	CommonName cn;
	SECItem cn_item;
	int rc;

	rc = generate_object_id(cms, &cn.oid, SEC_OID_AVA_COMMON_NAME);
	if (rc < 0)
		return rc;
	rc = generate_string(cms, &cn.string, cn_str);
	if (rc < 0)
		return rc;

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, &cn_item, &cn, CommonNameTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode common name");

	SECItem cn_set;
	SECItem *items[2] = {&cn_item, NULL};
	rc = wrap_in_set(cms, &cn_set, items);
	if (rc < 0)
		return rc;
	rc = wrap_in_seq(cms, der, &cn_set, 1);
	if (rc < 0)
		return rc;
	return 0;
}

typedef struct {
	SECItem type;
	SECItem value;
} ava;

static const SEC_ASN1Template AVATemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (ava),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(ava, type),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(ava, value),
	 .sub = &SEC_AnyTemplate,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

/* I can't figure out how to get a CERTName out in a non-rediculous form, so
 * we wind up encoding the whole thing manually :/ */
static int
generate_ava(cms_context *cms, SECItem *der, CERTAVA *certava)
{
	ava ava;

	SECOidData *oid;

	void *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL)
		cmsreterr(-1, cms, "could not create arena");

	void *real_arena = cms->arena;
	cms->arena = arena;

	oid = SECOID_FindOID(&certava->type);
	if (!oid) {
		save_port_err(PORT_FreeArena(arena, PR_TRUE));
		cms->arena = real_arena;
		cmsreterr(-1, cms, "could not find OID");
	}

	int rc = generate_object_id(cms, &ava.type, oid->offset);
	if (rc < 0) {
		PORT_FreeArena(arena, PR_TRUE);
		cms->arena = real_arena;
		return -1;
	}

	memcpy(&ava.value, &certava->value, sizeof (ava.value));

	void *ret;
	SECItem tmp;
	ret = SEC_ASN1EncodeItem(arena, &tmp, &ava, AVATemplate);
	if (ret == NULL) {
		save_port_err(PORT_FreeArena(arena, PR_TRUE));
		cms->arena = real_arena;
		cmsreterr(-1, cms, "could not encode AVA");
	}

	der->type = tmp.type;
	der->len = tmp.len;
	der->data = PORT_ArenaAlloc(real_arena, tmp.len);
	if (!der->data) {
		save_port_err(PORT_FreeArena(arena, PR_TRUE));
		cms->arena = real_arena;
		cmsreterr(-1, cms, "could not allocate AVA");
	}
	memcpy(der->data, tmp.data, tmp.len);
	PORT_FreeArena(arena, PR_TRUE);
	cms->arena = real_arena;

	return 0;
}

int
generate_name(cms_context *cms, SECItem *der, CERTName *certname)
{
	void *marka = PORT_ArenaMark(cms->arena);
	CERTRDN **rdns = certname->rdns;
	CERTRDN *rdn;

	int num_items = 0;
	int rc = 0;

	while (rdns && (rdn = *rdns++) != NULL) {
		CERTAVA **avas = rdn->avas;
		CERTAVA *ava;
		while (avas && (ava = *avas++) != NULL)
			num_items++;
	}

	SECItem items[num_items];

	int i = 0;
	rdns = certname->rdns;
	while (rdns && (rdn = *rdns++) != NULL) {
		CERTAVA **avas = rdn->avas;
		CERTAVA *ava;
		while (avas && (ava = *avas++) != NULL) {
			SECItem avader;
			rc = generate_ava(cms, &avader, ava);
			if (rc < 0) {
				PORT_ArenaRelease(cms->arena, marka);
				return -1;
			}

			SECItem *list[2] = {
				&avader,
				NULL,
			};
			rc = wrap_in_set(cms, &items[i], list);
			if (rc < 0) {
				PORT_ArenaRelease(cms->arena, marka);
				return -1;
			}
			i++;
		}
	}
	wrap_in_seq(cms, der, &items[0], num_items);
	PORT_ArenaUnmark(cms->arena, marka);

	return 0;
}

typedef struct {
	SECItem oid;
	SECItem url;
} AuthInfo;

static SEC_ASN1Template AuthInfoTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (AuthInfo),
	},
	{.kind = SEC_ASN1_OBJECT_ID,
	 .offset = offsetof(AuthInfo, oid),
	 .sub = &SEC_ObjectIDTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_UTF8_STRING,
	 .offset = offsetof(AuthInfo, url),
	 .sub = NULL,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

static SEC_ASN1Template AuthInfoWrapperTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (AuthInfo),
	},
	{.kind = SEC_ASN1_OBJECT_ID,
	 .offset = offsetof(AuthInfo, oid),
	 .sub = &SEC_ObjectIDTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_OCTET_STRING,
	 .offset = offsetof(AuthInfo, url),
	 .sub = NULL,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

int
generate_auth_info(cms_context *cms, SECItem *der, char *url)
{
	AuthInfo ai;

	SECOidData *oid = SECOID_FindOIDByTag(SEC_OID_PKIX_CA_ISSUERS);
	if (!oid)
		cmsreterr(-1, cms, "could not get CA issuers OID");

	memcpy(&ai.oid, &oid->oid, sizeof (ai.oid));

	ai.url.data = (unsigned char *)url;
	ai.url.len = strlen(url);
	ai.url.type = siBuffer;

	void *ret;
	SECItem unwrapped;
	ret = SEC_ASN1EncodeItem(cms->arena, &unwrapped, &ai, AuthInfoTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode CA Issuers");

	/* I've no idea how to get SEC_ASN1EncodeItem to spit out the thing
	 * we actually want here.  So once again, just force the data to
	 * look correct :( */
	if (unwrapped.len < 12) {
		cms->log(cms, LOG_ERR, "%s:%s:%d generated CA Issuers Info "
			"cannot possibly be valid",
			__FILE__, __func__, __LINE__);
		return -1;
	}
	unwrapped.data[12] = 0x86;
	unwrapped.type = siBuffer;

	AuthInfo wrapper;
	oid = SECOID_FindOIDByTag(SEC_OID_X509_AUTH_INFO_ACCESS);
	if (!oid)
		cmsreterr(-1, cms, "could not find Auth Info Access OID");

	memcpy(&wrapper.oid, &oid->oid, sizeof (ai.oid));

	wrap_in_seq(cms, &wrapper.url, &unwrapped, 1);

	ret = SEC_ASN1EncodeItem(cms->arena, der, &wrapper,
					AuthInfoWrapperTemplate);
	if (ret == NULL)
		cmsreterr(-1, cms, "could not encode CA Issuers OID");

	return 0;
}

typedef struct {
	SECItem oid;
	SECItem keyhash;
} KeyId;

static const SEC_ASN1Template KeyIdTemplate[] = {
	{.kind = SEC_ASN1_SEQUENCE,
	 .offset = 0,
	 .sub = NULL,
	 .size = sizeof (KeyId),
	},
	{.kind = SEC_ASN1_OBJECT_ID,
	 .offset = offsetof(KeyId, oid),
	 .sub = &SEC_ObjectIDTemplate,
	 .size = sizeof (SECItem),
	},
	{.kind = SEC_ASN1_OCTET_STRING,
	 .offset = offsetof(KeyId, keyhash),
	 .sub = NULL,
	 .size = sizeof (SECItem),
	},
	{ 0 }
};

int
generate_keys(cms_context *cms, SECKEYPrivateKey **privkey,
		SECKEYPublicKey **pubkey)
{
	PK11SlotInfo *slot = NULL;
	PK11RSAGenParams rsaparams = {
		.keySizeInBits = 2048,
		.pe = 0x010001,
	};

	slot = PK11_GetInternalKeySlot();
	if (!slot)
		cmsreterr(-1, cms, "could not get NSS internal slot");

	SECStatus rv;
	rv = PK11_Authenticate(slot, PR_TRUE, cms->pwdata);
	if (rv != SECSuccess)
		cmsreterr(-1, cms, "could not authenticate with pk11 service");

	void *params = &rsaparams;
	*privkey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN,
					params, pubkey, PR_TRUE, PR_TRUE,
					cms->pwdata);
	if (!*privkey)
		cmsreterr(-1, cms, "could not generate RSA keypair");
	return 0;
}
