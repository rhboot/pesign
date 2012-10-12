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


static int
setup_digests(cms_context *cms)
{
	struct digest *digests = NULL;

	digests = calloc(n_digest_params, sizeof (*digests));
	if (!digests) {
		cms->log(cms, LOG_ERR, "cannot allocate memory: %m");
		return -1;
	}

	for (int i = 0; i < n_digest_params; i++) {
		digests[i].pk11ctx = PK11_CreateDigestContext(
						digest_params[i].digest_tag);
		if (!digests[i].pk11ctx) {
			cms->log(cms, LOG_ERR, "could not create digest "
						"context");
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

static void
teardown_digests(cms_context *ctx)
{
	struct digest *digests = ctx->digests;

	if (!digests)
		return;

	for (int i = 0; i < n_digest_params; i++) {
		if (digests[i].pk11ctx)
			PK11_DestroyContext(digests[i].pk11ctx, PR_TRUE);
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
	SECStatus status;
	
	status = NSS_Init("/etc/pki/pesign");
	if (status != SECSuccess)
		return -1;
	memset(cms, '\0', sizeof (*cms));

	status = register_oids();
	if (status != SECSuccess)
		return -1;

	cms->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!cms->arena) {
		cms->log(cms, LOG_ERR,
			"Could not create cryptographic arena: %s",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	int rc = setup_digests(cms);
	if (rc < 0) {
		cms->log(cms, LOG_ERR,
			"Could not initialize cryptographic digest functions.");
		return -1;
	}
	cms->selected_digest = -1;

	cms->log = cms_common_log;

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

	PORT_FreeArena(cms->arena, PR_TRUE);
	memset(cms, '\0', sizeof(*cms));

	NSS_Shutdown();
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

	if (PK11_FindPrivateKeyFromCert(slot, cert, pwdata) != NULL) {
		cbdata->cert = cert;
		return SECSuccess;
	}

	return SECFailure;
}

int
unlock_nss_token(cms_context *cms)
{
	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = cms->pwdata ? cms->pwdata : &pwdata_val;
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots) {
		cms->log(cms, LOG_ERR, "Could not find certificate \"%s\"",
			cms->tokenname);
err:
		return -1;
	}

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
err_slots:
		PK11_FreeSlotList(slots);
		goto err;
	}

	while (psle) {
		if (!strcmp(cms->tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle)
		goto err_slots;

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess) {
			cms->log(cms, LOG_ERR, "Authentication failed for "
				"token \"%s\"", cms->tokenname);
			goto err_slots;
		}
	}

	return 0;
}

int
find_certificate(cms_context *cms)
{
	if (!cms->certname || !*cms->certname)
		return -1;

	secuPWData pwdata_val = { 0, 0 };
	void *pwdata = cms->pwdata ? cms->pwdata : &pwdata_val;
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, pwdata);
	if (!slots) {
		cms->log(cms, LOG_ERR, "Could not find certificate \"%s:%s\"",
			cms->tokenname, cms->certname);
err:
		return -1;
	}

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
err_slots_errmsg:
		cms->log(cms, LOG_ERR, "Could not find certificate \"%s:%s\"",
			cms->tokenname, cms->certname);
err_slots:
		PK11_FreeSlotList(slots);
		goto err;
	}

	while (psle) {
		if (!strcmp(cms->tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle)
		goto err_slots;

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, pwdata)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, pwdata);
		if (status != SECSuccess) {
			cms->log(cms, LOG_ERR, "Authentication failed on "
				"certificate \"%s:%s\"", cms->tokenname,
				cms->certname);
			goto err_slots;
		}
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist)
		goto err_slots;

	SECItem nickname = {
		.data = (void *)ctx->certname,
		.len = strlen(ctx->certname) + 1,
		.type = siUTF8String,
	};
	struct cbdata cbdata = {
		.cert = NULL,
		.psle = psle,
		.pwdata = pwdata,
	};

	status = PK11_TraverseCertsForNicknameInSlot(&nickname, psle->slot,
					is_valid_cert, &cbdata);

	if (cbdata.cert == NULL)
		goto err_slots;

	ctx->cert = cbdata.cert;
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
		return -1;

	if (SEC_ASN1EncodeItem(cms->arena, encoded, &whenitem,
			SEC_UTCTimeTemplate) == NULL) {
		return -1;
	}
	return 0;
}

int
generate_empty_sequence(cms_context *cms, SECItem *encoded)
{
	SECItem empty = {.type = SEC_ASN1_SEQUENCE,
			 .data = NULL,
			 .len = 0
	};
	if (SEC_ASN1EncodeItem(cms->arena, encoded, &empty,
			EmptySequenceTemplate) == NULL)
		return -1;
	return 0;
}

int
generate_octet_string(cms_context *cms, SECItem *encoded, SECItem *original)
{
	if (SEC_ASN1EncodeItem(cms->arena, encoded, original,
			SEC_OctetStringTemplate) == NULL)
		return -1;
	return 0;
}

int
generate_object_id(cms_context *cms, SECItem *encoded, SECOidTag tag)
{
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(tag);
	if (!oid)
		return -1;

	if (SEC_ASN1EncodeItem(cms->arena, encoded, &oid->oid,
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
generate_spc_string(cms_context *cms, SECItem *ssp, char *str, int len)
{
	SpcString ss;
	memset(&ss, '\0', sizeof (ss));

	SECITEM_AllocItem(cms->arena, &ss.unicode, len);
	if (!ss.unicode.data && len != 0) {
		cms->log(cms, LOG_ERR, "could not allocate memory: %s",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	memcpy(ss.unicode.data, str, len);
	ss.unicode.type = siBMPString;

	if (SEC_ASN1EncodeItem(cms->arena, ssp, &ss, SpcStringTemplate) == NULL) {
		cms->log(cms, LOG_ERR, "could not encode SpcString: %s",
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

void
generate_digest_step(cms_context *cms, void *data, size_t len)
{
	for (int i = 0; i < n_digest_params; i++)
		PK11_DigestOp(cms->digests[i].pk11ctx, data, len);
}

int
generate_digest_finish(cms_context *cms)
{
	for (int i = 0; i < n_digest_params; i++) {
		SECItem *digest = PORT_ArenaZAlloc(cms->arena,
						   sizeof (SECItem));
		if (!digest) {
			cms->log(cms, LOG_ERR, "could not allocate memory");
			goto err;
		}

		digest->type = siBuffer;
		digest->data = PORT_ArenaZAlloc(cms->arena, digest_params[i].size);
		digest->len = digest_params[i].size;

		if (!digest->data) {
			cms->log(cms, LOG_ERR, "could not allocate memory");
			goto err;
		}

		PK11_DigestFinal(cms->digests[i].pk11ctx,
			digest->data, &digest->len, digest_params[i].size);
		cms->digests[i].pe_digest = digest;
	}

	return 0;
err:
	for (int i = 0; i < n_digest_params; i++) {
		if (cms->digests[i].pk11ctx)
			PK11_DestroyContext(cms->digests[i].pk11ctx, PR_TRUE);

		if (cms->digests[i].pe_digest) {
			PORT_Free(cms->digests[i].pe_digest->data);
			PORT_Free(cms->digests[i].pe_digest);
		}
	}
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
		exit(1);
	}

	struct pe_hdr pehdr;
	if (pe_getpehdr(pe, &pehdr) == NULL) {
		cms->log(cms, LOG_ERR, "pesign: invalid output file header");
		return -1;
	}

	void *map = NULL;
	size_t map_size = 0;

	/* 1. Load the image header into memory - should be done
	 * 2. Initialize SHA hash context. */
	map = pe_rawfile(pe, &map_size);
	if (!map) {
		cms->log(cms, LOG_ERR, "pesign: could not get raw output "
					"file address");
		return -1;
	}

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
		cms->log(cms, LOG_ERR, "Pe header is invalid");
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
		cms->log(cms, LOG_ERR, "Pe data directory is invalid");
		goto error;
	}

	hash_size = (uintptr_t)&dd->certs - (uintptr_t)hash_base;
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "Pe data directory is invalid");
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
		cms->log(cms, LOG_ERR, "Pe relocations table is invalid");
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
			cms->log(cms, LOG_ERR, "Pe section \"%s\" has invalid"
				"address", shdrs[i].name);
			goto error_shdrs;
		}

		generate_digest_step(cms, hash_base, hash_size);

		hashed_bytes += hash_size;
	}

	if (map_size > hashed_bytes) {
		hash_base = (void *)((uintptr_t)map + hashed_bytes);
		hash_size = map_size - dd->certs.size - hashed_bytes;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			cms->log(cms, LOG_ERR, "Pe has invalid trailing data");
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
