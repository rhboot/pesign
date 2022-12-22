// SPDX-License-Identifier: GPLv2
/*
 * cms_common.c - Implement the common parts pf PKCS7 that we need
 *                regardless of the target file type.
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "pesign.h"

#include <prerror.h>
#include <nss.h>
#include <secport.h>
#include <secpkcs7.h>
#include <secder.h>
#include <keyhi.h>
#include <base64.h>
#include <pk11pub.h>
#include <secerr.h>
#include <certt.h>

#include "hex.h"

/*
 * Note that cms->selected_digest defaults to 0, which means the first
 * entry of this array is the default digest.
 */
const struct digest_param digest_params[] = {
	[DIGEST_PARAM_SHA256] = {
		.name = "sha256",
		.digest_tag = SEC_OID_SHA256,
		.signature_tag = SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION,
		.digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
		.efi_guid = &efi_guid_sha256,
		.size = 32
	},
#if 1
	[DIGEST_PARAM_SHA1] = {
		.name = "sha1",
		.digest_tag = SEC_OID_SHA1,
		.signature_tag = SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION,
		.digest_encryption_tag = SEC_OID_PKCS1_RSA_ENCRYPTION,
		.efi_guid = &efi_guid_sha1,
		.size = 20
	},
#endif
};
const unsigned int n_digest_params = sizeof (digest_params) / sizeof (digest_params[0]);

SECOidTag
digest_get_digest_oid(cms_context *cms)
{
	unsigned int i = cms->selected_digest;
	return digest_params[i].digest_tag;
}

SECOidTag
digest_get_encryption_oid(cms_context *cms)
{
	unsigned int i = cms->selected_digest;
	return digest_params[i].digest_encryption_tag;
}

SECOidTag
digest_get_signature_oid(cms_context *cms)
{
	unsigned int i = cms->selected_digest;
	return digest_params[i].signature_tag;
}

int
digest_get_digest_size(cms_context *cms)
{
	unsigned int i = cms->selected_digest;
	return digest_params[i].size;
}

void
teardown_digests(cms_context *ctx)
{
	struct digest *digests = ctx->digests;

	if (!digests)
		return;

	for (unsigned int i = 0; i < n_digest_params; i++) {
		if (digests[i].pk11ctx) {
			PK11_Finalize(digests[i].pk11ctx);
			PK11_DestroyContext(digests[i].pk11ctx, PR_TRUE);
		}
		if (digests[i].pe_digest) {
			/* XXX sure seems like we should be freeing it here,
			 * but that's segfaulting, and we know it'll get
			 * cleaned up with PORT_FreeArena a couple of lines
			 * down.
			 */
			digests[i].pe_digest = NULL;
		}
	}
	PORT_Free(digests);
	ctx->digests = NULL;
}

static int PRINTF(3, 4)
cms_common_log(cms_context *ctx UNUSED, int priority,
	       char *fmt, ...)
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
		cnreterr(-1, cms, "could not create cryptographic arena");

	cms->selected_digest = DEFAULT_DIGEST_PARAM;

	INIT_LIST_HEAD(&cms->pk12_ins);
	cms->pk12_out.fd = -1;
	cms->db_out = cms->dbx_out = cms->dbt_out = -1;

	return 0;
}

void
cms_context_fini(cms_context *cms)
{
	struct list_head *n, *pos;

	if (cms->cert) {
		CERT_DestroyCertificate(cms->cert);
		cms->cert = NULL;
	}

	switch (cms->pwdata.source) {
	case PW_SOURCE_INVALID:
	case PW_PROMPT:
	case PW_DEVICE:
	case PW_FROMFILEDB:
	case PW_FROMENV:
	case PW_FROMFILE:
	case PW_FROMFD:
	case PW_SOURCE_MAX:
		break;
	case PW_DATABASE:
		xfree(cms->pwdata.data);
		break;
	case PW_PLAINTEXT:
		memset(cms->pwdata.data, 0, strlen(cms->pwdata.data));
		xfree(cms->pwdata.data);
		break;
	}
	cms->pwdata.source = PW_SOURCE_INVALID;
	cms->pwdata.orig_source = PW_SOURCE_INVALID;

	if (cms->privkey) {
		free(cms->privkey);
		cms->privkey = NULL;
	}

	if (cms->db_out >= 0)
		fsync(cms->db_out);
	xclose(cms->db_out);
	if (cms->dbx_out >= 0)
		fsync(cms->dbx_out);
	xclose(cms->dbx_out);
	if (cms->dbt_out >= 0)
		fsync(cms->dbt_out);
	xclose(cms->dbt_out);
	list_for_each_safe(pos, n, &cms->pk12_ins) {
		pk12_file_t *file = list_entry(pos, pk12_file_t, list);

		xfree(file->path);
		if (file->fd >= 0) {
			/*
			 * This may or may not be writable...
			 */
			fsync(file->fd);
			errno = 0;
		}
		xclose(file->fd);
		xfree(file->pw);
	}
	xclose(cms->pk12_out.fd);
	xfree(cms->pk12_out.path);
	xfree(cms->pk12_out.pw);

	/* These were freed when the arena was destroyed */
	if (cms->tokenname)
		cms->tokenname = NULL;
	if (cms->certname)
		cms->certname = NULL;

	if (cms->newsig.data) {
		free_poison(cms->newsig.data, cms->newsig.len);
		free(cms->newsig.data);
		memset(&cms->newsig, '\0', sizeof (cms->newsig));
	}

	cms->selected_digest = DEFAULT_DIGEST_PARAM;

	if (cms->ci_digest) {
		free_poison(cms->ci_digest->data, cms->ci_digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		cms->ci_digest = NULL;
	}

	teardown_digests(cms);

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
		free(cms->signatures[i]->data);
		free(cms->signatures[i]);
	}

	xfree(cms->signatures);
	cms->num_signatures = 0;

	if (cms->authbuf) {
		xfree(cms->authbuf);
		cms->authbuf_len = 0;
	}

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
		set_errno_guard();
		xfree(cms);
		cms = NULL;
		return -1;
	}
	*cmsp = cms;
	return 0;
}

void cms_set_pw_callback(cms_context *cms, PK11PasswordFunc func)
{
	cms->func = func;
}

void cms_set_pw_data(cms_context *cms, secuPWData *pwdata)
{
	ingress();

	switch (cms->pwdata.source) {
	case PW_SOURCE_INVALID:
	case PW_PROMPT:
	case PW_DEVICE:
	case PW_SOURCE_MAX:
		break;

	case PW_FROMFD:
		if (cms->pwdata.intdata >= 0 &&
		    !(pwdata && pwdata->source == PW_FROMFD &&
		      cms->pwdata.intdata == pwdata->intdata))
			close(cms->pwdata.intdata);
		break;

	case PW_FROMFILEDB:
	case PW_FROMENV:
	case PW_FROMFILE:
	case PW_PLAINTEXT:
		memset(cms->pwdata.data, 0, strlen(cms->pwdata.data));
		xfree(cms->pwdata.data);
		break;

	case PW_DATABASE:
		xfree(cms->pwdata.data);
		break;
	}

	if (!pwdata) {
		cms->pwdata.source = PW_SOURCE_INVALID;
		dbgprintf("pwdata:NULL");
	} else {
		memmove(&cms->pwdata, pwdata, sizeof(*pwdata));
		dbgprintf("pwdata:%p", pwdata);
		dbgprintf("pwdata->source:%d", pwdata->source);
		dbgprintf("pwdata->data:%p (\"%s\")", pwdata->data,
			  pwdata->data ? pwdata->data : "(null)");
	}

	egress();
}

int
set_digest_parameters(cms_context *cms, char *name)
{
	if (strcmp(name, "help")) {
		for (unsigned int i = 0; i < n_digest_params; i++) {
			if (!strcmp(name, digest_params[i].name)) {
				cms->selected_digest = i;
				return 0;
			}
		}
	} else {
		printf("Supported digests: ");
		for (unsigned int i = 0; digest_params[i].name != NULL; i++) {
			printf("%s ", digest_params[i].name);
		}
		printf("\n");
	}
	return -1;
}

struct validity_cbdata {
	cms_context *cms;
	PK11SlotListElement *psle;
	PK11SlotInfo *slot;
	CERTCertificate *cert;
};

static SECStatus
is_valid_cert(CERTCertificate *cert, void *data)
{
	struct validity_cbdata *cbd = (struct validity_cbdata *)data;
	PK11SlotInfo *slot = cbd->slot;
	SECKEYPrivateKey *privkey = NULL;
	int errnum;

	errnum = PORT_GetError();
	if (errnum == SEC_ERROR_EXTENSION_NOT_FOUND) {
		dbgprintf("Got SEC_ERROR_EXTENSION_NOT_FOUND; clearing");
		PORT_SetError(0);
		errnum = 0;
	}
	if (cert == NULL) {
		if (!errnum)
			PORT_SetError(SEC_ERROR_UNKNOWN_CERT);
		return SECFailure;
	}

	privkey = PK11_FindPrivateKeyFromCert(slot, cert, cbd->cms);
	if (privkey != NULL) {
		if (cbd->cert)
			CERT_DestroyCertificate(cbd->cert);
		cbd->cert = CERT_DupCertificate(cert);
		CERT_DestroyCertificate(cert);
		SECKEY_DestroyPrivateKey(privkey);
		PORT_SetError(0);
		return SECSuccess;
	}
	return SECFailure;
}

static SECStatus
is_valid_cert_without_private_key(CERTCertificate *cert, void *data)
{
	struct validity_cbdata *cbd = (struct validity_cbdata *)data;
	PK11SlotInfo *slot = cbd->slot;
	SECKEYPrivateKey *privkey = NULL;
	int errnum;

	errnum = PORT_GetError();
	if (errnum == SEC_ERROR_EXTENSION_NOT_FOUND) {
		dbgprintf("Got SEC_ERROR_EXTENSION_NOT_FOUND; clearing");
		PORT_SetError(0);
		errnum = 0;
	}
	if (cert == NULL) {
		if (!errnum)
			PORT_SetError(SEC_ERROR_UNKNOWN_CERT);
		return SECFailure;
	}

	privkey = PK11_FindPrivateKeyFromCert(slot, cert, cbd->cms);
	if (privkey == NULL) {
		if (cbd->cert)
			CERT_DestroyCertificate(cbd->cert);
		PORT_SetError(0);
		cbd->cert = CERT_DupCertificate(cert);
		CERT_DestroyCertificate(cert);
		return SECSuccess;
	} else {
		SECKEY_DestroyPrivateKey(privkey);
		CERT_DestroyCertificate(cert);
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

static inline void
unescape_html_in_place(char *s)
{
	size_t sz = strlen(s) + 1;
	size_t pos = 0;
	char *s1;

	dbgprintf("unescaping pos:%zd sz:%zd \"%s\"", pos, sz, s);
	do {
		s1 = strchrnul(&s[pos], '%');
		if (s1[0] == '\0')
			break;
		dbgprintf("s1 is \"%s\"", s1);
		if ((size_t)(s1 - s) < (size_t)(sz - 3)) {
			int c;

			c = (hexchar_to_bin(s1[1]) << 4)
			    | (hexchar_to_bin(s1[2]) & 0xf);
			dbgprintf("replacing %%%c%c with 0x%02hhx", s1[1], s1[2], (char)c);
			s1[0] = c;
			memmove(&s1[1], &s1[3], sz - (&s1[3] - s));
			sz -= 2;
			pos = &s1[1] - s;
			dbgprintf("new pos:%zd sz:%zd s:\"%s\"", pos, sz, s);
		}
	} while (pos < sz);
}

static inline void
resolve_pkcs11_token_in_place(char *tokenname)
{
	char *ntn = tokenname;
	size_t pos = 0;

	while (*ntn) {
		char *cp = strchrnul(ntn, ';');
		char c = *cp;
		*cp = '\0';

		dbgprintf("ntn:\"%s\"", ntn);
		if (!strncmp(&ntn[pos], "token=", 6)) {
			ntn += 6;
			memmove(tokenname, ntn, cp - ntn + 1);
			break;
		}

		*cp = c;
		ntn = cp + (c ? 1 : 0);
	}
	unescape_html_in_place(tokenname);
	dbgprintf("token name is \"%s\"", tokenname);
}

#define resolve_token_name(tn) ({					\
	char *s_ = tn;							\
	if (!strncmp(tn, "pkcs11:", 7))	{				\
		dbgprintf("provided token name is pkcs11 uri; parsing");\
		s_ = strdupa(tn+7);					\
		resolve_pkcs11_token_in_place(s_);			\
	}								\
	s_;								\
})

int
unlock_nss_token(cms_context *cms)
{
	char *tokenname = resolve_token_name(cms->tokenname);

	dbgprintf("setting password function to %s",
		  cms->func ? "cms->func" : "SECU_GetModulePassword");
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, cms);
	if (!slots)
		cnreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		nssreterr(-1, "Could not find token \"%s\"", tokenname);
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) &&
			!PK11_IsLoggedIn(psle->slot, cms)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, cms);
		if (status != SECSuccess) {
			save_port_err() {
				int err = PORT_GetError();
				PK11_DestroySlotListElement(slots, &psle);
				PK11_FreeSlotList(slots);
				cms->log(cms, LOG_ERR,
					 "authentication failed for token \"%s\": %s",
					 tokenname, PORT_ErrorToString(err));
			}
			return -1;
		}
	}

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	return 0;
}

int
find_certificate(cms_context *cms, int needs_private_key)
{
	char *tokenname = resolve_token_name(cms->tokenname);

	struct validity_cbdata cbd;
	if (!cms->certname || !*cms->certname) {
		cms->log(cms, LOG_ERR, "no certificate name specified");
		return -1;
	}

	dbgprintf("setting password function to %s",
		  cms->func ? "cms->func" : "SECU_GetModulePassword");
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, cms);
	if (!slots)
		cnreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		dbgprintf("looking for token \"%s\", got \"%s\"",
			  tokenname, PK11_GetTokenName(psle->slot));
		if (!strcmp(tokenname, PK11_GetTokenName(psle->slot))) {
			dbgprintf("found token \"%s\"", tokenname);
			break;
		}

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		nssreterr(-1, "Could not find token \"%s\"", tokenname);
	}

	int errnum;
	SECStatus status;
	if ((needs_private_key || !PK11_IsFriendly(psle->slot)) &&
	    (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, cms))) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, cms);
		if (status != SECSuccess) {
			save_port_err() {
				errnum = PORT_GetError();
				PK11_DestroySlotListElement(slots, &psle);
				PK11_FreeSlotList(slots);
				cms->log(cms, LOG_ERR,
					 "authentication failed for token \"%s\": %s",
					 tokenname, PORT_ErrorToString(errnum));
			}
			return -1;
		}
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist) {
		save_port_err() {
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get certificate list");
	}

	SECItem nickname = {
		.data = (void *)cms->certname,
		.len = strlen(cms->certname) + 1,
		.type = siUTF8String,
	};

	cms->psle = psle;

	cbd.cms = cms;
	cbd.psle = psle;
	cbd.slot = psle->slot;
	cbd.cert = NULL;

	PORT_SetError(SEC_ERROR_UNKNOWN_CERT);
	if (needs_private_key) {
		status = PK11_TraverseCertsForNicknameInSlot(&nickname,
					psle->slot, is_valid_cert, &cbd);
		errnum = PORT_GetError();
		if (errnum)
			dbgprintf("PK11_TraverseCertsForNicknameInSlot():%s:%s",
				  PORT_ErrorToName(errnum),
				  PORT_ErrorToString(errnum));
	} else {
		status = PK11_TraverseCertsForNicknameInSlot(&nickname,
					psle->slot,
					is_valid_cert_without_private_key,
					&cbd);
		errnum = PORT_GetError();
		if (errnum)
			dbgprintf("PK11_TraverseCertsForNicknameInSlot():%s:%s",
				PORT_ErrorToName(errnum),
				PORT_ErrorToString(errnum));
	}
	dbgprintf("status:%d cbd.cert:%p", status, cbd.cert);
	if (status == SECSuccess && cbd.cert != NULL) {
		if (cms->cert)
			CERT_DestroyCertificate(cms->cert);
		cms->cert = CERT_DupCertificate(cbd.cert);
	} else {
		errnum = PORT_GetError();
		dbgprintf("token traversal %s; cert %sfound:%s:%s",
			  status == SECSuccess ? "succeeded" : "failed",
			  cbd.cert == NULL ? "not" : "",
			  PORT_ErrorToName(errnum),
			  PORT_ErrorToString(errnum));
	}

	save_port_err() {
		dbgprintf("Destroying cert list");
		CERT_DestroyCertList(certlist);
		dbgprintf("Destroying slot list element");
		PK11_DestroySlotListElement(slots, &psle);
		dbgprintf("Destroying slot list");
		PK11_FreeSlotList(slots);
		cms->psle = NULL;
	}
	if (status != SECSuccess || cms->cert == NULL)
		cnreterr(-1, cms, "could not find certificate");

	return 0;
}

int
find_slot_for_token(cms_context *cms, PK11SlotInfo **slot)
{
	if (!cms->tokenname) {
		cms->log(cms, LOG_ERR, "no token name specified");
		return -1;
	}

	char *tokenname = resolve_token_name(cms->tokenname);

	dbgprintf("setting password function to %s",
		  cms->func ? "cms->func" : "SECU_GetModulePassword");
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, cms);
	if (!slots)
		cnreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		nssreterr(-1, "Could not find token \"%s\"", tokenname);
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, cms)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, cms);
		if (status != SECSuccess) {
			save_port_err() {
				int err = PORT_GetError();
				PK11_DestroySlotListElement(slots, &psle);
				PK11_FreeSlotList(slots);
				cms->log(cms, LOG_ERR,
					 "authentication failed for token \"%s\": %s",
					 tokenname, PORT_ErrorToString(err));
			}
			return -1;
		}
	}
	*slot = psle->slot;

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	return 0;
}

int
find_certificate_by_callback(cms_context *cms,
			     find_cert_match_t *match, void *cbdata,
			     CERTCertificate **cert)
{
	char *tokenname = resolve_token_name(cms->tokenname);

	if (!match) {
		cms->log(cms, LOG_ERR, "no certificate match callback not specified");
		return -1;
	}
	if (!cbdata) {
		cms->log(cms, LOG_ERR, "no certificate callback data not specified");
		return -1;
	}

	dbgprintf("setting password function to %s",
		  cms->func ? "cms->func" : "SECU_GetModulePassword");
	PK11_SetPasswordFunc(cms->func ? cms->func : SECU_GetModulePassword);

	PK11SlotList *slots = NULL;
	slots = PK11_GetAllTokens(CKM_RSA_PKCS, PR_FALSE, PR_TRUE, cms);
	if (!slots)
		cnreterr(-1, cms, "could not get pk11 token list");

	PK11SlotListElement *psle = NULL;
	psle = PK11_GetFirstSafe(slots);
	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get pk11 safe");
	}

	while (psle) {
		if (!strcmp(tokenname, PK11_GetTokenName(psle->slot)))
			break;

		psle = PK11_GetNextSafe(slots, psle, PR_FALSE);
	}

	if (!psle) {
		save_port_err() {
			PK11_FreeSlotList(slots);
			cms->log(cms, LOG_ERR, "could not find token \"%s\"",
				 tokenname);
		}
		return -1;
	}

	SECStatus status;
	if (PK11_NeedLogin(psle->slot) && !PK11_IsLoggedIn(psle->slot, cms)) {
		status = PK11_Authenticate(psle->slot, PR_TRUE, cms);
		if (status != SECSuccess) {
			save_port_err() {
				int err = PORT_GetError();
				PK11_DestroySlotListElement(slots, &psle);
				PK11_FreeSlotList(slots);
				cms->log(cms, LOG_ERR,
					 "authentication failed for token \"%s\": %s",
					 tokenname, PORT_ErrorToString(err));
			}
			return -1;
		}
	}

	CERTCertList *certlist = NULL;
	certlist = PK11_ListCertsInSlot(psle->slot);
	if (!certlist) {
		save_port_err() {
			PK11_DestroySlotListElement(slots, &psle);
			PK11_FreeSlotList(slots);
		}
		cnreterr(-1, cms, "could not get certificate list");
	}

	CERTCertListNode *node = NULL;
	for_each_cert(certlist, tmpnode) {
		/* If we're looking up the issuer of some cert, and the
		 * issuer isn't in the database, we'll get back what is
		 * essentially a template that's in NSS's cache waiting to
		 * be filled out.  We can't use that, it'll just cause
		 * CERT_DupCertificate() to segfault. */
		if (!tmpnode || !tmpnode->cert
		    || !tmpnode->cert->derCert.data
		    || !tmpnode->cert->derCert.len
		    || !tmpnode->cert->derIssuer.data
		    || !tmpnode->cert->derIssuer.len
		    || !tmpnode->cert->serialNumber.data
		    || !tmpnode->cert->serialNumber.len)
			continue;

		int rc = match(tmpnode->cert, cbdata);
		if (rc == 1) {
			node = tmpnode;
			break;
		}
	}

	if (!node) {
		PK11_DestroySlotListElement(slots, &psle);
		PK11_FreeSlotList(slots);
		CERT_DestroyCertList(certlist);
		cnreterr(-1, cms, "Could not find certificate");
	}

	*cert = CERT_DupCertificate(node->cert);

	PK11_DestroySlotListElement(slots, &psle);
	PK11_FreeSlotList(slots);
	CERT_DestroyCertList(certlist);

	return 0;

}

static int
match_subject(CERTCertificate *cert, void *cbdatap)
{
	if (!cert->subjectName)
		return 0;

	if (!strcmp(cert->subjectName, (char *)cbdatap))
		return 1;

	return 0;
}

int
find_named_certificate(cms_context *cms, char *name, CERTCertificate **cert)
{
	if (!name)
		cnreterr(-1, cms, "no subject name specified");

	return find_certificate_by_callback(cms, match_subject, name, cert);
}

static int
match_issuer_and_serial(CERTCertificate *cert, void *cbdatap)
{
	CERTIssuerAndSN *ias = cbdatap;
	bool found = false;

	if (ias->derIssuer.len == cert->derIssuer.len &&
	    ias->derIssuer.len != 0) {
		if (memcmp(ias->derIssuer.data, cert->derIssuer.data,
			   ias->derIssuer.len))
			return 0;
		found = true;
	}

	if (!found) {
		SECComparison seccomp;

		seccomp = CERT_CompareName(&ias->issuer, &cert->issuer);
		if (seccomp != SECEqual)
			return 0;
	}

	if (ias->serialNumber.len != cert->serialNumber.len)
		return 0;

	if (memcmp(ias->serialNumber.data, cert->serialNumber.data,
		   ias->serialNumber.len))
		return 0;

	return 1;
}

int
find_certificate_by_issuer_and_sn(cms_context *cms,
				  CERTIssuerAndSN *ias,
				  CERTCertificate **cert)
{
	if (!ias)
		cnreterr(-1, cms, "invalid issuer and serial number");

	return find_certificate_by_callback(cms, match_issuer_and_serial, &ias, cert);
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
		cnreterr(-1, cms, "could not encode string");
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
		cnreterr(-1, cms, "could not encode timestamp");

	if (SEC_ASN1EncodeItem(cms->arena, encoded, &whenitem,
			SEC_UTCTimeTemplate) == NULL)
		cnreterr(-1, cms, "could not encode timestamp");
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
		cnreterr(-1, cms, "could not encode empty sequence");
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
		cnreterr(-1, cms, "could not encode context specific data");
	return 0;
}

static SEC_ASN1Template EKUOidSequence[] = {
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = 0,
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0 }
};

int
make_eku_oid(cms_context *cms, SECItem *encoded, SECOidTag oid_tag)
{
	void *rv;
	SECOidData *oid_data;

	oid_data = SECOID_FindOIDByTag(oid_tag);
	if (!oid_data)
		cnreterr(-1, cms, "could not encode eku oid data");

	rv = SEC_ASN1EncodeItem(cms->arena, encoded, &oid_data->oid,
				EKUOidSequence);
	if (rv == NULL)
		cnreterr(-1, cms, "could not encode eku oid data");

	encoded->type = siBuffer;
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
		cnreterr(-1, cms, "could not encode octet string");

	return 0;
}

int
generate_object_id(cms_context *cms, SECItem *der, SECOidTag tag)
{
	SECOidData *oid;

	oid = SECOID_FindOIDByTag(tag);
	if (!oid)
		cnreterr(-1, cms, "could not find OID");

	void *ret;
	ret = SEC_ASN1EncodeItem(cms->arena, der, &oid->oid,
						SEC_ObjectIDTemplate);
	if (ret == NULL)
		cnreterr(-1, cms, "could not encode ODI");
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
		cnreterr(-1, cms, "could not encode Algorithm ID");

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
			cnreterr(-1, cms, "could not allocate memory");

		memcpy(ss.unicode.data, str, len);
	}
	ss.unicode.type = siBMPString;

	if (SEC_ASN1EncodeItem(cms->arena, ssp, &ss, SpcStringTemplate) == NULL)
		cnreterr(-1, cms, "could not encode SpcString");

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

int
generate_digest_begin(cms_context *cms)
{
	struct digest *digests = NULL;

	if (cms->digests) {
		digests = cms->digests;
	} else {
		digests = PORT_ZAlloc(n_digest_params * sizeof (*digests));
		if (digests == NULL)
			cnreterr(-1, cms, "could not allocate digest context");
	}

	for (unsigned int i = 0; i < n_digest_params; i++) {
		digests[i].pk11ctx = PK11_CreateDigestContext(
						digest_params[i].digest_tag);
		if (!digests[i].pk11ctx)
			cngotoerr(err, cms, "could not create digest context");

		PK11_DigestBegin(digests[i].pk11ctx);
	}

	cms->digests = digests;
	return 0;

err:
	for (unsigned int i = 0; i < n_digest_params; i++) {
		if (digests[i].pk11ctx)
			PK11_DestroyContext(digests[i].pk11ctx, PR_TRUE);
	}

	free(digests);
	return -1;
}

void
generate_digest_step(cms_context *cms, void *data, size_t len)
{
	for (unsigned int i = 0; i < n_digest_params; i++)
		PK11_DigestOp(cms->digests[i].pk11ctx, data, len);
}

int
generate_digest_finish(cms_context *cms)
{
	void *mark = PORT_ArenaMark(cms->arena);

	for (unsigned int i = 0; i < n_digest_params; i++) {
		SECItem *digest = PORT_ArenaZAlloc(cms->arena,sizeof (SECItem));
		if (digest == NULL)
			cngotoerr(err, cms, "could not allocate memory");

		digest->type = siBuffer;
		digest->len = digest_params[i].size;
		digest->data = PORT_ArenaZAlloc(cms->arena, digest_params[i].size);
		if (digest->data == NULL)
			cngotoerr(err, cms, "could not allocate memory");

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
	for (unsigned int i = 0; i < n_digest_params; i++) {
		if (cms->digests[i].pk11ctx)
			PK11_DestroyContext(cms->digests[i].pk11ctx, PR_TRUE);
	}
	PORT_ArenaRelease(cms->arena, mark);
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
	int i = cms->selected_digest;

	if (cms->digests[i].pe_digest == NULL)
		cnreterr(-1, cms, "PE digest has not been allocated");

	if (content_is_empty(cms->digests[i].pe_digest->data,
			cms->digests[i].pe_digest->len))
		cnreterr(-1, cms, "PE binary has not been digested");

	SECItem sd_der;
	memset(&sd_der, '\0', sizeof(sd_der));
	rc = generate_spc_signed_data(cms, &sd_der);
	if (rc < 0)
		cnreterr(-1, cms, "could not create signed data");

	memcpy(&cms->newsig, &sd_der, sizeof (cms->newsig));
	cms->newsig.data = malloc(sd_der.len);
	if (!cms->newsig.data)
		cnreterr(-1, cms, "could not allocate signed data");
	memcpy(cms->newsig.data, sd_der.data, sd_der.len);
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
		cnreterr(-1, cms, "could not encode validity");
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
		cnreterr(-1, cms, "could not encode set");
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
		save_port_err() {
			PORT_ArenaRelease(cms->arena, mark);
		}
		cnreterr(-1, cms, "could not encode set");
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
		cnreterr(-1, cms, "could not encode common name");

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
		cnreterr(-1, cms, "could not create arena");

	void *real_arena = cms->arena;
	cms->arena = arena;

	oid = SECOID_FindOID(&certava->type);
	if (!oid) {
		save_port_err() {
			PORT_FreeArena(arena, PR_TRUE);
		}
		cms->arena = real_arena;
		cnreterr(-1, cms, "could not find OID");
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
		save_port_err() {
			PORT_FreeArena(arena, PR_TRUE);
		}
		cms->arena = real_arena;
		cnreterr(-1, cms, "could not encode AVA");
	}

	der->type = tmp.type;
	der->len = tmp.len;
	der->data = PORT_ArenaAlloc(real_arena, tmp.len);
	if (!der->data) {
		save_port_err() {
			PORT_FreeArena(arena, PR_TRUE);
		}
		cms->arena = real_arena;
		cnreterr(-1, cms, "could not allocate AVA");
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
		while (avas && ((*avas++) != NULL))
			num_items++;
	}

	if (num_items == 0) {
		PORT_ArenaRelease(cms->arena, marka);
		cnreterr(-1, cms, "No name items to encode");
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
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(AuthInfo, url),
	 .sub = &SEC_AnyTemplate,
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
	{.kind = SEC_ASN1_ANY,
	 .offset = offsetof(AuthInfo, url),
	 .sub = &SEC_AnyTemplate,
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
		cnreterr(-1, cms, "could not get CA issuers OID");

	memcpy(&ai.oid, &oid->oid, sizeof (ai.oid));

	SECItem urlitem = {
		.data = (unsigned char *)url,
		.len = strlen(url),
		.type = siBuffer
	};
	int rc = make_context_specific(cms, 6, &ai.url, &urlitem);
	if (rc < 0)
		return rc;

	void *ret;
	SECItem unwrapped;
	ret = SEC_ASN1EncodeItem(cms->arena, &unwrapped, &ai, AuthInfoTemplate);
	if (ret == NULL)
		cnreterr(-1, cms, "could not encode CA Issuers");

	rc = wrap_in_seq(cms, der, &unwrapped, 1);
	if (rc < 0)
		return rc;
	return 0;

	/* I've no idea how to get SEC_ASN1EncodeItem to spit out the thing
	 * we actually want here.  So once again, just force the data to
	 * look correct :( */
	if (unwrapped.len < 12)
		cnreterr(-1, cms,
			 "generated CA Issuers Info cannot possibly be valid");

	unwrapped.data[12] = 0x86;
	unwrapped.type = siBuffer;

	AuthInfo wrapper;
	oid = SECOID_FindOIDByTag(SEC_OID_X509_AUTH_INFO_ACCESS);
	if (!oid)
		cnreterr(-1, cms, "could not find Auth Info Access OID");

	memcpy(&wrapper.oid, &oid->oid, sizeof (ai.oid));

	wrap_in_seq(cms, &wrapper.url, &unwrapped, 1);

	ret = SEC_ASN1EncodeItem(cms->arena, der, &wrapper,
					AuthInfoWrapperTemplate);
	if (ret == NULL)
		cnreterr(-1, cms, "could not encode CA Issuers OID");

	return 0;
}

int
generate_keys(cms_context *cms, PK11SlotInfo *slot,
		SECKEYPrivateKey **privkey, SECKEYPublicKey **pubkey)
{
	PK11RSAGenParams rsaparams = {
		.keySizeInBits = 2048,
		.pe = 0x010001,
	};

	SECStatus rv;
	rv = PK11_Authenticate(slot, PR_TRUE, cms);
	if (rv != SECSuccess)
		cnreterr(-1, cms, "could not authenticate with pk11 service");

	void *params = &rsaparams;
	*privkey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN,
					params, pubkey, PR_TRUE, PR_TRUE,
					cms);
	if (!*privkey)
		cnreterr(-1, cms, "could not generate RSA keypair");
	return 0;
}

// vim:fenc=utf-8:tw=75:noet
