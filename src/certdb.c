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

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <nss.h>
#include <prerror.h>
#include <cert.h>
#include <pkcs7t.h>
#include <pk11pub.h>

#include "pesigcheck.h"

static int
add_db_file(pesigcheck_context *ctx, db_specifier which, const char *dbfile,
	    db_f_type type)
{
	dblist *db = calloc(1, sizeof (dblist));
	
	if (!db)
		return -1;

	db->type = type;

	db->fd = open(dbfile, O_RDONLY);
	if (db->fd < 0) {
		save_errno(free(db));
		return -1;
	}

	struct stat sb;
	int rc = fstat(db->fd, &sb);
	if (rc < 0) {
		save_errno(close(db->fd);
			   free(db));
		return -1;
	}
	db->size = sb.st_size;

	db->map = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, db->fd, 0);
	if (db->map == MAP_FAILED) {
		save_errno(close(db->fd);
			   free(db));
		return -1;
	}

	EFI_SIGNATURE_LIST *certlist;
	EFI_SIGNATURE_DATA *cert;
	efi_guid_t efi_x509 = efi_guid_x509_cert;

	switch (type) {
	case DB_FILE:
		db->data = db->map;
		db->datalen = db->size;
		break;
	case DB_EFIVAR:
		/* skip the first 4 bytes (EFI attributes) */
		db->data = db->map + 4;
		db->datalen = db->size - 4;
		break;
	case DB_CERT:
		db->datalen = db->size + sizeof(EFI_SIGNATURE_LIST) +
			      sizeof(efi_guid_t);
		db->data = calloc(1, db->datalen);
		if (!db->data)
			return -1;

		certlist = (EFI_SIGNATURE_LIST *)db->data;
		memcpy((void *)&certlist->SignatureType, &efi_x509, sizeof(efi_guid_t));
		certlist->SignatureListSize = db->datalen;
		certlist->SignatureHeaderSize = 0;
		certlist->SignatureSize = db->size + sizeof(efi_guid_t);

		cert = (EFI_SIGNATURE_DATA *)(db->data + sizeof(EFI_SIGNATURE_LIST));
		memcpy((void *)cert->SignatureData, db->map, db->size);
		break;
	default:
		break;
	}

	dblist **tmp = which == DB ? &ctx->db : &ctx->dbx;

	db->next = *tmp;
	*tmp = db;

	return 0;
}

int
add_cert_db(pesigcheck_context *ctx, const char *filename)
{
	return add_db_file(ctx, DB, filename, DB_FILE);
}

int
add_cert_dbx(pesigcheck_context *ctx, const char *filename)
{
	return add_db_file(ctx, DBX, filename, DB_FILE);
}

int
add_cert_file(pesigcheck_context *ctx, const char *filename)
{
	return add_db_file(ctx, DB, filename, DB_CERT);
}

#define DB_PATH "/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define MOK_PATH "/sys/firmware/efi/efivars/MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23"
#define DBX_PATH "/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f"

void
init_cert_db(pesigcheck_context *ctx, int use_system_dbs)
{
	int rc = 0;

	if (!use_system_dbs)
		return;

	rc = add_db_file(ctx, DB, DB_PATH, DB_EFIVAR);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "pesigcheck: Could not add key database "
			"\"%s\": %m\n", DB_PATH);
		exit(1);
	}

	rc = add_db_file(ctx, DB, MOK_PATH, DB_EFIVAR);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "pesigcheck: Could not add key database "
			"\"%s\": %m\n", MOK_PATH);
		exit(1);
	}

	if (ctx->db == NULL) {
		fprintf(stderr, "pesigcheck: warning: "
			"No key database available\n");
	}

	rc = add_db_file(ctx, DBX, DBX_PATH, DB_EFIVAR);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "pesigcheck: Could not add revocation "
			"database \"%s\": %m\n", DBX_PATH);
		exit(1);
	}
}

typedef db_status (*checkfn)(pesigcheck_context *ctx, SECItem *sig,
			     efi_guid_t *sigtype, SECItem *pkcs7sig);

static db_status
check_db(db_specifier which, pesigcheck_context *ctx, checkfn check,
	 void *data, ssize_t datalen)
{
	SECItem pkcs7sig, sig;
	dblist *dbl = which == DB ? ctx->db : ctx->dbx;
	db_status found = NOT_FOUND;

	pkcs7sig.data = data;
	pkcs7sig.len = datalen;
	pkcs7sig.type = siBuffer;

	sig.type = siBuffer;

	while (dbl) {
		EFI_SIGNATURE_LIST *certlist;
		EFI_SIGNATURE_DATA *cert;
		size_t dbsize = dbl->datalen;
		unsigned long certcount;

		certlist = dbl->data;
		while (dbsize > 0 && dbsize >= certlist->SignatureListSize) {
			certcount = (certlist->SignatureListSize -
				     certlist->SignatureHeaderSize)
				    / certlist->SignatureSize;
			cert = (EFI_SIGNATURE_DATA *)((uint8_t *)certlist +
				sizeof(EFI_SIGNATURE_LIST) +
				certlist->SignatureHeaderSize);

			for (unsigned int i = 0; i < certcount; i++) {
				sig.data = cert->SignatureData;
				sig.len = certlist->SignatureSize - sizeof(efi_guid_t);
				found = check(ctx, &sig, &certlist->SignatureType,
					      &pkcs7sig);
				if (found == FOUND)
					return FOUND;
				cert = (EFI_SIGNATURE_DATA *)((uint8_t *)cert +
				        certlist->SignatureSize);
			}

			dbsize -= certlist->SignatureListSize;
			certlist = (EFI_SIGNATURE_LIST *)((uint8_t *)certlist +
			            certlist->SignatureListSize);
		}
		dbl = dbl->next;
	}
	return NOT_FOUND;
}

static db_status
check_hash(pesigcheck_context *ctx, SECItem *sig, efi_guid_t *sigtype,
	   SECItem *pkcs7sig)
{
	efi_guid_t efi_sha256 = efi_guid_sha256;
	efi_guid_t efi_sha1 = efi_guid_sha1;
	void *digest;

	if (memcmp(sigtype, &efi_sha256, sizeof(efi_guid_t)) == 0) {
		digest = ctx->cms_ctx->digests[0].pe_digest->data;
		if (memcmp (digest, sig->data, 32) == 0)
			return FOUND;
	} else if (memcmp(sigtype, &efi_sha1, sizeof(efi_guid_t)) == 0) {
		digest = ctx->cms_ctx->digests[1].pe_digest->data;
		if (memcmp (digest, sig->data, 20) == 0)
			return FOUND;
	}

	return NOT_FOUND;
}

db_status
check_db_hash(db_specifier which, pesigcheck_context *ctx)
{
	return check_db(which, ctx, check_hash, NULL, 0);
}

static PRTime
determine_reasonable_time(CERTCertificate *cert)
{
	PRTime notBefore, notAfter;
	CERT_GetCertTimes(cert, &notBefore, &notAfter);
	return notBefore;
}

static db_status
check_cert(pesigcheck_context *ctx, SECItem *sig, efi_guid_t *sigtype,
	   SECItem *pkcs7sig)
{
	SEC_PKCS7ContentInfo *cinfo = NULL;
	CERTCertificate *cert = NULL;
	CERTCertTrust trust;
	SECItem *content, *digest = NULL;
	PK11Context *pk11ctx = NULL;
	SECOidData *oid;
	PRBool result;
	SECStatus rv;
	db_status status = NOT_FOUND;

	efi_guid_t efi_x509 = efi_guid_x509_cert;

	if (memcmp(sigtype, &efi_x509, sizeof(efi_guid_t)) != 0)
		return NOT_FOUND;

	cinfo = SEC_PKCS7DecodeItem(pkcs7sig, NULL, NULL, NULL, NULL, NULL,
				    NULL, NULL);
	if (!cinfo)
		goto out;

	/* Generate the digest of contentInfo */
	/* XXX support only sha256 for now */
	digest = SECITEM_AllocItem(NULL, NULL, 32);
	if (digest == NULL)
		goto out;

	content = cinfo->content.signedData->contentInfo.content.data;
	oid = SECOID_FindOIDByTag(SEC_OID_SHA256);
	if (oid == NULL)
		goto out;
	pk11ctx = PK11_CreateDigestContext(oid->offset);
	if (ctx == NULL)
		goto out;
	if (PK11_DigestBegin(pk11ctx) != SECSuccess)
		goto out;
	/*   Skip the SEQUENCE tag */
	if (PK11_DigestOp(pk11ctx, content->data + 2, content->len - 2) != SECSuccess)
		goto out;
	if (PK11_DigestFinal(pk11ctx, digest->data, &digest->len, 32) != SECSuccess)
		goto out;

	/* Import the trusted certificate */
	cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(), sig, "Temp CA",
				       PR_FALSE, PR_TRUE);
	if (!cert) {
		fprintf(stderr, "Unable to create cert: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto out;
	}

	rv = CERT_DecodeTrustString(&trust, ",,P");
	if (rv != SECSuccess) {
		fprintf(stderr, "Unable to decode trust string: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto out;
	}

	rv = CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), cert, &trust);
	if (rv != SECSuccess) {
		fprintf(stderr, "Failed to change cert trust: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto out;
	}

	PRTime atTime;
	atTime = determine_reasonable_time(cert);
	/* Verify the signature */
	result = SEC_PKCS7VerifyDetachedSignatureAtTime(cinfo,
						certUsageObjectSigner,
						digest, HASH_AlgSHA256,
						PR_FALSE, atTime);
	if (!result) {
		fprintf(stderr, "%s\n",	PORT_ErrorToString(PORT_GetError()));
		goto out;
	}

	status = FOUND;
out:
	if (cinfo)
		SEC_PKCS7DestroyContentInfo(cinfo);
	if (cert)
		CERT_DestroyCertificate(cert);
	if (pk11ctx)
		PK11_DestroyContext(pk11ctx, PR_TRUE);
	if (digest)
		SECITEM_FreeItem(digest, PR_FALSE);

	return status;
}

db_status
check_db_cert(db_specifier which, pesigcheck_context *ctx, void *data, ssize_t datalen)
{
	return check_db(which, ctx, check_cert, data, datalen);
}
