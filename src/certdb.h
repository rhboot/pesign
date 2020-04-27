// SPDX-License-Identifier: GPLv2
/*
 * certdb.h - decls for our UEFI security databases
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef CERTDB_H
#define CERTDB_H 1

typedef enum {
	DB = 0,
	DBX = 1
} db_specifier;

typedef enum {
	FOUND = 0,
	NOT_FOUND = 1
} db_status;

typedef struct {
	efi_guid_t	SignatureOwner;
	uint8_t		SignatureData[1];
} EFI_SIGNATURE_DATA;

typedef struct {
	efi_guid_t	SignatureType;
	uint32_t	SignatureListSize;
	uint32_t	SignatureHeaderSize;
	uint32_t	SignatureSize;
} EFI_SIGNATURE_LIST;

extern db_status check_db_hash(db_specifier which, pesigcheck_context *ctx);
extern db_status check_db_cert(db_specifier which, pesigcheck_context *ctx,
				void *data, ssize_t datalen, SECItem *match);

extern void init_cert_db(pesigcheck_context *ctx, int use_system_dbs);
extern int add_cert_db(pesigcheck_context *ctx, const char *filename);
extern int add_cert_dbx(pesigcheck_context *ctx, const char *filename);
extern int add_cert_file(pesigcheck_context *ctx, const char *filename);

#endif /* CERTDB_H */
