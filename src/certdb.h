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

extern db_status check_db_hash(db_specifier which, peverify_context *ctx);
extern db_status check_db_cert(db_specifier which, peverify_context *ctx,
				void *data, ssize_t datalen);

extern void init_cert_db(peverify_context *ctx, int use_system_dbs);
extern int add_cert_db(peverify_context *ctx, const char *filename);
extern int add_cert_dbx(peverify_context *ctx, const char *filename);
extern int add_cert_file(peverify_context *ctx, const char *filename);

#endif /* CERTDB_H */
