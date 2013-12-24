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

#include "peverify.h"

static int
add_db_file(peverify_context *ctx, db_specifier which, const char *dbfile)
{
	dblist *db = calloc(1, sizeof (dblist));
	
	if (!db)
		return -1;

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

	dblist **tmp = which == DB ? &ctx->db : &ctx->dbx;

	db->next = *tmp;
	*tmp = db;

	return 0;
}

int
add_cert_db(peverify_context *ctx, const char *filename)
{
	return add_db_file(ctx, DB, filename);
}

int
add_cert_dbx(peverify_context *ctx, const char *filename)
{
	return add_db_file(ctx, DBX, filename);
}

#define DB_PATH "/sys/firmware/efi/vars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f/data"
#define MOK_PATH "/sys/firmware/efi/vars/fixmefixmefixme/data"
#define DBX_PATH "/sys/firmware/efi/vars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f/data"

void
init_cert_db(peverify_context *ctx, int use_system_dbs)
{
	int rc = 0;

	if (!use_system_dbs)
		return;

	rc = add_db_file(ctx, DB, DB_PATH);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "peverify: Could not add key database "
			"\"%s\": %m\n", DB_PATH);
		exit(1);
	}

	rc = add_db_file(ctx, DB, MOK_PATH);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "peverify: Could not add key database "
			"\"%s\": %m\n", DB_PATH);
		exit(1);
	}

	if (ctx->db == NULL) {
		fprintf(stderr, "peverify: warning: "
			"No key database available\n");
	}

	rc = add_db_file(ctx, DBX, DBX_PATH);
	if (rc < 0 && errno != ENOENT) {
		fprintf(stderr, "peverify: Could not add revocation "
			"database \"%s\": %m\n", DBX_PATH);
		exit(1);
	}
}

typedef db_status (*checkfn)(peverify_context *ctx, void *sigdata,
			     efi_guid_t *sigtype);

static db_status
check_db(db_specifier which, peverify_context *ctx, checkfn check)
{
	dblist *dbl = which == DB ? ctx->db : ctx->dbx;
	db_status found = NOT_FOUND;

	while (dbl) {
		EFI_SIGNATURE_LIST *certlist;
		EFI_SIGNATURE_DATA *cert;
		size_t dbsize = dbl->size;
		unsigned long certcount;

		certlist = dbl->map;
		while (dbsize > 0 && dbsize >= certlist->SignatureListSize) {
			certcount = (certlist->SignatureListSize -
				     certlist->SignatureHeaderSize)
				    / certlist->SignatureSize;
			cert = (EFI_SIGNATURE_DATA *)((uint8_t *)certlist +
				sizeof(*cert) + certlist->SignatureHeaderSize);
			
			for (int i = 0; i < certcount; i++) {
				found = check(ctx,
					      cert->SignatureData,
					      &certlist->SignatureType);
				if (found == FOUND)
					return FOUND;
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
check_hash(peverify_context *ctx, void *sigdata, efi_guid_t *sigtype)
{
	return NOT_FOUND;
}

db_status
check_db_hash(db_specifier which, peverify_context *ctx)
{
	return check_db(which, ctx, check_hash);
}

static db_status
check_cert(peverify_context *ctx, void *sigdata, efi_guid_t *sigtype)
{
	return NOT_FOUND;
}

db_status
check_db_cert(db_specifier which, peverify_context *ctx, void *data, ssize_t datalen)
{
	return check_db(which, ctx, check_cert);
}
