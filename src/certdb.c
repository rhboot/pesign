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

#include "peverify.h"

int
add_db_file(peverify_context *ctx, db_specifier which, char *dbfile)
{
	dblist *db = calloc(1, sizeof (dblist));
	
	if (!db)
		return -1;

	db->f = fopen(dbfile, "r");
	if (!db->f) {
		free(db);
		return -1;
	}

	dblist **tmp = which == DB ? &ctx->db : &ctx->dbx;

	db->next = *tmp;
	*tmp = db;

	return 0;
}


db_status
check_db_hash(db_specifier which, peverify_context *ctx)
{
	return NOT_FOUND;
}

db_status
check_db_cert(db_specifier which, peverify_context *ctx,
			void *data, ssize_t datalen)
{
	return NOT_FOUND;
}
