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

extern db_status check_db_hash(db_specifier, peverify_context *ctx);
extern db_status check_db_cert(db_specifier, peverify_context *ctx,
				void *data, ssize_t datalen);

#endif /* CERTDB_H */
