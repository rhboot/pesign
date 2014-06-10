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
#ifndef AUTHVAR_CONTEXT_H
#define AUTHVAR_CONTEXT_H 1

typedef struct {
	char *namespace;
	efi_guid_t guid;
	char *name;
	uint32_t attr;

	char  *value;
	char  *valuefile;
	int    valuefd;
	size_t value_size;

	efi_time_t timestamp;

	char *importfile;
	int   inmportfd;

	char *exportfile;
	int   exportfd;
	uint8_t to_firmware;

	win_cert_uefi_guid_t *authinfo;

	cms_context *cms_ctx;
} authvar_context;

extern int authvar_context_init(authvar_context *ctx);
extern void authvar_context_fini(authvar_context *ctx);
extern int generate_descriptor(authvar_context *ctx);
extern int write_authvar(authvar_context *ctx);

#endif /* AUTHVAR_CONTEXT_H */
