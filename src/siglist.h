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
#ifndef SIGLIST_H
#define SIGLIST_H 1

typedef struct signature_list signature_list;

extern signature_list *signature_list_new(efi_guid_t *SignatureType);
extern int signature_list_add_sig(signature_list *sl, efi_guid_t owner,
			uint8_t *sig, uint32_t sigsize);
extern int signature_list_realize(signature_list *sl,
				void **out, size_t *outsize);
extern void signature_list_free(signature_list *sl);

#endif /* SIGLIST_H */
