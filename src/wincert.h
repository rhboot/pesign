/*
 * Copyright 2011 Red Hat, Inc.
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
#ifndef PESIGN_WINCERT_H
#define PESIGN_WINCERT_H 1

#include "efitypes.h"

#define WIN_CERT_TYPE_PKCS_SIGNED_DATA	0x0002
#define WIN_CERT_TYPE_EFI_PKCS115	0x0EF0
#define WIN_CERT_TYPE_EFI_GUID		0x0EF1

#define WIN_CERT_REVISION_1_0	0x0100
#define WIN_CERT_REVISION_2_0	0x0200

typedef struct win_certificate {
	uint32_t length;
	uint16_t revision;
	uint16_t cert_type;
} win_certificate;

typedef struct cert_iter {
	Pe *pe;
	off_t n;
	void *certs;
	size_t size;
} cert_iter;

typedef struct {
	win_certificate	hdr;
	efi_guid_t	type;
	uint8_t		data[1];
} win_cert_uefi_guid_t;

typedef struct {
	efi_time_t		timestamp;
	win_cert_uefi_guid_t	authinfo;
} efi_var_auth_2_t;

extern int cert_iter_init(cert_iter *iter, Pe *pe);
extern int next_cert(cert_iter *iter, void **cert, ssize_t *cert_size);
extern ssize_t available_cert_space(Pe *pe);
extern ssize_t calculate_signature_space(cms_context *cms, Pe *pe);
extern int parse_signatures(SECItem ***sigs, int *num_sigs, Pe *pe);
extern int finalize_signatures(SECItem **sigs, int num_sigs, Pe *pe);
extern size_t get_reserved_sig_space(cms_context *cms, Pe *pe);
extern ssize_t get_sigspace_extend_amount(cms_context *cms, Pe *pe, SECItem *sig);

#define ALIGNMENT_PADDING(address, align) ((align - (address % align)) % align)

#endif /* PESIGN_WINCERT_H */
