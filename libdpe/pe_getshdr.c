// SPDX-License-Identifier: GPLv2
/*
 * pe_getshdr - helpers for PE section headers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

struct section_header *
pe_getshdr(Pe_Scn *scn, struct section_header *dst)
{
	struct section_header *result = NULL;

	if (scn == NULL)
		return NULL;

	if (dst == NULL) {
		__libpe_seterrno(PE_E_INVALID_OPERAND);
		return NULL;
	}

	result = memcpy(dst, scn->shdr, sizeof(*dst));

	return result;
}
