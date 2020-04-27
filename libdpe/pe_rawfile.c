// SPDX-License-Identifier: GPLv2
/*
 * pe_rawfile.c - I really don't remember.
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

char *
pe_rawfile(Pe *pe, size_t *size)
{
	char *result;

	if (pe == NULL) {
		__libpe_seterrno(PE_E_INVALID_HANDLE);
error_out:
		if (size != NULL)
			*size = 0;
		return NULL;
	}

	if (pe->map_address == NULL && __libpe_readall(pe) == NULL)
		goto error_out;

	if (size != NULL)
		*size = pe->maximum_size;

	result = (char *)pe->map_address;

	return result;
}
