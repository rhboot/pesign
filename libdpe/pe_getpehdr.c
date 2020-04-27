// SPDX-License-Identifier: GPLv2
/*
 * pe_getpehdr - helpers to find the PE file header
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

struct pe_hdr *
pe_getpehdr(Pe *pe, struct pe_hdr *dest)
{
	if (pe == NULL)
		return NULL;
	memcpy(dest, pe->state.pe.pehdr, sizeof(*dest));
	return dest;
}
