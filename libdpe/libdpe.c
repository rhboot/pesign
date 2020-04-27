// SPDX-License-Identifier: GPLv2
/*
 * libdpe.c - miscelanious PE access functions
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include <stdio.h>

#include "libdpe_priv.h"

Pe *pe_clone(Pe *pe UNUSED,
	     Pe_Cmd cmd UNUSED)
{
	return NULL;
}

Pe *pe_memory(char *image UNUSED,
	      size_t size UNUSED)
{
	return NULL;
}

Pe_Kind pe_kind(Pe *pe)
{
	return pe == NULL ? PE_K_NONE : pe->kind;
}
