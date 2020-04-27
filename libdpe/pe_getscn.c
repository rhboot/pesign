// SPDX-License-Identifier: GPLv2
/*
 * pe_getscn.c - PE section access
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

Pe_Scn *
pe_getscn(Pe *pe, size_t idx)
{
	if (pe == NULL)
		return NULL;

	switch (pe->kind) {
	case PE_K_PE_OBJ:
	case PE_K_PE_EXE:
	case PE_K_PE_ROM:
	case PE_K_PE64_OBJ:
	case PE_K_PE64_EXE:
		break;
	default:
		__libpe_seterrno(PE_E_INVALID_HANDLE);
		return NULL;
	}

	Pe_Scn *result = NULL;

	Pe_ScnList *runp = &pe->state.pe.scns;

	while (1) {
		if (idx < runp->max) {
			if (idx < runp->cnt)
				result = &runp->data[idx];
			else
				__libpe_seterrno(PE_E_INVALID_INDEX);
			break;
		}

		idx -= runp->max;

		runp = runp->next;
		if (runp == NULL) {
			__libpe_seterrno(PE_E_INVALID_INDEX);
			break;
		}
	}

	return result;
}
