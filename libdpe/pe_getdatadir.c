// SPDX-License-Identifier: GPLv2
/*
 * pe_getdatadir.c - find the data directory
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

int
pe_getdatadir(Pe *pe, data_directory **dd)
{
	int rc = -1;

	if (!pe || !dd) {
		__libpe_seterrno(PE_E_INVALID_INDEX);
		return rc;
	}

	switch (pe->kind) {
	case PE_K_PE_EXE: {
		*dd = pe->state.pe32_exe.datadir;
		rc = 0;
		break;
	}
	case PE_K_PE64_EXE: {
		*dd = pe->state.pe32plus_exe.datadir;
		rc = 0;
		break;
	}
	case PE_K_PE_OBJ:
	case PE_K_PE64_OBJ:
	case PE_K_PE_ROM:
	default:
		break;
	}

	return rc;
}
