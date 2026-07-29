// SPDX-License-Identifier: GPLv2
/*
 * pe_getdatadir.c - find the data directory
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

int
pe_getdatadir(Pe *pe, data_directory **ddp)
{
	int rc = -1;
	data_directory *dd = NULL;
	uint64_t dd_pos, dd_size, dd_end;

	if (!pe || !ddp) {
		__libpe_seterrno(PE_E_INVALID_INDEX);
		return rc;
	}

	switch (pe->kind) {
	case PE_K_PE_EXE: {
		dd = pe->state.pe32_exe.datadir;
		rc = 0;
		break;
	}
	case PE_K_PE64_EXE: {
		dd = pe->state.pe32plus_exe.datadir;
		rc = 0;
		break;
	}
	case PE_K_PE_OBJ:
	case PE_K_PE64_OBJ:
	case PE_K_PE_ROM:
	default:
		break;
	}

	if (!dd)
		return rc;

	dd_pos = le32_to_cpu(dd->certs.virtual_address);
	dd_size = le32_to_cpu(dd->certs.size);

	if (__builtin_add_overflow(dd_pos, dd_size, &dd_end) ||
	    dd_pos >= pe->maximum_size ||
	    dd_end > pe->maximum_size) {
		__libpe_seterrno(PE_E_INVALID_FILE);
		rc = -1;
	}

	if (rc >= 0)
		*ddp = dd;

	return rc;
}
