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

#include "libdpe.h"

int
pe_getdatadir(Pe *pe, data_directory **dd)
{
	int rc = -1;

	if (!dd) {
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
