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
