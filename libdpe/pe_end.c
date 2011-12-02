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
pe_end(Pe *pe)
{
	Pe *parent = NULL;

	if (pe == NULL) {
		/* This is allowed and is a no-op. */
		return 0;
	}

	rwlock_wrlock(pe->lock);

	if (pe->ref_count != 0 && --pe->ref_count != 0) {
		int result = pe->ref_count;
		return result;
	}

	parent = pe->parent;

	switch (pe->kind) {
	case PE_K_NONE:
	case PE_K_MZ:
		break;
	case PE_K_PE_OBJ:
	case PE_K_PE_EXE:
	case PE_K_PE_ROM:
	case PE_K_PE64_OBJ:
	case PE_K_PE64_EXE:
		{
			Pe_ScnList *list = &pe->state.pe.scns;
			do {
				size_t cnt = list->max;
		
				while (cnt-- > 0) {
					Pe_Scn *scn = &list->data[cnt];
		
					if ((scn->shdr_flags & PE_F_MALLOCED))
						xfree(scn->shdr);
		
					if (scn->data_base != scn->rawdata_base)
						xfree(scn->data_base);
		
					if (pe->map_address == NULL)
						xfree(scn->rawdata_base);
				}
		
				Pe_ScnList *oldp = list;
				list = list->next;
				assert(list == NULL || oldp->cnt == oldp->max);
				if (oldp != &pe->state.pe.scns)
					xfree(oldp);
			} while (list);
		}
		break;
	case PE_K_NUM:
	default:
		break;
	}

	if (pe->map_address != NULL && parent == NULL) {
		if (pe->flags & PE_F_MALLOCED)
			xfree(pe->map_address);
		else if (pe->flags & PE_F_MMAPPED)
			xmunmap(pe->map_address, pe->maximum_size);
	}
	rwlock_fini(pe->lock);
	xfree(pe);

	return (parent != NULL && parent->ref_count ? pe_end(parent) : 0);
}
