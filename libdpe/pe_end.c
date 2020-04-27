// SPDX-License-Identifier: GPLv2
/*
 * pe_end.c - save our results and finalize the PE binary
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include <assert.h>

#include "libdpe_priv.h"

int
pe_end(Pe *pe)
{
	Pe *parent = NULL;

	if (pe == NULL) {
		/* This is allowed and is a no-op. */
		return 0;
	}

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
	xfree(pe);

	return (parent != NULL && parent->ref_count ? pe_end(parent) : 0);
}
