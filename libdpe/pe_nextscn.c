// SPDX-License-Identifier: GPLv2
/*
 * pe_nextscn.c - PE section iteration
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include <assert.h>

#include "libdpe_priv.h"

Pe_Scn *
pe_nextscn(Pe *pe, Pe_Scn *scn)
{
	Pe_Scn *result = NULL;

	if (pe == NULL)
		return NULL;

	if (scn == NULL) {
		if (pe->state.pe.scns.cnt > 0)
			result = &pe->state.pe.scns.data[0];
	} else {
		Pe_ScnList *list = scn->list;

		if (scn + 1 < &list->data[list->cnt]) {
			result = scn + 1;
		} else if (scn + 1 == &list->data[list->max] &&
				(list = list->next) != NULL) {
			assert(list->cnt > 0);
			result = &list->data[0];
		}
	}

	return result;
}
