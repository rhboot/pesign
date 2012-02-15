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
pe_nextscn(Pe *pe, Pe_Scn *scn)
{
	Pe_Scn *result = NULL;

	if (pe == NULL)
		return NULL;

	rwlock_rdlock(pe->lock);

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

	rwlock_unlock(pe->lock);

	return result;
}
