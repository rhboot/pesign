/*
 * Copyright 2012 Red Hat, Inc.
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

static struct pe_hdr *
__pe_getpehdr_rdlock(Pe *pe, struct pe_hdr *dest)
{
	struct pe_hdr *result = NULL;

	if (!pe)
		return NULL;

	if (pe->state.pe.pehdr == NULL) {
		__libpe_seterrno(PE_E_WRONG_ORDER_PEHDR);
	} else {
		memcpy(dest, pe->state.pe.pehdr, sizeof(*dest));
		result = dest;
	}
	return result;
}

struct pe_hdr *
pe_getpehdr(Pe *pe, struct pe_hdr *dest)
{
	struct pe_hdr *result;

	if (pe == NULL)
		return NULL;

	rwlock_rdlock(pe->lock);
	result = __pe_getpehdr_rdlock(pe, dest);
	rwlock_unlock(pe->lock);

	return result;
}
