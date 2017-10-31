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

#include "libdpe_priv.h"

struct section_header *
pe_getshdr(Pe_Scn *scn, struct section_header *dst)
{
	struct section_header *result = NULL;

	if (scn == NULL)
		return NULL;

	if (dst == NULL) {
		__libpe_seterrno(PE_E_INVALID_OPERAND);
		return NULL;
	}

	result = memcpy(dst, scn->shdr, sizeof(*dst));

	return result;
}
