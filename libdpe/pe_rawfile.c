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

char *
pe_rawfile(Pe *pe, size_t *size)
{
	char *result;

	if (pe == NULL) {
		__libpe_seterrno(PE_E_INVALID_HANDLE);
error_out:
		if (size != NULL)
			*size = 0;
		return NULL;
	}

	if (pe->map_address == NULL && __libpe_readall(pe) == NULL)
		goto error_out;

	if (size != NULL)
		*size = pe->maximum_size;

	result = (char *)pe->map_address;

	return result;
}
