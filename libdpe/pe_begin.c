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

#include <stdio.h>

#include <libdpe/libdpe.h>

#include "pe.h"
#include "libdpe.h"

static struct Pe *
read_file (int fildes, off_t offset, size_t maxsize,
	   Pe_Cmd cmd, Pe *parent)
{
	return NULL;
}

static struct Pe *
write_file (int fd, Pe_Cmd cmd)
{
	return NULL;
}

static Pe *
dup_pe(int fildes, Pe_Cmd cmd, Pe *ref)
{
	struct Pe *result = NULL;

	if (fildes == -1) {
		fildes = ref->fildes;
	} else if (ref->fildes != -1 && fildes != ref->fildes) {
		__libpe_seterrno(PE_E_FD_MISMATCH);
		return NULL;
	}

	if (ref->cmd != PE_C_READ && ref->cmd != PE_C_READ_MMAP
			&& ref->cmd != PE_C_WRITE && ref->cmd != PE_C_WRITE_MMAP
			&& ref->cmd != PE_C_RDWR && ref->cmd != PE_C_RDWR_MMAP
			&& ref->cmd != PE_C_READ_MMAP_PRIVATE) {
		__libpe_seterrno(PE_E_INVALID_OP);
		return NULL;
	}

	return result;
}

Pe *
pe_begin(int fildes, Pe_Cmd cmd, Pe *ref)
{
	Pe *retval = NULL;

	switch (cmd) {
		case PE_C_NULL:
			break;

		case PE_C_READ_MMAP_PRIVATE:
			if (ref != NULL && ref->cmd != PE_C_READ_MMAP_PRIVATE) {
				__libpe_seterrno(PE_E_INVALID_CMD);
				break;
			}
			/* fall through */
		case PE_C_READ:
		case PE_C_READ_MMAP:
			if (ref != NULL)
				retval = dup_pe(fildes, cmd, ref);
			else
				retval = read_file(fildes, 0, ~((size_t)0), cmd,
						NULL);
			break;
		case PE_C_RDWR:
		case PE_C_RDWR_MMAP:
			/* XXX PJFIX implement me */
			break;
		case PE_C_WRITE:
		case PE_C_WRITE_MMAP:
			retval = write_file(fildes, cmd);
			break;
		default:
			__libpe_seterrno(PE_E_INVALID_CMD);
			break;
	}
	return retval;
}


