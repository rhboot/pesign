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

#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

static int
pe_extend_file(Pe *pe, size_t size, uint32_t *new_space, int align)
{
	void *new = NULL;

	if (align)
		align = (pe->maximum_size + size) % align;
	int extra = size + align;

	int rc = ftruncate(pe->fildes, pe->maximum_size + extra);
	if (rc < 0)
		return -1;

	new = mremap(pe->map_address, pe->maximum_size,
		pe->maximum_size + extra, 0);
	if (!new)
		return -1;

	char *addr = compute_mem_addr(pe, pe->maximum_size);
	memset(addr, '\0', extra);

	*new_space = compute_file_addr(pe, addr + align);

	pe->maximum_size = pe->maximum_size + extra;
	ftruncate(pe->fildes, pe->maximum_size);

	return 0;
}

int
pe_allocspace(Pe *pe, size_t size, uint32_t *offset)
{
	int rc;

	/* XXX PJFIX TODO: this should try to find space in the already
	 * mapped regions. */
	rc = pe_extend_file(pe, size, offset, 0);
	if (rc < 0)
		return -1;
	return 0;
}

static int
__attribute__ (( unused ))
pe_shorten_file(Pe *pe, size_t size)
{
	void *new = NULL;

	new = mremap(pe->map_address, pe->maximum_size,
		pe->maximum_size - size, 0);
	if (!new)
		return -1;

	int rc = ftruncate(pe->fildes, pe->maximum_size - size);
	if (rc < 0)
		return -1;
	
	pe->maximum_size -= size;
	return 0;
}

int
pe_freespace(Pe *pe, uint32_t offset, size_t size)
{
	void *addr = compute_mem_addr(pe, offset);
	memset(addr, '\0', size);

	if (offset + size == pe->maximum_size)
		pe_shorten_file(pe, size);

	/* XXX PJFIX TODO: this should actually de-allocate the space when
	 * it isn't at the end of the file, too. */

	return 0;
}
