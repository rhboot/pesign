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

#define adjust(x,y) ((x) = (typeof (x))(((uint8_t *)(x)) + (y)))
static void
pe_fix_addresses(Pe *pe, int64_t offset)
{
	pe->map_address += offset;

	adjust(pe->state.pe.mzhdr, offset);
	adjust(pe->state.pe.pehdr, offset);
	adjust(pe->state.pe.reserved0, offset);
	adjust(pe->state.pe.reserved1, offset);
	adjust(pe->state.pe.shdr, offset);
}
#undef adjust

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

	ftruncate(pe->fildes, pe->maximum_size + extra);
	new = mremap(pe->map_address, pe->maximum_size,
		pe->maximum_size + extra, MREMAP_MAYMOVE);
	if (new == MAP_FAILED) {
		__libpe_seterrno (PE_E_NOMEM);
		return -1;
	}
	if (new != pe->map_address)
		pe_fix_addresses(pe, (uint8_t *)new-(uint8_t *)pe->map_address);

	char *addr = compute_mem_addr(pe, pe->maximum_size);
	memset(addr, '\0', extra);

	*new_space = compute_file_addr(pe, addr + align);

	pe->maximum_size = pe->maximum_size + extra;

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
	if (new == MAP_FAILED) {
		__libpe_seterrno (PE_E_NOMEM);
		return -1;
	}

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
