// SPDX-License-Identifier: GPLv2
/*
 * pe_allocspace.c - allocate space in the PE binary
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

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

	size_t scncnt = get_shnum(pe->map_address, pe->maximum_size);
	/* in general this means we couldn't identify any sections, so
	 * they must not need to be fixed up. */
	if (scncnt == (size_t)-1l)
		return;

	for (size_t cnt = 0; cnt < scncnt; cnt++) {
		pe->state.pe.scns.data[cnt].shdr =
			&pe->state.pe.shdr[cnt];

		adjust(pe->state.pe.scns.data[cnt].rawdata_base, offset);
		adjust(pe->state.pe.scns.data[cnt].data_base, offset);
	}
}
#undef adjust

#define align(val, align) (((val) + (align) -1 ) & (- (align)))

int
pe_set_image_size(Pe *pe)
{
	if (!pe) {
		errno = EINVAL;
		return -1;
	}

	uint32_t image_size = 0;
	struct pe_hdr *pehdr = pe->state.pe.pehdr;
	struct pe32plus_opt_hdr *opthdr = pe->state.pe32plus_exe.opthdr;

	Pe_Scn *scn = NULL;
	struct section_header shdr = { "", 0, }, tmp_shdr;
	if (pehdr->sections < 1)
		return -1;

	for (int i = 0; i < pehdr->sections; i++) {
		scn = pe_nextscn(pe, scn);
		if (scn == NULL)
			break;
		pe_getshdr(scn, &tmp_shdr);
		if (tmp_shdr.virtual_size > 0)
			memcpy (&shdr, &tmp_shdr, sizeof(shdr));
	}

	int falign = pe_get_file_alignment(pe);
	int salign = pe_get_scn_alignment(pe);
	image_size = shdr.virtual_address - opthdr->image_base +
		align(align(shdr.virtual_size, falign), salign);

	pe->state.pe32plus_exe.opthdr->image_size = image_size;
	return 0;
}

int
pe_extend_file(Pe *pe, size_t size, uint32_t *new_space, int align)
{
	if (!pe) {
		errno = EINVAL;
		return -1;
	}

	void *new = NULL;

	if (align)
		align = ALIGNMENT_PADDING(pe->maximum_size, align);
	int extra = size + align;

	int rc = ftruncate(pe->fildes, pe->maximum_size + extra);
	if (rc < 0)
		return -1;

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
pe_shorten_file(Pe *pe, size_t size)
{
	void *new = NULL;

	if (!pe) {
		errno = EINVAL;
		return -1;
	}
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
	if (!pe) {
		errno = EINVAL;
		return -1;
	}

	void *addr = compute_mem_addr(pe, offset);
	memset(addr, '\0', size);

	if (offset + size == pe->maximum_size)
		pe_shorten_file(pe, size);

	/* XXX PJFIX TODO: this should actually de-allocate the space, *if*
	 * it's the certificate list, when it isn't at the end of the file,
	 * too. */

	return 0;
}
