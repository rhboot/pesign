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

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

static struct section_header *
__attribute__((unused))
__get_last_section(Pe *pe)
{
	Pe_Scn *scn = NULL;
	Pe_Scn *ret = NULL;

	while ((scn = pe_nextscn(pe, scn)) != NULL) {
		if (!ret) {
			ret = scn;
			continue;
		}

		if (ret->shdr->virtual_address < scn->shdr->virtual_address)
			ret = scn;
	}
	if (ret)
		return ret->shdr;
	
	return NULL;
}

static int
compare_sections (const void *a, const void *b)
{
	const Pe_Scn **scna = (const Pe_Scn **)a;
	const Pe_Scn **scnb = (const Pe_Scn **)b;
	int rc;

	if ((*scna)->shdr->virtual_address > (*scnb)->shdr->virtual_address)
		return 1;
	if ((*scnb)->shdr->virtual_address > (*scna)->shdr->virtual_address)
		return -1;

	if ((*scna)->shdr->data_addr > (*scnb)->shdr->data_addr)
		return 1;
	if ((*scnb)->shdr->data_addr > (*scna)->shdr->data_addr)
		return -1;

	rc = strcmp((*scna)->shdr->name, (*scnb)->shdr->name);
	if (rc != 0)
		return rc;

	if ((*scna)->shdr->virtual_size > (*scnb)->shdr->virtual_size)
		return 1;
	if ((*scnb)->shdr->virtual_size > (*scna)->shdr->virtual_size)
		return -1;

	if ((*scna)->shdr->raw_data_size > (*scnb)->shdr->raw_data_size)
		return 1;
	if ((*scnb)->shdr->raw_data_size > (*scna)->shdr->raw_data_size)
		return -1;

	return 0;
}

static void
__attribute__((unused))
sort_sections (Pe_Scn **scns, Pe_ScnList *list)
{
	Pe_Scn **scnp = scns;
	do {
		for (size_t cnt = 0; cnt < list->cnt; ++cnt)
			*scnp++ = &list->data[cnt];
	} while ((list = list->next) != NULL);

	qsort(scns, scnp-scns, sizeof(*scns), compare_sections);
}

off_t
__pe_updatemmap(Pe *pe, size_t shnum)
{
	/* This needs to write back the whole file:
	 * 1) mz/pe/pe-o headers
	 * 2) section headers and sections
	 * 3) data directory table and data directories
	 *
	 * We also need to check if the signature is valid and if not,
	 * make sure it's not in the data directory.
	 */

	struct mz_hdr *mzhdr = pe->state.pe.mzhdr;
	struct pe_hdr *pehdr = pe->state.pe.pehdr;

	if (pe->flags & PE_F_DIRTY) {
		off_t offset = 0;
		memcpy(pe->map_address + offset, mzhdr, sizeof(*mzhdr));

		offset += le32_to_cpu(mzhdr->peaddr);
		memcpy(pe->map_address + offset, pehdr, sizeof(*pehdr));
	}

	/* it's not dirty any more, so clear the flag. */
	pe->flags &= ~PE_F_DIRTY;

	/* flush back to disk */
	char *msync_start = ((char *) pe->map_address
		+ (~(sysconf(_SC_PAGESIZE) -1 )));

	data_directory *dd = NULL;
	int rc = pe_getdatadir(pe, &dd);
	if (rc < 0) {
		/* XXX set an error here */
		return -1;
	}

	char *msync_end = (char *)dd + sizeof(*dd);
	msync(msync_start, msync_end - msync_start, MS_SYNC);

	#warning this is not done yet.
	//struct section_header *sh = __get_last_section(pe);

	size_t dd_size = sizeof (*dd) / sizeof (dd->exports);
	data_dirent *dde = &dd->exports;
	for (int i = 0; i < dd_size; i++, dde++) {
		if (dde->size != 0) {
			char *addr = compute_mem_addr(pe, dde->virtual_address);
			msync(addr, dde->size, MS_SYNC);
		}
	}

	return 0;
}

int
__pe_updatefile(Pe *pe, size_t shnum)
{
	__libpe_seterrno(PE_E_UNKNOWN_ERROR);
	return 1;
}
