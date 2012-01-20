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

static int
__get_last_datadir(Pe *pe, data_dirent *last_dd)
{
	if (!last_dd)
		return -1;

	for (int x = 0; x < PE_DATA_NUM; x++) {
		void *ddstart;
		size_t ddsize;

		int rc = pe_getdatadir(pe, x, &ddstart, &ddsize);
		if (rc < 0)
			continue;

		if ((uint64_t)ddstart > last_dd->virtual_address) {
			last_dd->virtual_address = (uint64_t)ddstart;
			last_dd->size = ddsize;
		}
	}
	return 0;
}

static struct section_header *
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

	rc = strcmp((*scna)->shdr->name, (*scnb)->shdr->name);
	if (rc != 0)
		return rc;

	if ((*scna)->shdr->virtual_address > (*scnb)->shdr->virtual_address)
		return -1;
	if ((*scnb)->shdr->virtual_address > (*scna)->shdr->virtual_address)
		return 1;

	if ((*scna)->shdr->data_addr > (*scnb)->shdr->data_addr)
		return -1;
	if ((*scnb)->shdr->data_addr > (*scna)->shdr->data_addr)
		return 1;

	if ((*scna)->shdr->virtual_size > (*scnb)->shdr->virtual_size)
		return -1;
	if ((*scnb)->shdr->virtual_size > (*scna)->shdr->virtual_size)
		return 1;

	if ((*scna)->shdr->raw_data_size > (*scnb)->shdr->raw_data_size)
		return -1;
	if ((*scnb)->shdr->raw_data_size > (*scna)->shdr->raw_data_size)
		return 1;

	return 0;
}

static void
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
	
	

	/* it's not dirty any more, so clear the flag. */
	pe->flags &= ~PE_F_DIRTY;

	/* flush back to disk */
	char *msync_start = ((char *) pe->map_address
		+ (pe->start_offset & ~(sysconf(_SC_PAGESIZE) -1 )));

	data_dirent dd = {0, 0};
	__get_last_datadir(pe, &dd);

	struct section_header *sh = __get_last_section(pe);
	assert(dd.virtual_address && sh);

	char *msync_end = (char *) pe->map_address + pe->start_offset;

	if (sh->virtual_address > dd.virtual_address) {
		msync_end += sh->virtual_address + sh->raw_data_size;
	} else {
		msync_end += dd.virtual_address + dd.size;
	}

	msync(msync_start, msync_end - msync_start, MS_SYNC);

	return 0;
}

int
__pe_updatefile(Pe *pe, size_t shnum)
{
	__libpe_seterrno(PE_E_UNKNOWN_ERROR);
	return 1;
}
