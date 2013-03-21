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

int
pe_clearcert(Pe *pe)
{
	int rc;
	data_directory *dd = NULL;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return rc;

	if (dd->certs.virtual_address != 0) {
		pe_freespace(pe, dd->certs.virtual_address, dd->certs.size);
		memset(&dd->certs, '\0', sizeof (dd->certs));
	}

	return 0;
}

int
pe_alloccert(Pe *pe, size_t size)
{
	int rc;
	data_directory *dd = NULL;

	pe_clearcert(pe);

	uint32_t new_space = 0;
	rc = pe_allocspace(pe, size, &new_space);
	if (rc < 0)
		return rc;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return rc;
	
	void *addr = compute_mem_addr(pe, new_space);
	/* We leave the whole list empty until finalize...*/
	memset(addr, '\0', size);

	dd->certs.virtual_address = compute_file_addr(pe, addr);
	dd->certs.size += size;

	return 0;
}

int
pe_populatecert(Pe *pe, void *cert, size_t size)
{
	int rc;
	data_directory *dd = NULL;
	rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return rc;

	if (size != dd->certs.size)
		return -1;

	void *addr = compute_mem_addr(pe, dd->certs.virtual_address);
	if (!addr)
		return -1;

	memcpy(addr, cert, size);
	msync(addr, size, MS_SYNC);

	return 0;
}
