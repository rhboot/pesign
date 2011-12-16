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

#include "libdpe.h"

static data_dirent *
find_dd_entry(Pe *pe, Pe_DataDir_Type ddt)
{
	struct data_directory *dd = NULL;

	switch (pe->kind) {
	case PE_K_PE_EXE: {
		struct pe32_opt_hdr *opthdr = pe->state.pe32_exe.opthdr;
		if (ddt > le32_to_cpu(opthdr->data_dirs)) {
			__libpe_seterrno(PE_E_INVALID_INDEX);
			return NULL;
		}
		dd = pe->state.pe32_exe.datadir;
		break;
	}
	case PE_K_PE64_EXE: {
		struct pe32plus_opt_hdr *opthdr = pe->state.pe32plus_exe.opthdr;
		if (ddt > le32_to_cpu(opthdr->data_dirs)) {
			__libpe_seterrno(PE_E_INVALID_INDEX);
			return NULL;
		}
		dd = pe->state.pe32plus_exe.datadir;
		break;
	}
	case PE_K_PE_OBJ:
	case PE_K_PE64_OBJ:
	case PE_K_PE_ROM:
	default:
		break;
	}

	if (!dd)
		return NULL;

	switch (ddt) {
	case PE_DATA_DIR_EXPORTS:
		return &dd->exports;
	case PE_DATA_DIR_IMPORTS:
		return &dd->imports;
	case PE_DATA_DIR_RESOURCES:
		return &dd->resources;
	case PE_DATA_DIR_EXCEPTIONS:
		return &dd->exceptions;
	case PE_DATA_DIR_CERTIFICATES:
		return &dd->certs;
	case PE_DATA_DIR_BASE_RELOCATIONS:
		return &dd->base_relocations;
	case PE_DATA_DIR_DEBUG:
		return &dd->debug;
	case PE_DATA_DIR_ARCH:
		return &dd->arch;
	case PE_DATA_DIR_GLOBAL_POINTER:
		return &dd->global_ptr;
	case PE_DATA_TLS:
		return &dd->tls;
	case PE_DATA_LOAD_CONFIG:
		return &dd->load_config;
	case PE_DATA_BOUND_IMPORT:
		return &dd->bound_imports;
	case PE_DATA_IMPORT_ADDRESS:
		return &dd->import_addrs;
	case PE_DATA_DELAY_IMPORTS:
		return &dd->delay_imports;
	case PE_DATA_CLR_RUNTIME_HEADER:
		return &dd->clr_runtime_hdr;
	case PE_DATA_RESERVED:
		return &dd->reserved;
	case PE_DATA_NUM:
	default:
		break;
	}

	return NULL; 
}

int
pe_getdatadir(Pe *pe, Pe_DataDir_Type ddt, void **addr, size_t *size)
{
	data_dirent *dde = NULL;

	if (addr == NULL || size == 0) {
		/* FIXME: is this the right error code? */
		__libpe_seterrno(PE_E_INVALID_OP);
		return -1;
	}

	dde = find_dd_entry(pe, ddt);
	if (!dde) {
		__libpe_seterrno(PE_E_INVALID_INDEX);
		return -1;
	}

	*addr = compute_mem_addr(pe, dde->virtual_address);
	*size = le32_to_cpu(dde->size);
	return 0;
}

#if 0
struct mem_data_directory {
	
}

static int
sort_datadir_by_location(Pe *pe, struct mem_data_directory **mdd)
{

}
#endif

static int
set_datadir_ptr(Pe *pe, Pe_DataDir_Type ddt, void *addr, size_t size)
{
	data_dirent *dde = find_dd_entry(pe, ddt);
	if (!dde) {
		__libpe_seterrno(PE_E_INVALID_INDEX);
		return -1;
	}

	dde->virtual_address = compute_file_addr(pe, addr);
	dde->size = cpu_to_le32(size);
	return 0;
}

static void *
allocate_space(Pe *pe, size_t size)
{
	return NULL;
}

int
pe_setdatadir(Pe *pe, Pe_DataDir_Type ddt, void *addr, size_t size)
{
	void *oldaddr;
	size_t oldsize;

	int rc = pe_getdatadir(pe, ddt, &oldaddr, &oldsize);
	if (rc < 0)
		return rc;
	if (addr == oldaddr) {
		if (size == oldsize) {
			return 0;
		} else if (size <= oldsize) {
			/* XXX FIXME try to reclaim unused space... */
			return 0;
		} else {
			/* you've done something seriously stupid here.*/
			/* XXX FIXME wrong error number */
			__libpe_seterrno(PE_E_NOMEM);
			return -1;
		}
	} else if (addr > oldaddr && (char *)addr < (char *)oldaddr + oldsize) {
		/* you've done something seriously stupid here.*/
		/* XXX FIXME wrong error number */
		__libpe_seterrno(PE_E_NOMEM);
		return -1;
	} else {
		/* XXX FIXME try to reclaim unused space... */
		char *dd_space = NULL;
		if (size && addr) {
			dd_space = allocate_space(pe, size);
			if (!dd_space) {
				__libpe_seterrno(PE_E_NOMEM);
				return -1;
			}
			
			memmove(dd_space, addr, size);
		}

		memset(oldaddr, '\0', oldsize);
		int rc = set_datadir_ptr(pe, ddt, dd_space, size);
		/* XXX FIXME if set_datadir_ptr didn't work, we should maybe
		 * try to free the space we allocated...*/
		return rc;
	}
}
