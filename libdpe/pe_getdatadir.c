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

int pe_getdatadir(Pe *pe, Pe_DataDir_Type ddt, void **addr, size_t *size)
{
	struct data_directory *dd = NULL;

	switch (pe->kind) {
	case PE_K_PE_EXE: {
		struct pe32_opt_hdr *opthdr = pe->state.pe32_exe.opthdr;
		if (ddt > le32_to_cpu(opthdr->data_dirs)) {
			__libpe_seterrno(PE_E_INVALID_INDEX);
			return -1;
		}
		dd = pe->state.pe32_exe.datadir;
		break;
	}
	case PE_K_PE64_EXE: {
		struct pe32plus_opt_hdr *opthdr = pe->state.pe32plus_exe.opthdr;
		if (ddt > le32_to_cpu(opthdr->data_dirs)) {
			__libpe_seterrno(PE_E_INVALID_INDEX);
			return -1;
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

	if (!dd) {
		/* FIXME: is this the right error code? */
		__libpe_seterrno(PE_E_INVALID_FILE);
		return -1;
	}

	if (addr == NULL || size == NULL) {
		/* FIXME: is this the right error code? */
		__libpe_seterrno(PE_E_INVALID_OP);
		return -1;
	}
	
	switch (ddt) {
	case PE_DATA_DIR_EXPORTS:
		*addr = compute_address(pe, dd->exports.virtual_address);
		*size = le32_to_cpu(dd->exports.size);
		return 0;
	case PE_DATA_DIR_IMPORTS:
		*addr = compute_address(pe, dd->imports.virtual_address);
		*size = le32_to_cpu(dd->imports.size);
		return 0;
	case PE_DATA_DIR_RESOURCES:
		*addr = compute_address(pe, dd->resources.virtual_address);
		*size = le32_to_cpu(dd->resources.size);
		return 0;
	case PE_DATA_DIR_EXCEPTIONS:
		*addr = compute_address(pe, dd->exceptions.virtual_address);
		*size = le32_to_cpu(dd->exceptions.size);
		return 0;
	case PE_DATA_DIR_CERTIFICATES:
		*addr = compute_address(pe, dd->certs.virtual_address);
		*size = le32_to_cpu(dd->certs.size);
		return 0;
	case PE_DATA_DIR_BASE_RELOCATIONS:
		*addr = compute_address(pe, dd->base_relocations.virtual_address);
		*size = le32_to_cpu(dd->base_relocations.size);
		return 0;
	case PE_DATA_DIR_DEBUG:
		*addr = compute_address(pe, dd->debug.virtual_address);
		*size = le32_to_cpu(dd->debug.size);
		return 0;
	case PE_DATA_DIR_ARCH:
		*addr = compute_address(pe, dd->arch.virtual_address);
		*size = le32_to_cpu(dd->arch.size);
		return 0;
	case PE_DATA_DIR_GLOBAL_POINTER:
		*addr = compute_address(pe, dd->global_ptr.virtual_address);
		*size = le32_to_cpu(dd->global_ptr.size);
		return 0;
	case PE_DATA_TLS:
		*addr = compute_address(pe, dd->tls.virtual_address);
		*size = le32_to_cpu(dd->tls.size);
		return 0;
	case PE_DATA_LOAD_CONFIG:
		*addr = compute_address(pe, dd->load_config.virtual_address);
		*size = le32_to_cpu(dd->load_config.size);
		return 0;
	case PE_DATA_BOUND_IMPORT:
		*addr = compute_address(pe, dd->bound_imports.virtual_address);
		*size = le32_to_cpu(dd->bound_imports.size);
		return 0;
	case PE_DATA_IMPORT_ADDRESS:
		*addr = compute_address(pe, dd->import_addrs.virtual_address);
		*size = le32_to_cpu(dd->import_addrs.size);
		return 0;
	case PE_DATA_DELAY_IMPORTS:
		*addr = compute_address(pe, dd->delay_imports.virtual_address);
		*size = le32_to_cpu(dd->delay_imports.size);
		return 0;
	case PE_DATA_CLR_RUNTIME_HEADER:
		*addr = compute_address(pe, dd->clr_runtime_hdr.virtual_address);
		*size = le32_to_cpu(dd->clr_runtime_hdr.size);
		return 0;
	case PE_DATA_RESERVED:
		*addr = compute_address(pe, dd->reserved.virtual_address);
		*size = le32_to_cpu(dd->reserved.size);
		return 0;
	case PE_DATA_NUM:
	default:
		break;
	}

	__libpe_seterrno(PE_E_INVALID_INDEX);
	return -1;
}
