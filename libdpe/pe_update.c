// SPDX-License-Identifier: GPLv2
/*
 * pe_update.c - routes to update the PE binary
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static off_t
write_file(Pe *pe, off_t size, size_t shnum)
{
	struct stat st;
	if (fstat(pe->fildes, &st) != 0) {
		__libpe_seterrno(PE_E_WRITE_ERROR);
		return -1;
	}

	if (pe->parent == NULL && (pe->maximum_size == ~((size_t)0) ||
			(size_t)size > pe->maximum_size) &&
			ftruncate(pe->fildes, size) != 0) {
		__libpe_seterrno(PE_E_WRITE_ERROR);
		return -1;
	}

	if (pe->map_address == NULL && pe->cmd == PE_C_WRITE_MMAP) {
		pe->map_address = mmap(NULL, size, PROT_READ|PROT_WRITE,
					MAP_SHARED, pe->fildes, 0);
		if (pe->map_address == MAP_FAILED)
			pe->map_address = NULL;
	}

	if (pe->map_address != NULL) {
		if (__pe_updatemmap(pe, shnum) != 0)
			size = -1;
	} else {
		if (__pe_updatefile(pe, shnum) != 0)
			size = -1;
	}

	if (size != -1 && pe->parent == NULL &&
			pe->maximum_size != ~((size_t)0) &&
			(size_t)size < pe->maximum_size &&
			ftruncate(pe->fildes, size) != 0) {
		__libpe_seterrno(PE_E_WRITE_ERROR);
		size = -1;
	}

	if (size != -1 && (st.st_mode & (S_ISUID | S_ISGID)) &&
			(fchmod(pe->fildes, st.st_mode) != 0)) {
		__libpe_seterrno(PE_E_WRITE_ERROR);
		size = -1;
	}

	if (size != -1 && pe->parent == NULL)
		pe->maximum_size = size;

	return size;
}

loff_t
pe_update(Pe *pe, Pe_Cmd cmd)
{
	if (cmd != PE_C_NULL && cmd != PE_C_WRITE && cmd != PE_C_WRITE_MMAP) {
		__libpe_seterrno(PE_E_INVALID_CMD);
		return -1;
	}

	if (pe == NULL)
		return -1;

	if (pe->kind != PE_K_PE_EXE && pe->kind != PE_K_PE64_EXE &&
			pe->kind != PE_K_PE_OBJ && pe->kind != PE_K_PE64_OBJ &&
			pe->kind != PE_K_PE_ROM) {
		__libpe_seterrno(PE_E_INVALID_HANDLE);
		return -1;
	}

	size_t shnum = (pe->state.pe.scns_last->cnt == 0
		? 0
		: 1 + pe->state.pe.scns_last->data[
					pe->state.pe.scns_last->cnt - 1].index);

	off_t size = __pe_updatenull(pe, shnum);

	if (size != -1 && (cmd == PE_C_WRITE || cmd == PE_C_WRITE_MMAP)) {
		if (pe->cmd != PE_C_RDWR && pe->cmd != PE_C_RDWR_MMAP &&
				pe->cmd != PE_C_WRITE &&
				pe->cmd != PE_C_WRITE_MMAP) {
			__libpe_seterrno(PE_E_UPDATE_RO);
			size = -1;
		} else if (pe->fildes == -1) {
			__libpe_seterrno(PE_E_FD_DISABLED);
			size = -1;
		} else {
			size = write_file(pe, size, shnum);
		}
	}

	return size;
}
