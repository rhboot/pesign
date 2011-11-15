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

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "libdpe.h"

static size_t
get_shnum(void *map_address, off_t offset, size_t maxsize)
{
	size_t result = 0;
	void *buf = (void *)map_address + offset;
	struct mz_hdr *mz = (struct mz_hdr *)buf;

	off_t hdr = (off_t)le32_to_cpu(mz->peaddr);
	struct pe_hdr *pe = (struct pe_hdr *)(buf + hdr);

	uint16_t sections = pe->sections;

	result = le16_to_cpu(sections);

	printf("got %ld sections!\n", result);
	return result;
}

static inline Pe *
file_read_pe_obj(int fildes, void *map_address, unsigned char *p_ident,
		off_t offset, size_t maxsize, Pe_Cmd cmd, Pe *parent)
{
	return NULL;
}

static inline Pe *
file_read_pe_exe(int fildes, void *map_address, unsigned char *p_ident,
		off_t offset, size_t maxsize, Pe_Cmd cmd, Pe *parent)
{
	size_t scncnt = get_shnum(map_address, offset, maxsize);
	if (scncnt == (size_t) -1l) {
		/* Could not determine the number of sections. */
		return NULL;
	}

	if (scncnt > SIZE_MAX / sizeof (struct section_header))
		return NULL;

	return NULL;
}

Pe *
__libpe_read_mmapped_file(int fildes, void *map_address, off_t offset,
			size_t maxsize, Pe_Cmd cmd, Pe *parent)
{
	unsigned char *p_ident = (unsigned char *) map_address + offset;

	Pe_Kind kind = determine_kind (p_ident, maxsize);

	switch (kind) {
		case PE_K_PE_OBJ:
		case PE_K_PE64_OBJ:
			return file_read_pe_obj(fildes, map_address, p_ident,
						offset, maxsize, cmd, parent);
		case PE_K_PE64_EXE:
		case PE_K_PE_EXE:
			return file_read_pe_exe(fildes, map_address, p_ident,
						offset, maxsize, cmd, parent);
		default:
			break;
	}

	return allocate_pe(fildes, map_address, offset, maxsize, cmd, parent,
		PE_K_NONE, 0);
}

static Pe *
read_unmmapped_file(int fildes, off_t offset, size_t maxsize, Pe_Cmd cmd,
			Pe *parent)
{
	union {
		struct {
			struct mz_hdr mz;
			struct pe_hdr pe;
		};
		unsigned char raw[1];
	} mem;

	ssize_t nread = pread_retry (fildes, &mem.mz, sizeof(mem.mz), offset);
	if (nread == -1)
		return NULL;

	/* this handles MZ-only binaries wrong, but who cares, really? */
	off_t peaddr = offset + le32_to_cpu(mem.mz.peaddr);
	ssize_t prev_nread = nread;
	nread += pread_retry (fildes, &mem.pe, sizeof(mem.pe), peaddr);
	if (nread == prev_nread)
		return NULL;
	mem.mz.peaddr = cpu_to_le32(offsetof(typeof(mem), pe));

	Pe_Kind kind = determine_kind(&mem, nread);

	switch (kind) {
		case PE_K_PE_OBJ:
			return file_read_pe_obj(fildes, NULL, mem.raw, offset,
						maxsize, cmd, parent);
		case PE_K_PE_EXE:
			return file_read_pe_exe(fildes, NULL, mem.raw, offset,
						maxsize, cmd, parent);
		default:
			break;
	}

	return allocate_pe(fildes, NULL, offset, maxsize, cmd, parent,
				PE_K_NONE, 0);
}

static Pe *
read_file(int fildes, off_t offset, size_t maxsize,
	   Pe_Cmd cmd, Pe *parent)
{
	void *map_address = NULL;
	int use_mmap = (cmd == PE_C_READ_MMAP ||
			cmd == PE_C_RDWR_MMAP ||
			cmd == PE_C_WRITE_MMAP ||
			cmd == PE_C_READ_MMAP_PRIVATE);

	if (use_mmap) {
		if (parent == NULL) {
			if (maxsize == ~((size_t) 0)) {
				struct stat st;

				if (fstat(fildes, &st) == 0 &&
						(sizeof(size_t) >=
							sizeof(st.st_size)||
						st.st_size <= ~((size_t)0)))
					maxsize = (size_t) st.st_size;
			}

			map_address = mmap(NULL, maxsize,
					cmd == PE_C_READ_MMAP
						? PROT_READ
						: PROT_READ|PROT_WRITE,
					cmd == PE_C_READ_MMAP_PRIVATE
						|| cmd == PE_C_READ_MMAP
						? MAP_PRIVATE : MAP_SHARED,
					fildes, offset);
			if (map_address == MAP_FAILED)
				map_address = NULL;
		} else {
			assert (maxsize != ~((size_t)0));

			map_address = parent->map_address;
		}
	}

	if (map_address != NULL) {
		assert(map_address != MAP_FAILED);

		struct Pe *result = __libpe_read_mmapped_file(fildes,
						map_address, offset, maxsize,
						cmd, parent);

		if (result == NULL && (parent == NULL ||
				parent->map_address != map_address))
			munmap(map_address, maxsize);
		else if (parent == NULL)
			result->flags |= PE_F_MMAPPED;

		return result;
	}

	return read_unmmapped_file(fildes, offset, maxsize, cmd, parent);
}

static struct Pe *
write_file (int fd, Pe_Cmd cmd)
{
	return NULL;
}

static Pe *
dup_pe(int fildes, Pe_Cmd cmd, Pe *ref)
{
	if (fildes == -1) {
		fildes = ref->fildes;
	} else if (ref->fildes != -1 && fildes != ref->fildes) {
		__libpe_seterrno(PE_E_FD_MISMATCH);
		return NULL;
	}

	if (ref->cmd != PE_C_READ && ref->cmd != PE_C_READ_MMAP &&
			ref->cmd != PE_C_WRITE && ref->cmd != PE_C_WRITE_MMAP &&
			ref->cmd != PE_C_RDWR && ref->cmd != PE_C_RDWR_MMAP &&
			ref->cmd != PE_C_READ_MMAP_PRIVATE) {
		__libpe_seterrno(PE_E_INVALID_OP);
		return NULL;
	}

	/* for now, just increment the refcount and return the same object */
	ref->ref_count++;

	return ref;
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


