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
#ifndef LIBDPE_COMMON_H
#define LIBDPE_COMMON_H 1

#include <stdlib.h>

#define pwrite_retry(fd, buf,  len, off) \
	TEMP_FAILURE_RETRY (pwrite (fd, buf, len, off))
#define write_retry(fd, buf, n) \
	TEMP_FAILURE_RETRY (write (fd, buf, n))
#define pread_retry(fd, buf,  len, off) \
	TEMP_FAILURE_RETRY (pread (fd, buf, len, off))

static inline Pe_Kind
__attribute__ ((unused))
determine_kind(void *buf, size_t len)
{
	Pe_Kind retval = PE_K_NONE;
	uint16_t mz_magic = MZ_MAGIC;
	struct mz_hdr *mz = (struct mz_hdr *)buf;

	if (cmp_le16(&mz->magic, &mz_magic))
		return retval;
		
	retval = PE_K_MZ;

	off_t hdr = (off_t)le32_to_cpu(mz->peaddr);
	struct pe_hdr *pe = (struct pe_hdr *)(buf + hdr);
	uint32_t pe_magic = PE_MAGIC;

	if (cmp_le32(&pe->magic, &pe_magic))
		return retval;

	retval = PE_K_PE_OBJ;
	if (le32_to_cpu(pe->opt_hdr_size) != 0)
		retval = PE_K_PE_EXE;

	return retval;
}


static inline Pe *
__attribute__ ((unused))
allocate_pe(int fildes, void *map_address, off_t offset, size_t maxsize,
	Pe_Cmd cmd, Pe *parent, Pe_Kind kind, size_t extra)
{
	Pe *result = (Pe *) calloc(1, sizeof (Pe) + extra);
	if (result == NULL) {
		__libpe_seterrno(PE_E_NOMEM);
	} else {
		result->kind = kind;
		result->cmd = cmd;
		result->fildes = fildes;
		result->start_offset = offset;
		result->maximum_size = maxsize;
		result->map_address = map_address;
		result->parent = parent;
	}

	return result;
}

#endif /* LIBDPE_COMMON_H */
