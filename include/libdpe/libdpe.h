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
#ifndef LIBDPE_H
#define LIBDPE_H 1

#include <sys/types.h>

typedef enum {
	PE_K_NONE,
	PE_K_MZ,
	PE_K_PE_OBJ,
	PE_K_PE_EXE,
	PE_K_PE_ROM,
	PE_K_PE64_OBJ,
	PE_K_PE64_EXE,
	PE_K_NUM /* terminating entry */
} Pe_Kind;

typedef enum {
	PE_C_NULL,
	PE_C_READ,
	PE_C_RDWR,
	PE_C_WRITE,
	PE_C_CLR,
	PE_C_SET,
	PE_C_FDDONE,
	PE_C_FDREAD,
	PE_C_READ_MMAP,
	PE_C_RDWR_MMAP,
	PE_C_WRITE_MMAP,
	PE_C_READ_MMAP_PRIVATE,
	PE_C_EMPTY,
	PE_C_NUM /* last entry */
} Pe_Cmd;

typedef struct Pe Pe;
typedef struct Pe_Scn Pe_Scn;

extern Pe *pe_begin(int fildes, Pe_Cmd cmd, Pe *ref);
extern Pe *pe_clone(Pe *pe, Pe_Cmd cmd);
extern Pe *pe_memory(char *image, size_t size);
extern Pe *pe_next(Pe *pe);
extern int pe_end(Pe *pe);
extern loff_t pe_update(Pe *pe, Pe_Cmd cmd);
extern Pe_Kind pe_kind(Pe *Pe) __attribute__ ((__pure__));
extern off_t pe_getbase(Pe *pe);

extern int pe_errno(void);
extern const char *pe_errmsg(int error);

#endif /* LIBDPE_H */
