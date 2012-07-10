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

#include <libdpe/pe.h>

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

typedef enum {
	PE_DATA_DIR_EXPORTS = 1,
	PE_DATA_DIR_IMPORTS,
	PE_DATA_DIR_RESOURCES,
	PE_DATA_DIR_EXCEPTIONS,
	PE_DATA_DIR_CERTIFICATES,
	PE_DATA_DIR_BASE_RELOCATIONS,
	PE_DATA_DIR_DEBUG,
	PE_DATA_DIR_ARCH,
	PE_DATA_DIR_GLOBAL_POINTER,
	PE_DATA_TLS,
	PE_DATA_LOAD_CONFIG,
	PE_DATA_BOUND_IMPORT,
	PE_DATA_IMPORT_ADDRESS,
	PE_DATA_DELAY_IMPORTS,
	PE_DATA_CLR_RUNTIME_HEADER,
	PE_DATA_RESERVED,
	PE_DATA_NUM /* last entry */
} Pe_DataDir_Type;

typedef struct Pe Pe;
typedef struct Pe_Scn Pe_Scn;

extern Pe *pe_begin(int fildes, Pe_Cmd cmd, Pe *ref);
extern Pe *pe_clone(Pe *pe, Pe_Cmd cmd);
extern Pe *pe_memory(char *image, size_t size);
extern int pe_end(Pe *pe);
extern loff_t pe_update(Pe *pe, Pe_Cmd cmd);
extern Pe_Kind pe_kind(Pe *Pe) __attribute__ ((__pure__));
extern Pe_Scn *pe_nextscn(Pe *pe, Pe_Scn *scn);
extern Pe_Scn *pe_getscn(Pe *pe, size_t idx);
extern struct section_header *pe_getshdr(Pe_Scn *scn, struct section_header *dst);
extern struct pe_hdr *pe_getpehdr(Pe *pe, struct pe_hdr *pehdr);
extern char *pe_rawfile(Pe *pe, size_t *ptr);
extern int pe_getdatadir(Pe *pe, data_directory **dd);
extern void *pe_getopthdr(Pe *pe);

extern int pe_allocspace(Pe *pe, size_t size, uint32_t *offset);
extern int pe_freespace(Pe *pe, uint32_t offset, size_t size);

extern int pe_clearcert(Pe *pe);
extern int pe_alloccert(Pe *pe, size_t len);
extern int pe_populatecert(Pe *pe, void *cert, size_t len);

extern int pe_errno(void);
extern const char *pe_errmsg(int error);

#endif /* LIBDPE_H */
