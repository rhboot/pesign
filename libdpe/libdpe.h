/*
 * Copyright 2011-2012 Red Hat, Inc.
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
#ifndef LIBDPE_PRIV_H
#define LIBDPE_PRIV_H 1

#include <libdpe/libdpe.h>
#include "endian.h"

enum {
	PE_F_DIRTY = 0x1,
	PE_F_MMAPPED = 0x40,
	PE_F_MALLOCED = 0x80,
	PE_F_FILEDATA = 0x100,
};

enum {
	PE_E_NOERROR = 0,
	PE_E_UNKNOWN_ERROR,
	PE_E_INVALID_HANDLE,
	PE_E_NOMEM,
	PE_E_INVALID_FILE,
	PE_E_WRITE_ERROR,
	PE_E_INVALID_INDEX,
	PE_E_INVALID_OP,
	PE_E_INVALID_CMD,
	PE_E_INVALID_OPERAND,
	PE_E_WRONG_ORDER_PEHDR,
	PE_E_FD_DISABLED,
	PE_E_FD_MISMATCH,
	PE_E_UPDATE_RO,
	PE_E_NUM /* terminating entry */
};

extern void __libpe_seterrno(int value);

struct Pe_Scn {
	size_t index;
	struct Pe *pe;
	struct section_header *shdr;
	unsigned int shdr_flags;
	unsigned int flags;

	char *rawdata_base;
	char *data_base;

	struct Pe_ScnList *list;
};

typedef struct Pe_ScnList
{
	unsigned int cnt;
	unsigned int max;
	struct Pe_ScnList *next;
	struct Pe_Scn data[0];
} Pe_ScnList;

struct Pe {
	/* Address to which the file was mapped.  NULL if not mapped. */
	char *map_address;

	Pe *parent;
	Pe *next;

	/* command used to create this object */
	Pe_Cmd cmd;
	Pe_Kind kind;

	int fildes;
	size_t maximum_size;

	int flags;

	int ref_count;

	union {
		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			void *reserved0;
			void *reserved1;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;

			Pe_ScnList scns;
		} pe;

		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			void *reserved0;
			void *reserved1;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;
			
			Pe_ScnList scns;
		} pe32_obj;

		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			void *reserved0;
			void *reserved1;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;
			
			Pe_ScnList scns;
		} pe32_rom;

		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			struct pe32_opt_hdr *opthdr;
			data_directory *datadir;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;
			
			Pe_ScnList scns;
		} pe32_exe;

		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			void *reserved0;
			void *reserved1;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;
			
			Pe_ScnList scns;
		} pe32plus_obj;

		struct {
			struct mz_hdr *mzhdr;
			struct pe_hdr *pehdr;
			struct pe32plus_opt_hdr *opthdr;
			data_directory *datadir;
			struct section_header *shdr;

			Pe_ScnList *scns_last;
			unsigned int scnincr;
			
			Pe_ScnList scns;
		} pe32plus_exe;
	} state;
};

#include "common.h"

extern off_t __pe_updatemmap(Pe *pe, size_t shnum);
extern int __pe_updatefile(Pe *pe, size_t shnum);
extern off_t __pe_updatenull(Pe *pe, size_t shnum);
extern char *__libpe_readall(Pe *pe);

#endif /* LIBDPE_PRIV_H */
