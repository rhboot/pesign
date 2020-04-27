// SPDX-License-Identifier: GPLv2
/*
 * common.h - common types and helpers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef LIBDPE_COMMON_H
#define LIBDPE_COMMON_H 1

#include "fix_coverity.h"

#include <stdlib.h>
#include <sys/mman.h>

#define pwrite_retry(fd, buf,  len, off) \
	TEMP_FAILURE_RETRY (pwrite (fd, buf, len, off))
#define write_retry(fd, buf, n) \
	TEMP_FAILURE_RETRY (write (fd, buf, n))
#define pread_retry(fd, buf,  len, off) \
	TEMP_FAILURE_RETRY (pread (fd, buf, len, off))

#define is_64_bit(pe) ((pe)->flags & IMAGE_FILE_32BIT_MACHINE)

#define xfree(x) ({if (x) { free(x); x = NULL; }})
#define xmunmap(addr, size) ({if (addr) { munmap(addr,size); addr = NULL; }})

#include <stdio.h>

static inline void * UNUSED
compute_mem_addr(Pe *pe, off_t offset)
{
	/* XXX this might not work when we're not mmapped */
	return (char *)pe->map_address + le32_to_cpu(offset);
}

static inline uint32_t UNUSED
compute_file_addr(Pe *pe, void *addr)
{
	/* XXX this might not work when we're not mmapped */
	return cpu_to_le32((char *)addr - ((char *)pe->map_address));
}

static inline size_t UNUSED
get_shnum(void *map_address, size_t maxsize UNUSED)
{
	size_t result = 0;
	void *buf = (void *)map_address;
	struct mz_hdr *mz = (struct mz_hdr *)buf;

	if (mz == NULL)
		return (size_t)-1l;

	off_t hdr = (off_t)le32_to_cpu(mz->peaddr);
	struct pe_hdr *pe = (struct pe_hdr *)(buf + hdr);

	uint16_t sections = pe->sections;

	result = le16_to_cpu(sections);

	return result;
}

static inline Pe_Kind UNUSED
determine_kind(void *buf, size_t len UNUSED)
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

	if (pe->flags & IMAGE_FILE_EXECUTABLE_IMAGE) {
		if (le32_to_cpu(pe->opt_hdr_size) == 0) {
			/* this PE header is invalid, so return PE_K_MZ */
			return retval;
		}

		struct pe32_opt_hdr *peo =
			(struct pe32_opt_hdr *)(buf + hdr + sizeof(*pe));

		/* if we don't have an optional header, fall back to testing
		 * our machine type list... */
		switch (le16_to_cpu(peo->magic)) {
			case PE_OPT_MAGIC_PE32:
				retval = PE_K_PE_EXE;
				break;
			case PE_OPT_MAGIC_PE32_ROM:
				retval = PE_K_PE_ROM;
				break;
			case PE_OPT_MAGIC_PE32PLUS:
				retval = PE_K_PE64_EXE;
				break;
			default:
				/* some magic we don't know?  Guess based on
				 * machine type */
				retval = is_64_bit(pe)
					? PE_K_PE64_EXE : PE_K_PE_EXE;
				break;
		}
	} else {
		/* this is an object file */
		retval = is_64_bit(pe) ? PE_K_PE64_OBJ : PE_K_PE_OBJ;
	}

	return retval;
}

#undef choose_kind
#undef is_64_bit

static inline Pe * UNUSED
allocate_pe(int fildes, void *map_address, size_t maxsize,
	Pe_Cmd cmd, Pe *parent, Pe_Kind kind, size_t extra)
{
	Pe *result = (Pe *) calloc(1, sizeof (Pe) + extra);
	if (result == NULL) {
		__libpe_seterrno(PE_E_NOMEM);
	} else {
		result->kind = kind;
		result->ref_count = 1;
		result->cmd = cmd;
		result->fildes = fildes;
		result->maximum_size = maxsize;
		result->map_address = map_address;
		result->parent = parent;
	}

	return result;
}

/* We often have to update a flag iff a value changed.  Make this
 * convenient.  */
#define update_if_changed(var, exp, flag)				\
	({								\
		__typeof__ (var) *_var = &(var);			\
		__typeof__ (exp) _exp = (exp);				\
		if (*_var != _exp) {					\
			*_var = _exp;					\
			(flag) |= PE_F_DIRTY;				\
		}							\
	})

#endif /* LIBDPE_COMMON_H */
