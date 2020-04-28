// SPDX-License-Identifier: GPLv2
/*
 * cms_pe_common.c - common decls for the PE CMS implementation
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "pesign.h"

#include <prerror.h>
#include <nss.h>
#include <secport.h>
#include <secpkcs7.h>
#include <secder.h>
#include <keyhi.h>
#include <base64.h>
#include <pk11pub.h>
#include <secerr.h>
#include <certt.h>

static int
check_pointer_and_size(Pe *pe, void *ptr, size_t size)
{
	void *map = NULL;
	size_t map_size = 0;

	map = pe_rawfile(pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	if ((uintptr_t)ptr < (uintptr_t)map)
		return 0;

	if ((uintptr_t)ptr + size > (uintptr_t)map + map_size)
		return 0;

	if (ptr <= map && size >= map_size)
		return 0;

	return 1;
}

static void *
get_strtab(Pe *pe)
{
	static void *ret = NULL;
	uint32_t *ptr;
	intptr_t intret = 0;
	struct pe_hdr pehdr;
	void *map = NULL;
	size_t map_size = 0;

	if (ret)
		return ret;

	if (pe_getpehdr(pe, &pehdr) == NULL)
		pereterr(NULL, "invalid PE file header");

	map = pe_rawfile(pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	if (pehdr.symbol_table == 0)
		return NULL;

	intret = (intptr_t)pehdr.symbol_table;
	intret += pehdr.symbols * sizeof(struct pe_symtab_entry);

	ptr = (uint32_t *)((intptr_t)map + intret);
	if (!check_pointer_and_size(pe, ptr, 4))
		pereterr(NULL, "invalid string table start");

	if (!check_pointer_and_size(pe, ptr, *ptr))
		pereterr(NULL, "invalid string table size");
	ret = ptr;
	return ret;
}

static char *
get_str(Pe *pe, char *strnum)
{
	size_t sz;
	unsigned long num;
	char *strtab;
	uint32_t strtabsz;

	/* no idea what the real max size for these is, so... we're not going
	 * to have 4B strings, and this can't be the end of the binary, so
	 * this is big enough. */
	sz = strnlen(strnum, 11);
	if (sz == 11)
		return NULL;

	errno = 0;
	num = strtoul(strnum, NULL, 10);
	if (errno != 0)
		return NULL;

	strtab = get_strtab(pe);
	if (!strtab)
		return NULL;

	strtabsz = *(uint32_t *)strtab;
	if (num >= strtabsz)
		return NULL;

	if (strnlen(&strtab[num], strtabsz - num) > strtabsz - num - 1)
		return NULL;

	return &strtab[num];
}

int
generate_digest(cms_context *cms, Pe *pe, int padded)
{
	void *hash_base;
	size_t hash_size;
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;
	unsigned long hashed_bytes = 0;
	void *opthdr;
	int rc = -1;

	if (!pe) {
		cms->log(cms, LOG_ERR, "no output pe ready");
		return -1;
	}

	rc = generate_digest_begin(cms);
	if (rc < 0)
		return rc;

	struct pe_hdr pehdr;
	if (pe_getpehdr(pe, &pehdr) == NULL)
		pereterr(-1, "invalid PE file header");

	void *map = NULL;
	size_t map_size = 0;

	/* 1. Load the image header into memory - should be done
	 * 2. Initialize SHA hash context. */
	map = pe_rawfile(pe, &map_size);
	if (!map)
		pereterr(-1, "could not get raw output file address");

	/* 3. Calculate the distance from the base of the image header to the
	 * image checksum.
	 * 4. Hash the image header from start to the beginning of the
	 * checksum. */
	hash_base = map;

	opthdr = pe_getopthdr(pe);
	if (opthdr == NULL) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE header is invalid", __FILE__, __func__, __LINE__);
		goto error;
	}

	switch (pe_kind(pe)) {
	case PE_K_PE_EXE: {
		pe32opthdr = opthdr;
		hash_size = (uintptr_t)&pe32opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	case PE_K_PE64_EXE: {
		pe64opthdr = opthdr;
		hash_size = (uintptr_t)&pe64opthdr->csum - (uintptr_t)hash_base;
		break;
	}
	default:
		goto error;
	}
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE header is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}
	dprintf("beginning of hash\n");
	dprintf("digesting %lx + %lx\n", hash_base - map, hash_size);
	generate_digest_step(cms, hash_base, hash_size);

	/* 5. Skip over the image checksum
	 * 6. Get the address of the beginning of the cert dir entry
	 * 7. Hash from the end of the csum to the start of the cert dirent. */
	hash_base += hash_size;
	hash_base += pe32opthdr ? sizeof(pe32opthdr->csum)
				: sizeof(pe64opthdr->csum);
	data_directory *dd;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0 || !dd || !check_pointer_and_size(pe, dd, sizeof(*dd))) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE data directory is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}

	hash_size = (uintptr_t)&dd->certs - (uintptr_t)hash_base;
	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE data directory is invalid",
			__FILE__, __func__, __LINE__);
		goto error;
	}
	generate_digest_step(cms, hash_base, hash_size);
	dprintf("digesting %lx + %lx\n", hash_base - map, hash_size);

	/* 8. Skip over the crt dir
	 * 9. Hash everything up to the end of the image header. */
	hash_base = &dd->base_relocations;
	hash_size = (pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size) -
		((uintptr_t)&dd->base_relocations - (uintptr_t)map);

	if (!check_pointer_and_size(pe, hash_base, hash_size)) {
		cms->log(cms, LOG_ERR, "%s:%s:%d PE relocations table is "
			"invalid", __FILE__, __func__, __LINE__);
		goto error;
	}
	generate_digest_step(cms, hash_base, hash_size);
	dprintf("digesting %lx + %lx\n", hash_base - map, hash_size);

	/* 10. Set SUM_OF_BYTES_HASHED to the size of the header. */
	hashed_bytes = pe32opthdr ? pe32opthdr->header_size
				: pe64opthdr->header_size;

	struct section_header *shdrs = calloc(pehdr.sections, sizeof (*shdrs));
	if (!shdrs)
		goto error;
	Pe_Scn *scn = NULL;
	for (int i = 0; i < pehdr.sections; i++) {
		scn = pe_nextscn(pe, scn);
		if (scn == NULL)
			break;
		pe_getshdr(scn, &shdrs[i]);
	}
	sort_shdrs(shdrs, pehdr.sections - 1);

	for (int i = 0; i < pehdr.sections; i++) {
		if (shdrs[i].raw_data_size == 0)
			continue;

		hash_base = (void *)((uintptr_t)map + shdrs[i].data_addr);
		hash_size = shdrs[i].raw_data_size;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			cms->log(cms, LOG_ERR, "%s:%s:%d PE section \"%s\" "
				"has invalid address",
				__FILE__, __func__, __LINE__, shdrs[i].name);
			goto error_shdrs;
		}

		if (cms->omit_vendor_cert) {
			char *name = shdrs[i].name;
			if (name && name[0] == '/')
				name = get_str(pe, name + 1);
			dprintf("section:\"%s\"\n", name);
			if (name && !strcmp(name, ".vendor_cert")) {
				dprintf("skipping .vendor_cert section\n");
				hashed_bytes += hash_size;
				continue;
			}
		}

		generate_digest_step(cms, hash_base, hash_size);
		dprintf("digesting %lx + %lx\n", hash_base - map, hash_size);

		hashed_bytes += hash_size;
	}

	if (map_size > hashed_bytes) {
		hash_base = (void *)((uintptr_t)map + hashed_bytes);
		hash_size = map_size - dd->certs.size - hashed_bytes;

		if (!check_pointer_and_size(pe, hash_base, hash_size)) {
			cms->log(cms, LOG_ERR, "%s:%s:%d PE has invalid "
				"trailing data", __FILE__, __func__, __LINE__);
			goto error_shdrs;
		}
		if (hash_size % 8 != 0 && padded) {
			size_t tmp_size = hash_size +
					  ALIGNMENT_PADDING(hash_size, 8);
			uint8_t tmp_array[tmp_size];
			memset(tmp_array, '\0', tmp_size);
			memcpy(tmp_array, hash_base, hash_size);
			generate_digest_step(cms, tmp_array, tmp_size);
			dprintf("digesting %lx + %lx\n", (unsigned long)tmp_array, tmp_size);
		} else {
			generate_digest_step(cms, hash_base, hash_size);
			dprintf("digesting %lx + %lx\n", hash_base - map, hash_size);
		}
	}
	dprintf("end of hash\n");

	rc = generate_digest_finish(cms);
	if (rc < 0)
		goto error_shdrs;

	if (shdrs) {
		free(shdrs);
		shdrs = NULL;
	}

	return 0;

error_shdrs:
	if (shdrs)
		free(shdrs);
error:
	return -1;
}

/* vim:fenc=utf-8:sw=8:sts=8:noet */
