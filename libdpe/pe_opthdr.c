// SPDX-License-Identifier: GPLv2
/*
 * pe_opthdr.c - helpers for the PE optional headers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

void *
pe_getopthdr(Pe *pe)
{
	switch (pe_kind(pe)) {
	case PE_K_PE_EXE:
		return pe->state.pe32_exe.opthdr;
	case PE_K_PE64_EXE:
		return pe->state.pe32plus_exe.opthdr;
	default:
		return NULL;
	}
}

uint32_t
pe_get_file_alignment(Pe *pe)
{
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;

	switch (pe_kind(pe)) {
	case PE_K_PE_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe32opthdr = opthdr;
		return pe32opthdr->file_align;
	}
	case PE_K_PE64_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe64opthdr = opthdr;
		return pe64opthdr->file_align;
		break;
	}
	default:
		break;
	}
	return -1;
}

uint32_t
pe_get_scn_alignment(Pe *pe)
{
	struct pe32_opt_hdr *pe32opthdr = NULL;
	struct pe32plus_opt_hdr *pe64opthdr = NULL;

	switch (pe_kind(pe)) {
	case PE_K_PE_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe32opthdr = opthdr;
		return pe32opthdr->section_align;
	}
	case PE_K_PE64_EXE: {
		void *opthdr = pe_getopthdr(pe);
		pe64opthdr = opthdr;
		return pe64opthdr->section_align;
		break;
	}
	default:
		break;
	}
	return -1;
}

