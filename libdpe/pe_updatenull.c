/// SPDX-License-Identifier: GPLv2
/*
 * pe_updatenull.c - not implemented, really.
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "libdpe_priv.h"

static int
pe_default_mzhdr(Pe *pe, struct mz_hdr *mzhdr)
{
	/* Always write the mz magic */
	uint16_t mz_magic = cpu_to_le16(MZ_MAGIC);
	update_if_changed(mzhdr->magic, mz_magic, pe->flags);

	/* XXX FIXME: write a real MZ header */
	/* print "the only way to win is not to play" */
	return 0;
}

static int
pe_default_pehdr(Pe *pe, struct pe_hdr *pehdr,
		 size_t shnum UNUSED)
{
	/* Always write the pe magic */
	uint32_t pe_magic = cpu_to_le32(PE_MAGIC);
	update_if_changed(pehdr->magic, pe_magic, pe->flags);

	return 0;
}

off_t
__pe_updatenull(Pe *pe UNUSED,
		       size_t shnum UNUSED)
{
	return 0;
}
