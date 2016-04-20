/*
 * Copyright 2012 Red Hat, Inc.
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

#include "libdpe.h"

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
		 size_t shnum __attribute__((__unused__)))
{
	/* Always write the pe magic */
	uint32_t pe_magic = cpu_to_le32(PE_MAGIC);
	update_if_changed(pehdr->magic, pe_magic, pe->flags);

	return 0;
}


off_t
__pe_updatenull(Pe *pe __attribute__((__unused__)),
		       size_t shnum __attribute__((__unused__)))
{
	return 0;
}
