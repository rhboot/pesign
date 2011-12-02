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

#include <stdio.h>

#include "libdpe.h"

Pe *pe_clone(Pe *pe, Pe_Cmd cmd)
{
	return NULL;
}

Pe *pe_memory(char *image, size_t size)
{
	return NULL;
}

Pe *pe_next(Pe *pe)
{
	return NULL;
}

loff_t pe_update(Pe *pe, Pe_Cmd cmd)
{
	return 0;
}

Pe_Kind pe_kind(Pe *Pe)
{
	return PE_K_NONE;
}

loff_t pe_getbase(Pe *pe)
{
	return 0;
}
