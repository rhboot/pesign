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

#include "libdpe_priv.h"

Pe *pe_clone(Pe *pe __attribute__((__unused__)),
	     Pe_Cmd cmd __attribute__((__unused__)))
{
	return NULL;
}

Pe *pe_memory(char *image __attribute__((__unused__)),
	      size_t size __attribute__((__unused__)))
{
	return NULL;
}

Pe_Kind pe_kind(Pe *pe)
{
	return pe == NULL ? PE_K_NONE : pe->kind;
}
