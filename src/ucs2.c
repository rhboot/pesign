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

#include "fix_coverity.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ucs2.h"

size_t ucs2_strlen(const uint16_t *s)
{
	size_t i;
	for (i = 0; s[i] != L'\0'; i++)
		;
	return i;
}

uint16_t *ucs2_strdup(const uint16_t *s)
{
	size_t len = ucs2_strlen(s);
	uint16_t *ret = calloc(len, sizeof (*ret));

	if (!ret)
		return NULL;

	memcpy(ret, s, len * sizeof (*ret));
	return ret;
}

extern uint16_t *ascii_to_ucs2(const char *s)
{
	uint16_t *ret = NULL;
	size_t size = strlen(s) + 1;

	ret = calloc(2, size);
	if (!ret)
		return NULL;
	for (unsigned int i = 0; i < size; i++)
		ret[i] = s[i];
	return ret;
}
