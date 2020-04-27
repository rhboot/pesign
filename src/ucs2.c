// SPDX-License-Identifier: GPLv2
/*
 * ucs2.c - helpers for 16-bit unicode chatacters
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
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
