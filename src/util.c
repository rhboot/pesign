// SPDX-License-Identifier: GPLv2
/*
 * util.c - utility functions and data that can't go in a header
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include <unistd.h>

#include "compiler.h"
#include "util.h"

size_t HIDDEN page_size;

void CONSTRUCTOR
set_up_global_constants(void)
{
	page_size = sysconf(_SC_PAGE_SIZE);
}

// vim:fenc=utf-8:tw=75:noet
