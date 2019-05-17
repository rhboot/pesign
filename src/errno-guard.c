/*
 * errno-guard.c
 * Copyright 2019 Peter Jones <pjones@redhat.com>
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>

#include "compiler.h"
#include "errno-guard.h"

__thread int errno_guards_[ERRNO_GUARD_ENTRIES_];
__thread int errno_guard_no_ = -1;

void
clean_up_errno_guard_(int *handle)
{
	if (*handle < 0
	    || *handle >= ERRNO_GUARD_ENTRIES_
	    || *handle > errno_guard_no_)
		return;

	if (errno_guards_[*handle] >= 0) {
		errno = errno_guards_[*handle];
		errno_guard_no_ = *handle - 1;
	}
	*handle = -1;
}

int
set_up_errno_guard_(int *handle)
{
	int guard_var = ++errno_guard_no_;

	if (guard_var < ERRNO_GUARD_ENTRIES_)
		errno_guards_[guard_var] = errno;

	if (handle)
		*handle = guard_var;
	return guard_var;
}

int
override_errno_guard(int *handle, int error)
{
	if (handle == NULL
	    || *handle < 0
	    || *handle >= ERRNO_GUARD_ENTRIES_)
		return -1;

	if (*handle > errno_guard_no_) {
		*handle = -1;
		return -1;
	}

	errno = error;
	errno_guard_no_ = *handle;

	return *handle;
}

// vim:fenc=utf-8:tw=75:noet
