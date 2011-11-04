/*
 * Copyright 2011 Red Hat, Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
#include <assert.h>

#include "libdpe.h"

static int global_error;

int
pe_errno (void)
{
	int result = global_error;
	global_error = PE_E_NOERROR;
	return result;
}

static const char msgstr[] =
{
#define PE_E_NOERROR_IDX 0
	"no error"
	"\0"
#define PE_E_UNKNOWN_ERROR_IDX \
	(PE_E_NOERROR_IDX + sizeof "no error")
	"unknown error"
	"\0"
#define PE_E_INVALID_OP_IDX \
	(PE_E_UNKNOWN_ERROR_IDX + sizeof "unknown error")
	"invalid operation"
	"\0"
#define PE_E_INVALID_CMD_IDX \
	(PE_E_INVALID_OP_IDX + sizeof "invalid operation")
	"invalid command"
	"\0"
#define PE_E_FD_MISMATCH_IDX \
	(PE_E_INVALID_CMD_IDX + sizeof "invalid command")
	"file descriptor mismatch"
};

static const uint16_t msgidx[PE_E_NUM] =
{
	[PE_E_NOERROR] = PE_E_NOERROR_IDX,
	[PE_E_UNKNOWN_ERROR] = PE_E_UNKNOWN_ERROR_IDX,
	[PE_E_INVALID_OP] = PE_E_INVALID_OP_IDX,
	[PE_E_INVALID_CMD] = PE_E_INVALID_CMD_IDX,
	[PE_E_FD_MISMATCH] = PE_E_FD_MISMATCH_IDX,
};
#define nmsgidx ((int) (sizeof (msgidx) / sizeof (msgidx[0])))

void __libpe_seterrno(int value)
{
	global_error = value >= 0 && value <= nmsgidx
			? value : PE_E_UNKNOWN_ERROR;
}

const char *
pe_errmsg(int error)
{
	int last_error = global_error;

	if (error == 0) {
		assert(msgidx[last_error] < sizeof(msgstr));
		return last_error != 0 ? msgstr + msgidx[last_error] : NULL;
	} else if (error < -1 || error >= nmsgidx) {
		return msgstr + PE_E_UNKNOWN_ERROR_IDX;
	}

	assert (msgidx[error == -1 ? last_error : error] < sizeof (msgstr));
	return msgstr + msgidx[error == -1 ? last_error : error];
}
