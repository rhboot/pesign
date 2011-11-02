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
#ifndef LIBDPE_PRIV_H
#define LIBDPE_PRIV_H 1

enum {
	PE_E_NOERROR = 0,
	PE_E_UNKNOWN_ERROR,
	PE_E_INVALID_OP,
	PE_E_INVALID_CMD,
	PE_E_FD_MISMATCH,
	PE_E_NUM /* terminating entry */
};

extern void __libpe_seterrno(int value);

struct Pe {
	int fildes;
	Pe_Cmd cmd;
};

struct Pe_Scn {
	
};

#endif /* LIBDPE_PRIV_H */
