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
#ifndef VARFILE_H
#define VARFILE_H 1

enum {
	CREATE,
	APPEND,
	DELETE
};

typedef struct variable_file variable_file;

extern int add_variable_op(variable_file *vf, uint8_t operation,
	efi_guid_t guid, uint16_t *name, uint32_t attributes,
	uint64_t data_size, uint8_t *data);
extern variable_file *alloc_variable_file(void);
extern int realize_variable_file(variable_file *, void **data, size_t *len);
extern void free_variable_file(variable_file *vf);

#endif /* VARFILE_H */
