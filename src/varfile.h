// SPDX-License-Identifier: GPLv2
/*
 * varfile.h - types and headers for helpers to store variables in files
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
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
