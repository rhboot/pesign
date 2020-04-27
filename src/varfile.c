// SPDX-License-Identifier: GPLv2
/*
 * varfile.c - implement storing variables in files
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "authvar.h"

struct variable_operation {
	uint8_t operation;
	efi_guid_t vendor_guid;
	uint32_t attributes;
	uint64_t name_size;
	uint64_t data_size;
	uint16_t *name;
	uint8_t *data;
};

struct variable_file {
	uint8_t magic[8]; /* always "EFIVARS" with a nul */
	uint16_t version;
	uint32_t num_vops;
	struct variable_operation **vops;
};

#define EFIVARS_MAGIC	"EFIVARS"
#define EFIVARS_VERSION	1

static int
vop_valid(struct variable_operation *vop)
{
	efi_guid_t empty_guid = {0,0,0,{0,0,0,0,0,0,0,0}};

	if (!memcmp(&empty_guid, &vop->vendor_guid, sizeof(empty_guid)))
not_ready:
		return 0;

	if (vop->name_size == 0)
		goto not_ready;

	if (vop->data_size == 0)
		goto not_ready;

	if (vop->attributes == 0)
		goto not_ready;

	if (vop->operation == APPEND &&
			!(vop->attributes & EFI_VARIABLE_APPEND_WRITE))
		goto not_ready;

	if (vop->operation != APPEND &&
			(vop->attributes & EFI_VARIABLE_APPEND_WRITE))
		goto not_ready;

	return 1;
}

#if 0
static int
is_ready(variable_file *vf)
{
	if (vf->num_vops == 0)
		return 0;

	for (int i; i < vf->num_vops; i++) {
		struct variable_operation *vop = vf->vops[i];

		if (!vop_valid(vop))
			return 0;

		if (!vop->data || !vop->name)
			return 0;

		if (vop->data[0] == L'\0')
			return 0;
	}
	return 1;
}
#endif

variable_file *
alloc_variable_file(void)
{
	variable_file *vf;

	vf = calloc(1, sizeof(*vf));
	memcpy(vf->magic, EFIVARS_MAGIC, sizeof(EFIVARS_MAGIC));
	vf->version = cpu_to_le16(EFIVARS_VERSION);
	vf->num_vops = 0;

	return 0;
}

int
add_variable_op(variable_file *vf, uint8_t operation, efi_guid_t guid,
	uint16_t *name, uint32_t attributes, uint64_t data_size, uint8_t *data)
{
	struct variable_operation *newvop = NULL, vop = {
		.operation = operation,
		.vendor_guid = guid,
		.attributes = attributes,
		.name_size = ucs2_strlen(name),
		.name = NULL,
		.data_size = data_size,
		.data = NULL,
	};

	if (!vop_valid(&vop))
		return -1;

	vop.name = ucs2_strdup(vop.name);
	if (!vop.name)
		return -1;

	vop.data = malloc(vop.data_size);
	if (!vop.data)
		goto err;

	newvop = malloc(sizeof (vop));
	if (!newvop)
		goto err;

	memcpy(newvop, &vop, sizeof (vop));

	struct variable_operation **vops = NULL;

	vops = realloc(vf->vops, (vf->num_vops + 1) * sizeof (newvop));
	if (!vops)
		goto err;

	vops[vf->num_vops] = newvop;
	vf->vops = vops;
	vf->num_vops++;

	return 0;
err:
	if (vop.name)
		free(vop.name);
	if (vop.data)
		free(vop.data);
	if (newvop)
		free(newvop);
	return -1;
}

int
realize_variable_file(variable_file *vf, void **data, size_t *len)
{
	return -1;
}

void
free_variable_file(variable_file *vf)
{
	for (int i = 0; i < vf->num_vops; i++) {
		struct variable_operation *vop = vf->vops[i];

		if (vop->name)
			free(vop->name);
		if (vop->data)
			free(vop->data);
		free(vop);

		vf->vops[i] = NULL;
	}
	if (vf->num_vops)
		free(vf->vops);
	free(vf);
}
