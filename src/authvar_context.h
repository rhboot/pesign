// SPDX-License-Identifier: GPLv2
/*
 * authvar_context.h - context setup and teardown for authvar
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef AUTHVAR_CONTEXT_H
#define AUTHVAR_CONTEXT_H 1

typedef struct {
	char *namespace;
	efi_guid_t guid;
	char *name;
	uint32_t attr;

	char  *value;
	char  *valuefile;
	int    valuefd;
	size_t value_size;

	efi_time_t timestamp;

	char *importfile;
	int   inmportfd;

	char *exportfile;
	int   exportfd;
	uint8_t to_firmware;

	win_cert_uefi_guid_t *authinfo;

	cms_context *cms_ctx;
} authvar_context;

extern int authvar_context_init(authvar_context *ctx);
extern void authvar_context_fini(authvar_context *ctx);
extern int generate_descriptor(authvar_context *ctx);
extern int write_authvar(authvar_context *ctx);

#endif /* AUTHVAR_CONTEXT_H */
