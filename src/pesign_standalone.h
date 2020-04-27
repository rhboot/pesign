// SPDX-License-Identifier: GPLv2
/*
 * pesign_standalone.h - decls for the standalone pesign tool
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PESIGN_STANDALONE_H
#define PESIGN_STANDADLONE_H 1

#define NO_FLAGS		0x00
#define GENERATE_DIGEST		0x01
#define GENERATE_SIGNATURE	0x02
#define IMPORT_RAW_SIGNATURE	0x04
#define IMPORT_SIGNATURE	0x08
#define IMPORT_SATTRS		0x10
#define EXPORT_SATTRS		0x20
#define EXPORT_SIGNATURE	0x40
#define REMOVE_SIGNATURE	0x80
#define LIST_SIGNATURES		0x100
#define PRINT_DIGEST		0x200
#define EXPORT_PUBKEY		0x400
#define EXPORT_CERT		0x800
#define DAEMONIZE		0x1000
#define OMIT_VENDOR_CERT	0x2000
#define FLAG_LIST_END		0x4000

void print_flag_name(FILE *f, int flag);
void pe_handle_action(pesign_context *ctxp, int action, int padding);
void kmod_handle_action(pesign_context *ctxp, int action);

#endif /* PESIGN_STANDALONE_H */
