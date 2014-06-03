/*
 * Copyright 2014 Red Hat, Inc.
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
#ifndef PESIGN_FILE_HANDLERS_H
#define PESIGN_FILE_HANDLERS_H

#include "pesign.h"

typedef struct {
	int (*is_valid)(void *addr, size_t len);
	void (*setup)(pesign_context *ctx, void *addr, size_t len);
	void (*teardown)(pesign_context *ctx);
	int (*list_signatures)(pesign_context *ctx);
	void (*allocate_signature_space)(pesign_context *ctx, ssize_t space);
	void (*assert_signature_space)(pesign_context *ctx);
} file_handlers_t;

extern int set_up_file_handlers(pesign_context *ctx, void *addr, size_t len);
extern int list_signatures(pesign_context *ctx);
extern void allocate_signature_space(pesign_context *ctx, ssize_t space);
extern void assert_signature_space(pesign_context *ctx);

#endif /* PESIGN_FILE_HANDLERS_H */
