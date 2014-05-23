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
#include "pesign.h"

int
generic_list_signatures(pesign_context *ctx)
{
	return 0;
}

int
list_signatures(pesign_context *ctx)
{
	if (ctx->file_handlers->list_signatures)
		return ctx->file_handlers->list_signatures(ctx);
	else
		return generic_list_signatures(ctx);
}

const file_handlers_t *file_handlers[] = {
	&pe_handlers,
	NULL
};

int
set_up_file_handlers(pesign_context *ctx, void *addr, size_t len)
{
	for (int x = 0; file_handlers[x] != NULL; x++) {
		if (file_handlers[x]->is_valid(addr, len)) {
			ctx->file_handlers = file_handlers[x];
			return 0;
		}
	}
	return -1;
}
