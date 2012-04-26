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
#ifndef AUTHVAR_CONTEXT_H
#define AUTHVAR_CONTEXT_H 1

typedef enum {
	none,
	append,
	clear,
	set
} action_t;

typedef struct {
	action_t action;

	char *name;
	char *importfile;
	char *exportfile;

	cms_context cms_ctx;
} authvar_context;

extern int authvar_context_init(authvar_context *ctx);
extern void authvar_context_fini(authvar_context *ctx);

#endif /* AUTHVAR_CONTEXT_H */
