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

#include "authvar.h"

static char *default_namespace="global";

int
authvar_context_init(authvar_context *ctx)
{
	memset(ctx, '\0', sizeof (*ctx));

	ctx->namespace = default_namespace;

	int rc = cms_context_init(&ctx->cms_ctx);

	return rc;
}

void
authvar_context_fini(authvar_context *ctx)
{
	if (!ctx)
		return;

	cms_context_fini(&ctx->cms_ctx);

	memset(ctx, '\0', sizeof (*ctx));
}
