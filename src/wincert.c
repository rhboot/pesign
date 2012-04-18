/*
 * Copyright 2011-2012 Red Hat, Inc.
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
generate_cert_list(pesign_context *ctx, void **cert_list,
		size_t *cert_list_size)
{
	struct {
		win_certificate wc;
		char *data[];
	} *cl;

	size_t cl_size = sizeof (win_certificate) + ctx->cms_ctx.signature.len;

	cl = malloc(cl_size);
	if (!cl)
		return -1;

	cl->wc.length = ctx->cms_ctx.signature.len;
	cl->wc.revision = WIN_CERT_REVISION_2_0;
	cl->wc.cert_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
	memcpy(cl->data, ctx->cms_ctx.signature.data, cl->wc.length);

	*cert_list = cl;
	*cert_list_size = cl_size;

	return 0;
}

int
implant_cert_list(pesign_context *ctx, void *cert_list, size_t cert_list_size)
{
	return pe_addcert(ctx->outpe, cert_list, cert_list_size);
}
