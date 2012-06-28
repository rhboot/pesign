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

struct cert_list_entry {
	win_certificate wc;
	uint8_t data[];
};

static int
generate_cert_list(pesign_context *ctx, void **cert_list,
		size_t *cert_list_size)
{
	cms_context *cms = &ctx->cms_ctx;

	size_t cl_size = 0;
	for (int i = 0; i < cms->num_signatures; i++) {
		cl_size += sizeof (win_certificate);
		cl_size += cms->signatures[i]->len;
	}

	uint8_t *data = malloc(cl_size);
	if (!data)
		return -1;

	*cert_list = (void *)data;
	*cert_list_size = cl_size;

	for (int i = 0; i < cms->num_signatures; i++) {
		struct cert_list_entry *cle = (struct cert_list_entry *)data;
		cle->wc.length = cms->signatures[i]->len +
			sizeof (win_certificate);
		cle->wc.revision = WIN_CERT_REVISION_2_0;
		cle->wc.cert_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
		memcpy(&cle->data[0], cms->signatures[i]->data,
					cms->signatures[i]->len);
		data += sizeof (win_certificate) + cms->signatures[i]->len;
	}

	return 0;
}

static int
implant_cert_list(pesign_context *ctx, void *cert_list, size_t cert_list_size)
{
	return pe_addcert(ctx->outpe, cert_list, cert_list_size);
}

int
finalize_signatures(pesign_context *ctx)
{
	void *clist = NULL;
	size_t clist_size = 0;

	if (generate_cert_list(ctx, &clist, &clist_size) < 0)
		return -1;

	if (implant_cert_list(ctx, clist, clist_size) < 0) {
		free(clist);
		return -1;
	}
	return 0;
}
