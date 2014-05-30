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

#include <sys/mman.h>

#include <prerror.h>
#include <nss.h>
#include <pk11pub.h>
#include <secport.h>
#include <secerr.h>

#include "authvar.h"

static char *default_namespace="global";

int
authvar_context_init(authvar_context *ctx)
{
	memset(ctx, '\0', sizeof (*ctx));

	ctx->namespace = default_namespace;

	int rc = cms_context_alloc(&ctx->cms_ctx);
	ctx->attr = EFI_VARIABLE_NON_VOLATILE |
		    EFI_VARIABLE_RUNTIME_ACCESS |
		    EFI_VARIABLE_BOOTSERVICE_ACCESS |
		    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
	ctx->exportfd = -1;

	return rc;
}

void
authvar_context_fini(authvar_context *ctx)
{
	if (!ctx)
		return;

	cms_context_fini(ctx->cms_ctx);

	if (ctx->name) {
		xfree(ctx->name);
	}

	if (ctx->valuefile) {
		munmap(ctx->value, ctx->value_size);
		ctx->value = NULL;

		close(ctx->valuefd);
		ctx->valuefd = -1;
		ctx->value_size = 0;

		xfree(ctx->valuefile);
		ctx->valuefile = NULL;
	} else if (ctx->value) {
		xfree(ctx->value);
		ctx->value = NULL;
		ctx->value_size = 0;
	}

	if (ctx->exportfd >= 0) {
		close(ctx->exportfd);
		ctx->exportfd = -1;
	}
}

static SECItem*
generate_buffer_digest(cms_context *cms, uint8_t *buf, size_t buf_len)
{
	PK11Context *pk11ctx = NULL;
	SECItem *digest = NULL;

	pk11ctx = PK11_CreateDigestContext(SEC_OID_SHA256);
	if (!pk11ctx) {
		cms->log(cms, LOG_ERR, "%s:%s:%d could not create "
			"digest context: %s",
			__FILE__, __func__, __LINE__,
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	PK11_DigestBegin(pk11ctx);
	PK11_DigestOp(pk11ctx, buf, buf_len);

	digest = PORT_ArenaZAlloc(cms->arena, sizeof (SECItem));
	if (!digest) {
		cms->log(cms, LOG_ERR, "%s:%s:%d could not allocate "
			"memory: %s", __FILE__, __func__, __LINE__,
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	digest->type = siBuffer;
	digest->len = 32;
	digest->data = PORT_ArenaZAlloc(cms->arena, 32);
	if (!digest->data) {
		cms->log(cms, LOG_ERR, "%s:%s:%d could not allocate "
			"memory: %s", __FILE__, __func__, __LINE__,
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	PK11_DigestFinal(pk11ctx, digest->data, &digest->len, 32);
	PK11_Finalize(pk11ctx);
	PK11_DestroyContext(pk11ctx, PR_TRUE);

err:
	return digest;
}

int
generate_descriptor(authvar_context *ctx)
{
	win_cert_uefi_guid_t *authinfo;
	SECItem *digest;
	char *name_ptr;
	uint8_t *buf, *ptr;
	size_t buf_len;

	/* prepare buffer for varname, vendor_guid, attr, timestamp, value */
	buf_len = strlen(ctx->name)*2 + sizeof(efi_guid_t) + sizeof(uint32_t) +
		  sizeof(efi_time_t) + ctx->value_size;
	buf = calloc(1, buf_len);
	if (!buf)
		return -1;

	ptr = buf;
	name_ptr = ctx->name;
	while (*name_ptr != '\0') {
		ptr++;
		*ptr = *name_ptr;
		name_ptr++;
	}
	ptr++;

	memcpy(ptr, &ctx->guid, sizeof(efi_guid_t));
	ptr += sizeof(efi_guid_t);

	memcpy(ptr, &ctx->attr, sizeof(uint32_t));
	ptr += sizeof(uint32_t);

	memcpy(ptr, &ctx->timestamp, sizeof(efi_time_t));
	ptr += sizeof(efi_time_t);

	memcpy(ptr, ctx->value, ctx->value_size);

	digest = generate_buffer_digest(ctx->cms_ctx, buf, buf_len);
	if (!digest || !digest->data) {
		xfree(buf);
		return -1;
	}

	/* TODO sign the digest */

	// TODO complete authinfo
	authinfo = &ctx->des.authinfo;
	//authinfo->hdr.length
	authinfo->hdr.revision = WIN_CERT_REVISION_2_0;
	authinfo->hdr.cert_type = WIN_CERT_TYPE_EFI_GUID;
	authinfo->type = (efi_guid_t)EFI_CERT_TYPE_PKCS7_GUID;
	// TODO append the signed data to authinfo->data


	return 0;
}

int
write_authvar(authvar_context *ctx)
{
	return 0;
}
