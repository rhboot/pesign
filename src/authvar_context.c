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

#include <unistd.h>
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

int
generate_descriptor(authvar_context *ctx)
{
	win_cert_uefi_guid_t *authinfo;
	SECItem sd_der;
	char *name_ptr;
	uint8_t *buf, *ptr;
	size_t buf_len;
	uint64_t offset;
	efi_char16_t *wptr;
	int rc;

	/* prepare buffer for varname, vendor_guid, attr, timestamp, value */
	buf_len = strlen(ctx->name)*sizeof(efi_char16_t) + sizeof(efi_guid_t) +
		  sizeof(uint32_t) + sizeof(efi_time_t) + ctx->value_size;
	buf = calloc(1, buf_len);
	if (!buf)
		return -1;

	ptr = buf;
	name_ptr = ctx->name;
	while (*name_ptr != '\0') {
		wptr = (efi_char16_t *)ptr;
		*wptr = *name_ptr;
		name_ptr++;
		ptr += sizeof(efi_char16_t);
	}

	memcpy(ptr, &ctx->guid, sizeof(efi_guid_t));
	ptr += sizeof(efi_guid_t);

	memcpy(ptr, &ctx->attr, sizeof(uint32_t));
	ptr += sizeof(uint32_t);

	memcpy(ptr, &ctx->timestamp, sizeof(efi_time_t));
	ptr += sizeof(efi_time_t);

	memcpy(ptr, ctx->value, ctx->value_size);

	ctx->cms_ctx->authbuf_len = buf_len;
	ctx->cms_ctx->authbuf = buf;

	/* XXX set the value to get SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION
	   from digest_get_signature_oid(). */
	ctx->cms_ctx->selected_digest = 0;

	/* sign the digest */
	memset(&sd_der, '\0', sizeof(sd_der));
	rc = generate_authvar_signed_data(ctx->cms_ctx, &sd_der);
	if (rc < 0)
		cmsreterr(-1, ctx->cms_ctx, "could not create signed data");

	offset = (uint64_t) &((win_cert_uefi_guid_t *)0)->data;
	authinfo = calloc(offset + sd_der.len, 1);
	if (!authinfo)
		cmsreterr(-1, ctx->cms_ctx, "could not allocate authinfo");

	authinfo->hdr.length = sd_der.len + (uint32_t)offset;
	authinfo->hdr.revision = WIN_CERT_REVISION_2_0;
	authinfo->hdr.cert_type = WIN_CERT_TYPE_EFI_GUID;
	authinfo->type = (efi_guid_t)EFI_CERT_TYPE_PKCS7_GUID;
	memcpy(&authinfo->data, sd_der.data, sd_der.len);

	ctx->authinfo = authinfo;

	return 0;
}

int
write_authvar(authvar_context *ctx)
{
	efi_var_auth_2_t *descriptor;
	void *buffer, *ptr;
	size_t buf_len, des_len, remain;
	ssize_t wlen;
	off_t offset;

	if (!ctx->authinfo)
		cmsreterr(-1, ctx->cms_ctx, "Not a valid authvar");

	des_len = sizeof(efi_var_auth_2_t) + ctx->authinfo->hdr.length -
		  sizeof(win_cert_uefi_guid_t);
	buf_len = sizeof(ctx->attr) + des_len + ctx->value_size;

	buffer = calloc(buf_len, 1);
	if (!buffer)
		cmsreterr(-1, ctx->cms_ctx, "could not allocate buffer");
	ptr = buffer;

	/* The attribute of the variable */
	memcpy(ptr, &ctx->attr, sizeof(ctx->attr));
	ptr += sizeof(ctx->attr);

	/* EFI_VARIABLE_AUTHENTICATION_2 */
	descriptor = (efi_var_auth_2_t *)ptr;
	memcpy(&descriptor->timestamp, &ctx->timestamp, sizeof(efi_time_t));
	memcpy(&descriptor->authinfo, ctx->authinfo, ctx->authinfo->hdr.length);
	ptr += des_len;

	/* Data */
	if (ctx->value_size > 0)
		memcpy(ptr, ctx->value, ctx->value_size);

	if (!ctx->to_firmware) {
		ftruncate(ctx->exportfd, buf_len);
		lseek(ctx->exportfd, 0, SEEK_SET);
	}

	remain = buf_len;
	offset = 0;
	do {
		wlen = write(ctx->exportfd, buffer + offset, remain);
		if (wlen < 0)
			cmsreterr(-1, ctx->cms_ctx, "failed to write authvar");
		remain -= wlen;
		offset += wlen;
	} while (remain > 0);

	return 0;
}
