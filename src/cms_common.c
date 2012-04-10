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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pesign.h"

#include <nspr4/prerror.h>

#include <nss3/nss.h>
#include <nss3/secport.h>
#include <nss3/secpkcs7.h>
#include <nss3/secder.h>
#include <nss3/base64.h>
#include <nss3/pk11pub.h>
#include <nss3/secerr.h>

int
cms_context_init(cms_context *ctx)
{
	SECStatus status;
	
	status = NSS_InitReadWrite("/etc/pki/pesign");
	if (status != SECSuccess)
		return -1;

	status = register_oids();
	if (status != SECSuccess)
		return -1;

	ctx->arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!ctx->arena) {
		fprintf(stderr, "Could not create cryptographic arena: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

void
cms_context_fini(cms_context *ctx)
{
	if (ctx->cert) {
		CERT_DestroyCertificate(ctx->cert);
		ctx->cert = NULL;
	}

	if (ctx->privkey) {
		free(ctx->privkey);
		ctx->privkey = NULL;
	}

	if (ctx->digest) {
		free_poison(ctx->digest->data, ctx->digest->len);
		/* XXX sure seems like we should be freeing it here, but
		 * that's segfaulting, and we know it'll get cleaned up with
		 * PORT_FreeArena a couple of lines down.
		 */
		ctx->digest = NULL;
	}

	PORT_FreeArena(ctx->arena, PR_TRUE);
	memset(ctx, '\0', sizeof(*ctx));

	NSS_Shutdown();
}

/* read a cert generated with:
 * $ openssl genrsa -out privkey.pem 2048
 * $ openssl req -new -key privkey.pem -out cert.csr
 * $ openssl req -new -x509 -key privkey.pem -out cacert.pem -days 1095
 * See also: http://www.openssl.org/docs/HOWTO/keys.txt
 */
int read_cert(int certfd, CERTCertificate **cert)
{
	char *certstr = NULL;
	size_t certlen = 0;
	int rc;

	rc = read_file(certfd, &certstr, &certlen);
	if (rc < 0)
		return -1;

	*cert = CERT_DecodeCertFromPackage(certstr, certlen);
	free(certstr);
	if (!*cert)
		return -1;
	return 0;
}

SEC_ASN1Template AlgorithmIDTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SECAlgorithmID),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(SECAlgorithmID, algorithm),
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_OPTIONAL |
		SEC_ASN1_ANY,
	.offset = offsetof(SECAlgorithmID, parameters),
	.sub = NULL,
	.size = 0,
	},
	{ 0, }
};

int
generate_algorithm_id(cms_context *ctx, SECAlgorithmID *idp, SECOidTag tag)
{
	SECAlgorithmID id;

	if (!idp)
		return -1;

	SECOidData *oiddata;
	oiddata = SECOID_FindOIDByTag(tag);
	if (!oiddata) {
		PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
		return -1;
	}
	if (SECITEM_CopyItem(ctx->arena, &id.algorithm, &oiddata->oid))
		return -1;

	SECITEM_AllocItem(ctx->arena, &id.parameters, 2);
	if (id.parameters.data == NULL)
		goto err;
	id.parameters.data[0] = SEC_ASN1_NULL;
	id.parameters.data[1] = 0;
	id.parameters.type = siBuffer;

	memcpy(idp, &id, sizeof (id));
	return 0;

err:
	SECITEM_FreeItem(&id.algorithm, PR_FALSE);
	return -1;
}


