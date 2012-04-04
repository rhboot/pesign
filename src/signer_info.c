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

#include "pesign.h"

#include <nspr4/prerror.h>
#include <nss3/cms.h>

SEC_ASN1Template SignerIdentifierTemplate[] = {
	{ 0, }
};

SEC_ASN1Template SpcSignerInfoTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_INTEGER,
	.offset = offsetof(SpcSignerInfo, CMSVersion),
	.sub = &SEC_IntegerTemplate,
	.size = sizeof (SECItem),
	},
#if 0
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SpcSignerInfo, sid),
	.sub = &SignerIdentifierTemplate,
	.size = sizeof (SignerIdentifier),
	},
#endif
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SpcSignerInfo, digestAlgorithm),
	.sub = &AlgorithmIDTemplate,
	.size = sizeof (SECItem)
	},
#if 0
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_OPTIONAL |
		SEC_ASN1_IMPLICIT,
	.offset = offsetof(SpcSignerInfo, signedAttrs),
	.sub = &AttributeSetTemplate;
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_ANY |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SpcSignerInfo, signatureAlgorithm),
	.sub = &DigestInfoTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_OCTET_STRING,
	.offset = offsetof(SpcSignerInfo, signature),
	.sub = &SEC_OctetStringTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 1 |
		SEC_ASN1_OPTIONAL |
		SEC_ASN1_IMPLICIT,
	.offset = offsetof(SpcSignerInfo, unsignedAttrs),
	.sub = &AttributeSetTemplate;
	.size = sizeof (SECItem)
	},
#endif
	{ 0, }
};

int
generate_spc_signer_info(SECItem *sip, cms_context *ctx)
{
	if (!sip)
		return -1;

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	SpcSignerInfo si;
	memset(&si, '\0', sizeof (si));

	if (SEC_ASN1EncodeInteger(arena, &si.CMSVersion, 1) == NULL) {
		fprintf(stderr, "Could not encode CMSVersion: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	memcpy(&si.digestAlgorithm, ctx->algorithm_id,
		sizeof(si.digestAlgorithm));

#if 0
	if (generate_signer_infos(arena, cert, pwcb_args,
#endif

	SECItem encoded;
	if (SEC_ASN1EncodeItem(arena, &encoded, &si, SpcSignerInfoTemplate) !=
			&encoded) {
		fprintf(stderr, "Could not encode SignerInfo: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	sip->data = malloc(encoded.len);
	if (!sip->data)
		goto err;
	memcpy(sip->data, encoded.data, encoded.len);
	sip->len = encoded.len;
	sip->type = encoded.type;

	/* this will clean up the whole of the allocations in this call chain
	 * except for the malloc we're returning through cip */
	PORT_FreeArena(arena, PR_TRUE);
	return 0;
err:
	PORT_FreeArena(arena, PR_TRUE);
	return -1;
}
