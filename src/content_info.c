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

#include <stddef.h>

#include <nspr4/prerror.h>
#include <nss3/cms.h>

/* Generate DER for SpcString, which is always "<<<Obsolete>>>" in UCS-2.
 * Irony abounds. Needs to decode like this:
 *        [0]  (28)
 *           00 3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00
 *           6c 00 65 00 74 00 65 00 3e 00 3e 00 3e
 */
SEC_ASN1Template SpcStringTemplate[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0,
	.offset = offsetof(SpcString, unicode),
	.sub = &SEC_BMPStringTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

static int
generate_spc_string(PRArenaPool *arena, SECItem *ssp, char *str, int len)
{
	SpcString ss;
	memset(&ss, '\0', sizeof (ss));

	SECITEM_AllocItem(arena, &ss.unicode, len);
	if (!ss.unicode.data)
		return -1;

	memcpy(ss.unicode.data, str, len);
	ss.unicode.type = siBMPString;

	if (SEC_ASN1EncodeItem(arena, ssp, &ss, SpcStringTemplate) == NULL) {
		fprintf(stderr, "Could not encode SpcString: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

/* Generate the SpcLink DER. Awesomely, this needs to decode as:
 *                      C-[2]  (30)
 * That is all.
 */
SEC_ASN1Template SpcLinkTemplate[] = {
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 2 |
		SEC_ASN1_INLINE,
	.offset = offsetof(SpcLink, file),
	.sub = &SpcStringTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

static int
generate_spc_link(PRArenaPool *arena, SECItem *slp)
{
	SpcLink sl;
	memset(&sl, '\0', sizeof (sl));

	if (generate_spc_string(arena, &sl.file,
			"\0<\0<\0<\0O\0b\0s\0o\0l\0e\0t\0e\0>\0>\0>", 28) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (SEC_ASN1EncodeItem(arena, slp, &sl, SpcLinkTemplate) == NULL) {
		fprintf(stderr, "Could not encode SpcLink: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	return 0;
}

/* This generates to the DER for a SpcPeImageData, which includes the two
 * DER chunks generated above. Output is basically:
 *
 *       C-Sequence (37)
 *          Bit String (1)
 *            00
 *          C-[0]  (32)
 *             C-[2]  (30)
 *                [0]  (28)
 *                   00 3c 00 3c 00 3c 00 4f 00 62 00 73 00
 *                   6f 00 6c 00 65 00 74 00 65 00 3e 00 3e
 *                   00 3e
 * The Bit String output is a cheap hack; I can't figure out how to get the
 * length right using DER_BIT_STRING in the template; it always comes out as
 * 07 00 instead of just 00. So instead, since it's /effectively/ constant,
 * I just picked DER_NULL since it'll always come out to the right size, and
 * then manually bang DER_BIT_STRING into the type in the encoded output.
 * I'm so sorry. -- pjones
 */
SEC_ASN1Template SpcPeImageDataTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SpcPeImageData),
	},
	{
	.kind = SEC_ASN1_NULL,
	.offset = offsetof(SpcPeImageData, flags),
	.sub = NULL,
	.size = 1
	},
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 0,
	.offset = offsetof(SpcPeImageData, link),
	.sub = &SpcLinkTemplate,
	.size = sizeof (SpcLink),
	},
	{ 0, }
};

static int
generate_spc_pe_image_data(PRArenaPool *arena, SECItem *spidp)
{
	SpcPeImageData spid;

	SECITEM_AllocItem(arena, &spid.flags, 1);
	if (!spid.flags.data)
		return -1;
	spid.flags.data[0] = 0;

	if (generate_spc_link(arena, &spid.link) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (SEC_ASN1EncodeItem(arena, spidp, &spid,
			SpcPeImageDataTemplate) == NULL) {
		fprintf(stderr, "Could not encode SpcPeImageData: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	/* XXX OMG FIX THIS */
	/* manually bang it from NULL to BIT STRING because I can't figure out
	 * how to make the fucking templates work right for the bitstring size
	 */
	spidp->data[2] = DER_BIT_STRING;
	return 0;
}

SEC_ASN1Template SpcAttributeTypeAndOptionalValueTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SpcAttributeTypeAndOptionalValue)
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(SpcAttributeTypeAndOptionalValue, contentType),
	.sub = &SEC_ObjectIDTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_OPTIONAL |
		SEC_ASN1_ANY,
	.offset = offsetof(SpcAttributeTypeAndOptionalValue, value),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

/* Generate DER for SpcAttributeTypeAndValue, which is basically just
 * a DER_SEQUENCE containing the OID 1.3.6.1.4.1.311.2.1.15
 * (SPC_PE_IMAGE_DATA_OBJID) and the SpcPeImageData.
 */
static int
generate_spc_attribute_yadda_yadda(PRArenaPool *arena, SECItem *ataovp)
{
	SpcAttributeTypeAndOptionalValue ataov;
	memset(&ataov, '\0', sizeof (ataov));

	if (get_ms_oid_secitem(SPC_PE_IMAGE_DATA_OBJID, &ataov.contentType) < 0){
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (generate_spc_pe_image_data(arena, &ataov.value) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (SEC_ASN1EncodeItem(arena, ataovp, &ataov,
			SpcAttributeTypeAndOptionalValueTemplate) == NULL) {
		fprintf(stderr,
			"Could not encode SpcAttributeTypeAndOptionalValue:"
			"%s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}
	return 0;
}

/* Generate the DigestInfo, which is a sequence containing a AlgorithmID
 * and an Octet String of the binary's hash in that algorithm. For some
 * reason this is the only place I could really get template chaining to
 * work right. It's probably my on defficiency.
 */
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

SEC_ASN1Template DigestInfoTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = 0
	},
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(DigestInfo, digestAlgorithm),
	.sub = AlgorithmIDTemplate,
	.size = sizeof (SECAlgorithmID),
	},
	{
	.kind = SEC_ASN1_OCTET_STRING,
	.offset = offsetof(DigestInfo, digest),
	.sub = NULL,
	.size = sizeof (SECItem)
	},
	{ 0, }
};

static int
generate_spc_digest_info(PRArenaPool *arena, SECItem *dip,
				SECAlgorithmID *hashtype, SECItem *hash)
{
	DigestInfo di;
	memset(&di, '\0', sizeof (di));

	memcpy(&di.digestAlgorithm, hashtype, sizeof (di.digestAlgorithm));
	memcpy(&di.digest, hash, sizeof (di.digest));

	if (SEC_ASN1EncodeItem(arena, dip, &di, DigestInfoTemplate) == NULL) {
		fprintf(stderr, "Could not encode DigestInfo: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}
	return 0;
}

/* Generate DER for SpcIndirectDataContent. It's just a DER_SEQUENCE that
 * holds the digestInfo above and the SpcAttributeTypeAndValue, also above.
 * Sequences, all the way down.
 *
 * This also generates the actual DER for SpcContentInfo, and is a public
 * function. SpcContentInfo is another sequence that holds a OID,
 * 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_OBJID) and then a reference to
 * the generated SpcIndirectDataContent structure.
 */
SEC_ASN1Template SpcIndirectDataContentTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_ANY |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SpcIndirectDataContent, data),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_ANY |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SpcIndirectDataContent, messageDigest),
	.sub = &DigestInfoTemplate,
	.size = sizeof (SECItem)
	},
	{ 0, }
};

static int
generate_spc_indirect_data_content(PRArenaPool *arena,
				SECItem *idcp,
				SECAlgorithmID *hashtype, SECItem *hash)
{
	SpcIndirectDataContent idc;
	memset(&idc, '\0', sizeof (idc));

	if (generate_spc_attribute_yadda_yadda(arena, &idc.data) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (generate_spc_digest_info(arena, &idc.messageDigest,
					hashtype, hash) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	if (SEC_ASN1EncodeItem(arena, idcp, &idc,
			SpcIndirectDataContentTemplate) == NULL) {
		fprintf(stderr,
			"Could not encode SpcIndirectDataContent: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		return -1;
	}
	return 0;
}

const SEC_ASN1Template SpcContentInfoTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SpcContentInfo)
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(SpcContentInfo, contentType),
	.sub = NULL,
	.size = 0,
	},
	{
	.kind = SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_OPTIONAL |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(SpcContentInfo, content),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

int
generate_spc_content_info(SECItem *cip, cms_context *ctx)
{
	if (!cip)
		return -1;

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

	SpcContentInfo ci;
	memset(&ci, '\0', sizeof (ci));

	if (get_ms_oid_secitem(SPC_INDIRECT_DATA_OBJID, &ci.contentType) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		goto err;
	}

	if (generate_spc_indirect_data_content(arena, &ci.content,
			ctx->algorithm_id, ctx->digest) < 0) {
		fprintf(stderr, "got here %s:%d\n",__func__,__LINE__);
		return -1;
	}

	SECItem encoded = { 0, };
	if (SEC_ASN1EncodeItem(arena, &encoded, &ci, SpcContentInfoTemplate) !=
			&encoded) {
		fprintf(stderr, "Could not encode SpcContentInfo: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	cip->data = malloc(encoded.len);
	if (!cip->data)
		goto err;
	memcpy(cip->data, encoded.data, encoded.len);
	cip->len = encoded.len;
	cip->type = encoded.type;

	/* this will clean up the whole of the allocations in this call chain
	 * except for the malloc we're returning through cip */
	PORT_FreeArena(arena, PR_TRUE);
	return 0;
err:
	PORT_FreeArena(arena, PR_TRUE);
	return -1;
}

/* There's nothing else here. */
