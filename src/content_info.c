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
#include <syslog.h>

#include <prerror.h>
#include <cms.h>
#include <pk11pub.h>

#include "content_info_priv.h"

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
		SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(SpcPeImageData, link),
	.sub = &SpcLinkTemplate,
	.size = sizeof (SpcLink),
	},
	{ 0, }
};

static int
generate_spc_pe_image_data(cms_context *cms, SECItem *spidp)
{
	SpcPeImageData spid;

	SECITEM_AllocItem(cms->arena, &spid.flags, 1);
	if (!spid.flags.data)
		return -1;
	spid.flags.data[0] = 0;

	char obsolete[28] = "";
	int rc;
	rc = generate_spc_link(cms, &spid.link, SpcLinkTypeFile, obsolete, 0);
	if (rc < 0)
		return rc;

	if (SEC_ASN1EncodeItem(cms->arena, spidp, &spid,
			SpcPeImageDataTemplate) == NULL) {
		cms->log(cms, LOG_ERR, "could not encode SpcPeImageData: %s",
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
generate_spc_attribute_yadda_yadda(cms_context *cms, SECItem *ataovp)
{
	SpcAttributeTypeAndOptionalValue ataov;
	memset(&ataov, '\0', sizeof (ataov));

	int rc;

	rc = get_ms_oid_secitem(SPC_PE_IMAGE_DATA_OBJID, &ataov.contentType);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "could not get SPC_PE_IMAGE_DATA_OBJID");
		return -1;
	}

	rc = generate_spc_pe_image_data(cms, &ataov.value);
	if (rc < 0)
		return rc;

	if (SEC_ASN1EncodeItem(cms->arena, ataovp, &ataov,
			SpcAttributeTypeAndOptionalValueTemplate) == NULL) {
		cms->log(cms, LOG_ERR, "could not encode "
			"SpcAttributeTypeAndOptionalValue: %s",
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
	.sub = &SECOID_AlgorithmIDTemplate,
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
generate_spc_digest_info(cms_context *cms, SECItem *dip)
{
	DigestInfo di;
	memset(&di, '\0', sizeof (di));

	if (generate_algorithm_id(cms, &di.digestAlgorithm,
			digest_get_digest_oid(cms)) < 0)
		return -1;
	int i = cms->selected_digest;
	memcpy(&di.digest, cms->digests[i].pe_digest, sizeof (di.digest));

	if (content_is_empty(di.digest.data, di.digest.len)) {
		cms->log(cms, LOG_ERR, "got empty digest");
		return -1;
	}

	if (SEC_ASN1EncodeItem(cms->arena, dip, &di,
						DigestInfoTemplate) == NULL) {
		cms->log(cms, LOG_ERR, "could not encode DigestInfo: %s",
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
generate_spc_indirect_data_content(cms_context *cms, SECItem *idcp)
{
	SpcIndirectDataContent idc;
	memset(&idc, '\0', sizeof (idc));
	int rc;

	rc = generate_spc_attribute_yadda_yadda(cms, &idc.data);
	if (rc < 0)
		return rc;

	rc = generate_spc_digest_info(cms, &idc.messageDigest);
	if (rc < 0) {
		SECITEM_FreeItem(&idc.data, PR_FALSE);
		return rc;
	}

	if (SEC_ASN1EncodeItem(cms->arena, idcp, &idc,
			SpcIndirectDataContentTemplate) == NULL) {
		cms->log(cms, LOG_ERR, "could not encode "
			"SpcIndirectDataContent: %s",
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
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SpcContentInfo, content),
	.sub = &SEC_OctetStringTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, }
};

static int
generate_cinfo_digest(cms_context *cms, SpcContentInfo *cip)
{
	/* I have exactly no idea why the thing I need to digest is 2 bytes
	 * in to the content data, but the hash winds up identical to what
	 * Microsoft is embedding in their binaries if I do, so I'm calling
	 * that "correct", where "correct" means "there's not enough booze
	 * in the world."
	 */
	SECItem encoded = {
		.type = cip->content.type,
		.data = cip->content.data + 2,
		.len = cip->content.len - 2
	};
	
	PK11Context *ctx = NULL;
	SECOidData *oid = SECOID_FindOIDByTag(digest_get_digest_oid(cms));
	if (oid == NULL)
		return -1;

	cms->ci_digest = SECITEM_AllocItem(cms->arena, NULL,
					digest_get_digest_size(cms));
	if (!cms->ci_digest)
		goto err;

	ctx = PK11_CreateDigestContext(oid->offset);
	if (ctx == NULL)
		goto err;

	if (PK11_DigestBegin(ctx) != SECSuccess)
		goto err;
	if (PK11_DigestOp(ctx, encoded.data, encoded.len) != SECSuccess)
		goto err;
	if (PK11_DigestFinal(ctx, cms->ci_digest->data,
				&cms->ci_digest->len,
				digest_get_digest_size(cms)) != SECSuccess)
		goto err;

	if (content_is_empty(cms->ci_digest->data, cms->ci_digest->len)) {
		cms->log(cms, LOG_ERR, "generated empty digest");
		goto err;
	}

	if ((long long)cms->ci_digest->len > digest_get_digest_size(cms))
		goto err;

	PK11_DestroyContext(ctx, PR_TRUE);
#if 0
	SECITEM_FreeItem(&encoded, PR_FALSE);
#endif
	return 0;
err:
	if (ctx)
		PK11_DestroyContext(ctx, PR_TRUE);
#if 0
	if (cms->ci_digest)
		SECITEM_FreeItem(cms->ci_digest, PR_TRUE);
	if (encoded.data)
		SECITEM_FreeItem(&encoded, PR_FALSE);
#endif
	return -1;
}

int
generate_spc_content_info(cms_context *cms, SpcContentInfo *cip)
{
	if (!cip)
		return -1;

	SpcContentInfo ci;
	memset(&ci, '\0', sizeof (ci));

	int rc;
	rc = get_ms_oid_secitem(SPC_INDIRECT_DATA_OBJID, &ci.contentType);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "could not get OID for "
			"SPC_INDIRECT_DATA_OBJID");
		return rc;
	}

	rc = generate_spc_indirect_data_content(cms, &ci.content);
	if (rc < 0)
		return rc;

	memcpy(cip, &ci, sizeof *cip);

	rc = generate_cinfo_digest(cms, cip);
	if (rc < 0)
		return rc;

	return 0;
}

int
generate_authvar_content_info(cms_context *cms, SpcContentInfo *cip)
{
	SECOidData *oid;

	if (!cip)
		return -1;

	SpcContentInfo ci;
	memset(&ci, '\0', sizeof (ci));

	oid = SECOID_FindOIDByTag(SEC_OID_PKCS7_DATA);
	if (oid == NULL) {
		cms->log(cms, LOG_ERR, "could not get OID for "
			"SEC_OID_PKCS7_DATA");
		return -1;
	}
	if (SECITEM_CopyItem(cms->arena, &ci.contentType, &oid->oid))
		return -1;

	ci.content.len = 0;
	ci.content.data = NULL;

	memcpy(cip, &ci, sizeof *cip);

	return 0;
}

void
free_spc_content_info(cms_context *cms __attribute__((__unused__)),
		      SpcContentInfo *cip __attribute__((__unused__)))
{
#if 0
	SECITEM_FreeItem(&cip->contentType, PR_TRUE);
	SECITEM_FreeItem(&cip->content, PR_TRUE);
#endif
}

/* There's nothing else here. */
