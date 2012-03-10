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


/* Generate DER for SpcString, which is always "<<<Obsolete>>>" in UCS-2.
 * Irony abounds. Needs to decode like this:
 *        [0]  (28)
 *           00 3c 00 3c 00 3c 00 4f 00 62 00 73 00 6f 00 
 *           6c 00 65 00 74 00 65 00 3e 00 3e 00 3e 
 */
typedef struct {
	SECItem obsolete;
} SpcString;

DERTemplate LettersTemplate[] = {
	{ (DER_CONTEXT_SPECIFIC | 0), offsetof(SpcString,obsolete),
		NULL, sizeof(SECItem) },
	{ 0, }
};

static int
generate_spc_string_der(PRArenaPool *arena, SECItem *der)
{
	SpcString notder;

	if (!arena || !der)
		return -1;
	
	SECITEM_AllocItem(NULL, &notder.obsolete, 28);
	if (!notder.obsolete.data)
		return -1;
	
	memcpy(notder.obsolete.data, "\x00\x3c\x00\x3c\x00\x3c\x00\x4f\x00\x62\x00\x73\x00\x6f\x00\x6c\x00\x65\x00\x74\x00\x65\x00\x3e\x00\x3e\x00\x3e", 28);
	notder.obsolete.type = siBMPString;

	SECStatus rv;

	rv = DER_Encode(arena, der, LettersTemplate, &notder);
	if (rv != SECSuccess)
		return -1;
	return 0;
}

/* Generate the SpcLink DER. Awesomely, this needs to decode as:
 *                      C-[2]  (30)
 * That is all.
 */
typedef struct {
	SECItem string;
} SpcLink;

DERTemplate SpcLinkTemplate[] = {
	{ DER_CONSTRUCTED | (DER_CONTEXT_SPECIFIC | 2), 0, NULL, sizeof(SpcString) },
	{ 0, }
};

static int
generate_spc_link_der(PRArenaPool *arena, SECItem *der)
{
	int rc;
	SECItem SpcStringDer;

	if (!arena || !der)
		return -1;

	rc = generate_spc_string_der(arena, &SpcStringDer);
	if (rc < 0)
		return rc;
	
	SECStatus rv;

	rv = DER_Encode(arena, der, SpcLinkTemplate, &SpcStringDer);
	if (rv != SECSuccess)
		return -1;
	return 0;
}

/* This generates to the DER for a SpcPeImageData, which includes the two
 * DER chunks generated above.  Output is basically:
 *
 *       C-Sequence  (37)
 *          Bit String  (1)
 *            00
 *          C-[0]  (32)
 *             C-[2]  (30)
 *                [0]  (28)
 *                   00 3c 00 3c 00 3c 00 4f 00 62 00 73 00
 *                   6f 00 6c 00 65 00 74 00 65 00 3e 00 3e
 *                   00 3e
 * The Bit String output is a cheap hack; I can't figure out how to get the
 * length right using DER_BIT_STRING in the template; it always comes out as
 * 07 00 instead of just 00.  So instead, since it's /effectively/ constant,
 * I just picked DER_NULL since it'll always come out to the right size, and
 * then manually bang DER_BIT_STRING into the type in the encoded output.
 * I'm so sorry.  -- pjones
 */
typedef SECItem SpcPeImageFlags;

DERTemplate SpcPeImageFlagsTemplate[] = {
	{ DER_NULL, 0, NULL, 1},
	{ 0, }
};

typedef struct {
	SpcPeImageFlags flags;
	SpcLink link;
} SpcPeImageData;

DERTemplate SpcPeImageDataTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, 0 },
	{ DER_NULL, offsetof(SpcPeImageData,flags),
		NULL, 1 },
	{ DER_CONSTRUCTED | (DER_CONTEXT_SPECIFIC | 0),
		offsetof(SpcPeImageData,link), NULL, sizeof(SpcLink) },
	{ 0, }
};

static int
generate_spc_pe_image_data_der(PRArenaPool *arena, SECItem *der)
{
	int rc;
	SpcPeImageData spid;

	if (!arena || !der)
		return -1;

	SECITEM_AllocItem(NULL, &spid.flags, 1);
	if (!spid.flags.data)
		return -1;

	rc = generate_spc_link_der(arena, &spid.link.string);
	if (rc < 0) {
		SECITEM_FreeItem(&spid.flags, PR_FALSE);
		return rc;
	}
	
	SECStatus rv;

	rv = DER_Encode(arena, der, SpcPeImageDataTemplate, &spid);
	if (rv != SECSuccess)
		return -1;
	/* XXX OMG FIX THIS */
	/* manually bang it from NULL to BIT STRING because I can't figure out
	 * how to make the fucking templates work right for the bitstring size
	 */
	der->data[2] = DER_BIT_STRING;
	return 0;
}

/* Generate DER for SpcAttributeTypeAndValue, which is basically just
 * a DER_SEQUENCE containing the OID 1.3.6.1.4.1.311.2.1.15
 * (SPC_PE_IMAGE_DATA_OBJID) and the SpcPeImageData.
 */
typedef struct {
	SECItem type;
	SECItem value;
} SpcAttributeTypeAndOptionalValue;

DERTemplate SpcAttributeTypeAndOptionalValueTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, 0 },
	{ DER_OBJECT_ID, offsetof(SpcAttributeTypeAndOptionalValue,type) },
	{ DER_OPTIONAL | DER_CONSTRUCTED | (DER_CONTEXT_SPECIFIC | 0),
		offsetof(SpcAttributeTypeAndOptionalValue,value),
		NULL, sizeof(SECItem) },
	{ 0, }
};

static int
generate_attrib_type_der(PRArenaPool *arena, SECItem *der)
{
	int rc;
	SpcAttributeTypeAndOptionalValue sataov;

	if (!arena || !der)
		return -1;

	rc = get_ms_oid_secitem(SPC_PE_IMAGE_DATA_OBJID, &sataov.type);
	if (rc < 0)
		return rc;
	rc = generate_spc_pe_image_data_der(arena, &sataov.value);
	if (rc < 0)
		return rc;

	SECStatus rv;
	rv = DER_Encode(arena, der, SpcAttributeTypeAndOptionalValueTemplate, &sataov);
	if (rv != SECSuccess)
		return -1;
	return 0;
}

/* Generate the DigestInfo, which is a sequence containing a AlgorithmID
 * and an Octet String of the binary's hash in that algorithm.  For some
 * reason this is the only place I could really get template chaining to
 * work right.  It's probably my on defficiency.
 */
typedef struct {
	SECAlgorithmID digestAlgorithm;
	SECItem digest;
} DigestInfo;

DERTemplate AlgorithmIdentifierTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, sizeof(SECAlgorithmID) },
	{ DER_OBJECT_ID, offsetof(SECAlgorithmID,algorithm), },
	{ DER_OPTIONAL | DER_ANY, offsetof(SECAlgorithmID,parameters), },
	{ 0, }
};

DERTemplate DigestInfoTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, 0 },
	{ DER_INLINE, offsetof(DigestInfo,digestAlgorithm),
		AlgorithmIdentifierTemplate },
	{ DER_OCTET_STRING, offsetof(DigestInfo,digest), },
	{ 0, }
};

static int
generate_digest_info_der(PRArenaPool *arena, SECAlgorithmID *hashtype,
			SECItem *hash, SECItem *der)
{
	DigestInfo di;

	if (!arena || !der)
		return -1;

	memcpy(&di.digestAlgorithm, hashtype,sizeof(*hashtype));
	memcpy(&di.digest, hash, sizeof(*hash));

	SECStatus rv;
	rv = DER_Encode(arena, der, DigestInfoTemplate, &di);
	if (rv != SECSuccess)
		return -1;
	return 0;
}

/* Generate DER for SpcIndirectDataContent.  It's just a DER_SEQUENCE that
 * holds the digestInfo above and the SpcAttributeTypeAndValue, also above.
 * Sequences, all the way down.
 *
 * This also generates the actual DER for SpcContentInfo, and is a public
 * function. SpcContentInfo is another sequence that holds a OID,
 * 1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_OBJID) and then a reference to
 * the generated SpcIndirectDataContent structure.
 */
typedef struct {
	SECItem data;
	SECItem messageDigest;
} SpcIndirectDataContent;

DERTemplate SpcIndirectDataContentTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, 0 },
	{ DER_ANY,
		offsetof(SpcIndirectDataContent,data),
		NULL, sizeof(SECItem) },
	{ DER_ANY,
		offsetof(SpcIndirectDataContent,messageDigest),
		NULL, sizeof(SECItem)},
	{ 0, }
};

typedef struct {
	SECItem contentType;
	SECItem content;
} SpcContentInfo;

DERTemplate SpcContentInfoTemplate[] = {
	{ DER_SEQUENCE, 0, NULL, 0 },
	{ DER_OBJECT_ID, offsetof(SpcContentInfo,contentType), },
	{ DER_OPTIONAL | DER_CONSTRUCTED | (DER_CONTEXT_SPECIFIC | 0),
		offsetof(SpcContentInfo,content), NULL, sizeof(SECItem) },
	{ 0, }
};

int
generate_spc_content_info(SECItem *cip,
			SECAlgorithmID *hashtype, SECItem *hash)
{
	SpcContentInfo ci;
	int rc = 0;

	if (!cip)
		return -1;

	PRArenaPool *arena = NULL;

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!arena)
		return -1;

	SpcIndirectDataContent idc;
	rc = generate_attrib_type_der(arena, &idc.data);
	rc = generate_digest_info_der(arena, hashtype, hash, &idc.messageDigest);

	SECStatus rv;
	rc = get_ms_oid_secitem(SPC_INDIRECT_DATA_OBJID, &ci.contentType);
	if (rc < 0)
		goto err;

	rv = DER_Encode(arena, &ci.content, SpcIndirectDataContentTemplate,
			&idc);
	if (rv != SECSuccess)
		goto err;

	SECItem der = { 0, };
	rv = DER_Encode(arena, &der, SpcContentInfoTemplate, &ci);

	cip->type = der.type;
	cip->len = der.len;
	cip->data = malloc(der.len);
	if (!cip->data)
		goto err;

	memcpy(cip->data, der.data, der.len);
	PORT_FreeArena(arena, PR_TRUE);
	return 0;
err:
	PORT_FreeArena(arena, PR_TRUE);
	return -1;
}

/* There's nothing else here. */
