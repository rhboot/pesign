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

#include <limits.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

#include <nspr4/prerror.h>
#include <nss3/cms.h>
#include <nss3/cryptohi.h>
#include <nss3/keyhi.h>
#include <nss3/pk11pub.h>

SEC_ASN1Template AttributeTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (Attribute)
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(Attribute, attrType),
	.sub = &SEC_ObjectIDTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = offsetof(Attribute, attrValues),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem **)
	},
	{ 0, }
};

SEC_ASN1Template AttributeSetTemplate[] = {
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = 0,
	.sub = AttributeTemplate,
	.size = 0
	},
};

SEC_ASN1Template SignedAttributesTemplate[] = {
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0,
	.offset = 0,
	.sub = &AttributeSetTemplate,
	.size = 0
	}
};

static int
generate_signed_attributes(cms_context *ctx, SECItem *sattrs)
{
	Attribute *attrs[5];
	memset(attrs, '\0', sizeof (attrs));

	SECItem encoded;
	SECOidTag tag;
	SECOidData *oid;

	/* build the first attribute, which says that this is
	 * a PKCS9 content blob thingy */
	attrs[0] = PORT_ArenaZAlloc(ctx->arena, sizeof (Attribute));
	if (!attrs[0])
		goto err;

	oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_CONTENT_TYPE);
	attrs[0]->attrType = oid->oid;

	SECItem *content_types[2] = { NULL, NULL };
	tag = find_ms_oid_tag(SPC_INDIRECT_DATA_OBJID);
	if (tag == SEC_OID_UNKNOWN)
		goto err;
	if (generate_object_id(ctx, &encoded, tag) < 0)
		goto err;
	content_types[0] = SECITEM_ArenaDupItem(ctx->arena, &encoded);
	if (!content_types[0])
		goto err;
	attrs[0]->attrValues = content_types;

	/* build the second attribute.  I have no idea what this
	 * is for whatsoever. */
	attrs[1] = PORT_ArenaZAlloc(ctx->arena, sizeof (Attribute));
	if (!attrs[1])
		goto err;
	if (get_ms_oid_secitem(SPC_STATEMENT_TYPE_OBJID,
			&attrs[1]->attrType) < 0)
		goto err;

	SECItem *microsoft_magic[2] = { NULL, NULL };
	tag = find_ms_oid_tag(SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID);
	if (tag == SEC_OID_UNKNOWN)
		goto err;
	if (generate_object_id(ctx, &encoded, tag) < 0)
		goto err;
	microsoft_magic[0] = SECITEM_ArenaDupItem(ctx->arena, &encoded);
	if (!microsoft_magic[0])
		goto err;
	attrs[1]->attrValues = microsoft_magic;

	/* build the third attribute, which is our PKCS9 message
	 * digest (which is a SHA-whatever selected and generated elsewhere */
	attrs[2] = PORT_ArenaZAlloc(ctx->arena, sizeof (Attribute));
	if (!attrs[2])
		goto err;

	oid = SECOID_FindOIDByTag(SEC_OID_PKCS9_MESSAGE_DIGEST);
	attrs[2]->attrType = oid->oid;

	SECItem *digest_values[2] = { NULL, NULL };
	if (generate_octet_string(ctx, &encoded, ctx->ci_digest) < 0)
		goto err;
	digest_values[0] = SECITEM_ArenaDupItem(ctx->arena, &encoded);
	if (!digest_values[0])
		goto err;
	attrs[2]->attrValues = digest_values;

	attrs[3] = PORT_ArenaZAlloc(ctx->arena, sizeof (Attribute));
	if (!attrs[3])
		goto err;

		goto err;
		goto err;

	Attribute **attrtmp = attrs;
	if (SEC_ASN1EncodeItem(ctx->arena, sattrs, &attrtmp,
				AttributeSetTemplate) == NULL)
		goto err;
	return 0;
err:
	return -1;
}

static char *getpw(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	struct termios sio, tio;
	char line[LINE_MAX], *p;

	if (tcgetattr(fileno(stdin), &sio) < 0) {
		fprintf(stderr, "Could not read password from standard input.\n");
		return NULL;
	}
	tio = sio;
	tio.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), 0, &tio) < 0) {
		fprintf(stderr, "Could not read password from standard input.\n");
		return NULL;
	}

	fprintf(stdout, "Enter passphrase for private key: ");
	if (fgets(line, sizeof(line), stdin) == NULL) {
		fprintf(stdout, "\n");
		tcsetattr(fileno(stdin), 0, &sio);
		return NULL;
	}
	fprintf(stdout, "\n");
	tcsetattr(fileno(stdin), 0, &sio);

	p = line + strcspn(line, "\r\n");
	if (p != NULL)
		*p = '\0';

	char *ret = strdup(line);
	memset(line, '\0', sizeof (line));
	if (!ret) {
		fprintf(stderr, "Could not read passphrase.\n");
		return NULL;
	}
	return ret;
}

static int
sign_blob(cms_context *ctx, SECItem *sigitem, SECItem *sign_content)
{
	sign_content = SECITEM_ArenaDupItem(ctx->arena, sign_content);
	if (!sign_content)
		return -1;

	SECOidData *oid = SECOID_FindOIDByTag(ctx->signature_oid_tag);
	if (!oid)
		goto err;

	PK11_SetPasswordFunc(getpw);
	SECKEYPrivateKey *privkey = PK11_FindKeyByAnyCert(ctx->cert, NULL);
	if (!privkey) {
		fprintf(stderr, "Could not get private key.\n");
		goto err;
	}
	
	SECItem signature;
	memset (&signature, '\0', sizeof (signature));

	SECStatus status;
	status = SEC_SignData(&signature, sign_content->data, sign_content->len,
			privkey, oid->offset);
	SECKEY_DestroyPrivateKey(privkey);
	privkey = NULL;

	if (status != SECSuccess) {
		fprintf(stderr, "Error signing data.\n");
		SECITEM_FreeItem(&signature, PR_FALSE);
		return -1;
	}
	*sigitem = signature;

	//SECITEM_FreeItem(sign_content, PR_TRUE);
	return 0;
err:
	//SECITEM_FreeItem(sign_content, PR_TRUE);
	return -1;
}

static int
generate_unsigned_attributes(cms_context *ctx, SECItem *uattrs)
{
	Attribute *attrs[1];
	memset(attrs, '\0', sizeof (attrs));

	Attribute **attrtmp = attrs;
	if (SEC_ASN1EncodeItem(ctx->arena, uattrs, &attrtmp,
				AttributeSetTemplate) == NULL)
		goto err;
	return 0;
err:
	return -1;
}

SEC_ASN1Template IssuerAndSerialNumberTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (IssuerAndSerialNumber)
	},
	{
	.kind = SEC_ASN1_ANY,
	.offset = offsetof(IssuerAndSerialNumber, issuer),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_INTEGER,
	.offset = offsetof(IssuerAndSerialNumber, serial),
	.sub = &SEC_IntegerTemplate,
	.size = sizeof (SECItem)
	},
	{ 0, }
};

SEC_ASN1Template SignerIdentifierTemplate[] = {
	/* we don't /really/ ever need signerType ==
	 * signerTypeSubjectKeyIdentifier */
#if 0
	{
	.kind = SEC_ASN1_CHOICE,
	.offset = offsetof(SignerIdentifier, signerType),
	.sub = NULL,
	.size = sizeof (SignerIdentifier)
	},
#endif
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SignerIdentifier, signerValue.iasn),
	.sub = &IssuerAndSerialNumberTemplate,
	.size = signerTypeIssuerAndSerialNumber,
	},
#if 0
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_EXPLICIT |
		SEC_ASN1_CONSTRUCTED,
	.offset = offsetof(SignerIdentifier, signerValue.subjectKeyID),
	.sub = &SEC_OctetStringTemplate,
	.size = signerTypeSubjectKeyIdentifier,
	},
#endif
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
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SpcSignerInfo, sid),
	.sub = &SignerIdentifierTemplate,
	.size = sizeof (SignerIdentifier),
	},
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SpcSignerInfo, digestAlgorithm),
	.sub = &AlgorithmIDTemplate,
	.size = sizeof (SECAlgorithmID)
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SpcSignerInfo, signedAttrs),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SpcSignerInfo, signatureAlgorithm),
	.sub = &AlgorithmIDTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_OCTET_STRING,
	.offset = offsetof(SpcSignerInfo, signature),
	.sub = &SEC_OctetStringTemplate,
	.size = sizeof (SECItem)
	},
#if 0
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 1 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_OPTIONAL |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(SpcSignerInfo, unsignedAttrs),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem)
	},
#endif
	{ 0, }
};

int
generate_spc_signer_info(SpcSignerInfo *sip, cms_context *ctx)
{
	if (!sip)
		return -1;

	SpcSignerInfo si;
	memset(&si, '\0', sizeof (si));

	if (SEC_ASN1EncodeInteger(ctx->arena, &si.CMSVersion, 1) == NULL) {
		fprintf(stderr, "Could not encode CMSVersion: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	si.sid.signerType = signerTypeIssuerAndSerialNumber;
	si.sid.signerValue.iasn.issuer = ctx->cert->derIssuer;
	si.sid.signerValue.iasn.serial = ctx->cert->serialNumber;

	if (generate_algorithm_id(ctx, &si.digestAlgorithm,
			ctx->digest_oid_tag) < 0)
		goto err;

	if (generate_signed_attributes(ctx, &si.signedAttrs) < 0)
		goto err;

	if (sign_blob(ctx, &si.signature, &si.signedAttrs) < 0)
		goto err;

	si.signedAttrs.data[0] = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
				SEC_ASN1_CONSTRUCTED;

	if (generate_algorithm_id(ctx, &si.signatureAlgorithm,
				ctx->signature_oid_tag) < 0)
		goto err;

	if (generate_unsigned_attributes(ctx, &si.unsignedAttrs) < 0)
		goto err;

	memcpy(sip, &si, sizeof(si));
	return 0;
err:
	return -1;
}
