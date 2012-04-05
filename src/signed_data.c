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
#include <stdio.h>
#include <string.h>

#include "pesign.h"

#include <nspr4/prerror.h>
#include <nss3/nss.h>

static int
generate_algorithm_id_list(SECAlgorithmID ***algorithm_list_p, cms_context *ctx)
{
	SECAlgorithmID **algorithms = NULL;

	algorithms = PORT_ArenaZAlloc(ctx->arena, sizeof (SECAlgorithmID *) *
						  2);
	if (!algorithms)
		return -1;

	algorithms[0] = PORT_ArenaZAlloc(ctx->arena, sizeof(SECAlgorithmID));
	if (!algorithms[0]) {
		int err = PORT_GetError();
		PORT_ZFree(algorithms, sizeof (SECAlgorithmID) * 2);
		PORT_SetError(err);
		return -1;
	}

	SECITEM_CopyItem(ctx->arena, &algorithms[0]->algorithm,
					&ctx->algorithm_id->algorithm);
	SECITEM_CopyItem(ctx->arena, &algorithms[0]->parameters,
					&ctx->algorithm_id->parameters);
	*algorithm_list_p = algorithms;
	return 0;
}

void
free_algorithm_list(SECAlgorithmID **algorithm_list, cms_context *ctx)
{
	if (!algorithm_list)
		return;

	for (int i = 0; algorithm_list[i] != NULL; i++) {
		PORT_Free(&algorithm_list[i]->algorithm);
		PORT_Free(&algorithm_list[i]->parameters);
	}
	PORT_ZFree(algorithm_list, sizeof (SECAlgorithmID *) * 2);
}

static int
generate_certificate_list(SECItem ***certificate_list_p, cms_context *ctx)
{
	SECItem **certificates = NULL;

	certificates = PORT_ArenaZAlloc(ctx->arena, sizeof (SECItem *) * 2);
	if (!certificates)
		return -1;
	
	certificates[0] = PORT_ArenaZAlloc(ctx->arena, sizeof (SECItem));
	if (!certificates[0]) {
		int err = PORT_GetError();
		PORT_ZFree(certificates, sizeof (SECItem) * 2);
		PORT_SetError(err);
		return -1;
	}

	SECITEM_CopyItem(ctx->arena, certificates[0], &ctx->cert->derCert);
	*certificate_list_p = certificates;
	return 0;
}

static void
free_certificate_list(SECItem **certificate_list, cms_context *ctx)
{
	if (!certificate_list)
		return;

	for (int i = 0; certificate_list[i] != NULL; i++)
		PORT_Free(certificate_list[i]);
	PORT_ZFree(certificate_list, sizeof (SECItem) * 2);
}

int
generate_signerInfo_list(SpcSignerInfo ***signerInfo_list_p, cms_context *ctx)
{
	SpcSignerInfo **signerInfo_list;

	if (!signerInfo_list_p)
		return -1;

	signerInfo_list = PORT_ArenaZAlloc(ctx->arena,
					sizeof (SpcSignerInfo *));

	if (!signerInfo_list)
		return -1;

	*signerInfo_list_p = signerInfo_list;
	return 0;
}

void
free_signerInfo_list(SpcSignerInfo **signerInfo_list, cms_context *ctx)
{
	
}

typedef struct {
	SECItem version;
	SECAlgorithmID **algorithms;
	SpcContentInfo cinfo;
	SECItem **certificates;
	SECItem **crls;
	SpcSignerInfo **signerInfos;
} SignedData;

SEC_ASN1Template SignedDataTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (SignedData)
	},
	{
	.kind = SEC_ASN1_INTEGER,
	.offset = offsetof(SignedData, version),
	.sub = &SEC_IntegerTemplate,
	.size = sizeof (SECItem)
	},
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = offsetof(SignedData, algorithms),
	.sub = &AlgorithmIDTemplate,
	.size = sizeof (SECItem),
	},
	{
	.kind = SEC_ASN1_INLINE,
	.offset = offsetof(SignedData, cinfo),
	.sub = &SpcContentInfoTemplate,
	.size = sizeof (SpcContentInfo),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SignedData, certificates),
	.sub = &SEC_SetOfAnyTemplate,
	.size = sizeof(SECItem**),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 1 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_OPTIONAL,
	.offset = offsetof(SignedData, crls),
	.sub = &SEC_SetOfAnyTemplate,
	.size = sizeof (SECItem **),
	},
	{
	.kind = SEC_ASN1_SET_OF,
	.offset = offsetof(SignedData, signerInfos),
	.sub = &SpcSignerInfoTemplate,
	.size = 0,
	},
	{ 0, }
};

typedef struct {
	SECItem contentType;
	SECItem content;
} ContentInfo;

SEC_ASN1Template ContentInfoTemplate[] = {
	{
	.kind = SEC_ASN1_SEQUENCE,
	.offset = 0,
	.sub = NULL,
	.size = sizeof (ContentInfo),
	},
	{
	.kind = SEC_ASN1_OBJECT_ID,
	.offset = offsetof(ContentInfo, contentType),
	.sub = &SEC_ObjectIDTemplate,
	.size = sizeof (SECItem),
	},
	{
	.kind = SEC_ASN1_CONTEXT_SPECIFIC | 0 |
		SEC_ASN1_CONSTRUCTED |
		SEC_ASN1_EXPLICIT,
	.offset = offsetof(ContentInfo, content),
	.sub = &SEC_AnyTemplate,
	.size = sizeof (SECItem),
	},
	{ 0, } 
};

int
generate_spc_signed_data(SECItem *sdp, cms_context *ctx)
{
	SignedData sd;

	if (!sdp)
		return -1;

	memset(&sd, '\0', sizeof (sd));

	if (SEC_ASN1EncodeInteger(ctx->arena, &sd.version, 1) == NULL)
		return -1;

	if (generate_algorithm_id_list(&sd.algorithms, ctx) < 0)
		goto err;
	
	if (generate_spc_content_info(&sd.cinfo, ctx) < 0)
		goto err_algorithms;

	if (generate_certificate_list(&sd.certificates, ctx) < 0)
		goto err_cinfo;

	sd.crls = NULL;

	if (generate_signerInfo_list(&sd.signerInfos, ctx) < 0)
		goto err_certificate_list;

	SECItem encoded = { 0, };
	if (SEC_ASN1EncodeItem(ctx->arena, &encoded, &sd, SignedDataTemplate)
			== NULL) {
		fprintf(stderr, "Could not encode SignedData: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err_signer_infos;
	}

	ContentInfo sdw;
	memset(&sdw, '\0', sizeof (sdw));

	SECOidData *oid = SECOID_FindOIDByTag(SEC_OID_PKCS7_SIGNED_DATA);

	memcpy(&sdw.contentType, &oid->oid, sizeof (sdw.contentType));
	memcpy(&sdw.content, &encoded, sizeof (sdw.content));

	SECItem wrapper = { 0, };
	if (SEC_ASN1EncodeItem(ctx->arena, &wrapper, &sdw,
			ContentInfoTemplate) == NULL) {
		fprintf(stderr, "Could not encode SignedData: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err_signed_data;
	}

	memcpy(sdp, &wrapper, sizeof(*sdp));
	return 0;
err_signed_data:
	SECITEM_FreeItem(&encoded, PR_FALSE);
err_signer_infos:
	free_signerInfo_list(sd.signerInfos, ctx);
err_certificate_list:
	free_certificate_list(sd.certificates, ctx);
err_cinfo:
	free_spc_content_info(&sd.cinfo, ctx);
err_algorithms:
	free_algorithm_list(sd.algorithms, ctx);
err:
	SECITEM_FreeItem(&sd.version, PR_TRUE);
	return -1;

	
#if 0
	NSSCMSMessage *cmsg = NULL;

	secuPWData pwdata = { 0, 0 };
	CERTCertificate *cert = NULL;

	cert = CERT_FindUserCertByUsage(NULL, "pjones@redhat.com",
		certUsageObjectSigner, PR_FALSE, &pwdata);
	if (cert == NULL) {
		fprintf(stderr, "Could not find certificate\n");
		goto err;
	}

	cmsg = NSS_CMSMessage_Create(NULL);
	if (cmsg == NULL) {
		fprintf(stderr, "Could not create CMS Message\n");
		goto err;
	}

	NSSCMSSignedData *sigd = NULL;
	sigd = NSS_CMSSignedData_Create(cmsg);
	if (sigd == NULL) {
		fprintf(stderr, "Could not create Signed Data\n");
		goto err;
	}

	NSSCMSContentInfo *cinfo;
	cinfo = NSS_CMSMessage_GetContentInfo(cmsg);
	if (NSS_CMSContentInfo_SetContent_SignedData(cmsg, cinfo, sigd) !=
			SECSuccess) {
		fprintf(stderr, "Could not set Signed Data\n");
		goto err;
	}
	//NSS_CMSContentInfo_SetDontStream(cinfo, PR_TRUE);

	cinfo = NSS_CMSSignedData_GetContentInfo(sigd);
	SECOidTag tag = find_ms_oid_tag(SPC_INDIRECT_DATA_OBJID);
	if (NSS_CMSContentInfo_SetContent(cmsg, cinfo, tag, cip) !=
			SECSuccess) {
		fprintf(stderr, "Could not set Data\n");
		goto err;
	}
	//NSS_CMSContentInfo_SetDontStream(cinfo, PR_TRUE);

	NSSCMSSignerInfo *signerinfo = NULL;
	signerinfo = NSS_CMSSignerInfo_Create(cmsg, cert, hashalg);
	if (signerinfo == NULL) {
		fprintf(stderr, "Could not create Signer Info\n");
		goto err;
	}

	if (NSS_CMSSignerInfo_IncludeCerts(signerinfo, NSSCMSCM_CertChain,
			certUsageObjectSigner) != SECSuccess) {
		fprintf(stderr, "Could not include certs in signer info\n");
		goto err;
	}

	if (NSS_CMSSignerInfo_AddSigningTime(signerinfo, PR_Now()) !=
			SECSuccess) {
		fprintf(stderr, "Could not add signing time\n");
		goto err;
	}

	if (NSS_CMSSignedData_AddSignerInfo(sigd, signerinfo) != SECSuccess) {
		fprintf(stderr, "Could not add Signer Info\n");
		goto err;
	}

	PRArenaPool *arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (!arena) {
		fprintf(stderr, "Could not create new arena\n");
		goto err;
	}

	NSSCMSEncoderContext *ecx = NULL;
	ecx = NSS_CMSEncoder_Start(cmsg,
				NULL, NULL,
				sdp, arena,
				NULL, NULL,
				NULL, NULL,
				NULL, NULL);
	if (!ecx) {
		fprintf(stderr, "Could not create encoder context: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	SECStatus rv;
	rv = NSS_CMSEncoder_Update(ecx, (char *)cip, cip->content.len + cip->contentType.len);
	if (rv != SECSuccess) {
		fprintf(stderr, "Failed to add content: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		goto err;
	}

	rv = NSS_CMSEncoder_Finish(ecx);
	if (rv != SECSuccess) {
		fprintf(stderr, "Failed to encode data: %s\n",
			PORT_ErrorToString(PORT_GetError()));
		ecx = NULL;
		sdp->data = NULL;
		sdp->len = 0;
		goto err;
	}
	ecx = NULL;

	rc = 0;
err:
	if (ecx)
		NSS_CMSEncoder_Cancel(ecx);
	
	if (arena) /* XXX use PR_TRUE, which means duplicating sdp before
			returning */
		PORT_FreeArena(arena, PR_FALSE);

	if (cert)
		CERT_DestroyCertificate(cert);

	if (cmsg)
		NSS_CMSMessage_Destroy(cmsg);
	return rc;
#endif
}

#if 0
typedef struct {
	enum {
		PW_NONE = 0,
		PW_FROMFILE = 1,
		PW_PLAINTEXT = 2,
		PW_EXTERNAL = 3
	} source;
	char *data;
} secuPWData;
#endif
