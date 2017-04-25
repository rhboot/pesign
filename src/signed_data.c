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
#include <syslog.h>

#include "pesign.h"

#include <prerror.h>
#include <nss.h>

static int
generate_algorithm_id_list(cms_context *cms, SECAlgorithmID ***algorithm_list_p)
{
	SECAlgorithmID **algorithms = NULL;
	int err = 0;

	algorithms = PORT_ArenaZAlloc(cms->arena, sizeof (SECAlgorithmID *) *
						  2);
	if (!algorithms)
		return -1;

	algorithms[0] = PORT_ArenaZAlloc(cms->arena, sizeof(SECAlgorithmID));
	if (!algorithms[0]) {
		err = PORT_GetError();
		goto err_list;
	}

	if (generate_algorithm_id(cms, algorithms[0],
			digest_get_digest_oid(cms)) < 0) {
		err = PORT_GetError();
		goto err_item;
	}

	*algorithm_list_p = algorithms;
	return 0;
err_item:
	PORT_ZFree(algorithms[0], sizeof (SECAlgorithmID));
err_list:
	PORT_ZFree(algorithms, sizeof (SECAlgorithmID *) * 2);
	PORT_SetError(err);
	return -1;
}

void
free_algorithm_list(cms_context *cms __attribute__((__unused__)),
		    SECAlgorithmID **algorithm_list)
{
	if (!algorithm_list)
		return;

#if 0
	for (int i = 0; algorithm_list[i] != NULL; i++) {
		PORT_ZFree(algorithm_list[i], sizeof (SECAlgorithmID));
	}
	PORT_ZFree(algorithm_list, sizeof (SECAlgorithmID *) * 2);
#endif
}

static int
generate_certificate_list(cms_context *cms, SECItem ***certificate_list_p)
{
	SECItem **certificates = NULL;
	void *mark = PORT_ArenaMark(cms->arena);

	certificates = PORT_ArenaZAlloc(cms->arena, sizeof (SECItem *) * 3);
	if (!certificates) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not allocate certificate list");
	}
	int i = 0;

	certificates[i] = PORT_ArenaZAlloc(cms->arena, sizeof (SECItem));
	if (!certificates[i]) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not allocate certificate entry");
	}
	SECITEM_CopyItem(cms->arena, certificates[i++], &cms->cert->derCert);

	if (!is_issuer_of(cms->cert, cms->cert)) {
		CERTCertificate *signer = NULL;
		int rc = find_named_certificate(cms, cms->cert->issuerName,
						&signer);
		if (rc == 0 && signer &&
				signer->derCert.len && signer->derCert.data) {
			if (signer->derCert.len != cms->cert->derCert.len ||
					memcmp(signer->derCert.data,
						cms->cert->derCert.data,
						signer->derCert.len)) {
				certificates[i] = PORT_ArenaZAlloc(cms->arena,
							sizeof (SECItem));
				if (!certificates[i]) {
					save_port_err(
						PORT_ArenaRelease(cms->arena, mark));
					cmsreterr(-1, cms,"could not allocate "
						"certificate entry");
				}
				SECITEM_CopyItem(cms->arena, certificates[i++],
						&signer->derCert);
			}
			CERT_DestroyCertificate(signer);
		}
	}

	*certificate_list_p = certificates;
	return 0;
}

typedef enum {
	PE_SIGNER_INFO,
	AUTHVAR_SIGNER_INFO,
	END_SIGNER_INFO_LIST
} SignerInfoType;

int
generate_signerInfo_list(cms_context *cms, SpcSignerInfo ***signerInfo_list_p, SignerInfoType type)
{
	SpcSignerInfo **signerInfo_list;
	int err = 0;
	int rc;

	if (!signerInfo_list_p)
		return -1;

	signerInfo_list = PORT_ArenaZAlloc(cms->arena,
					sizeof (SpcSignerInfo *) * 2);
	if (!signerInfo_list)
		return -1;

	signerInfo_list[0] = PORT_ArenaZAlloc(cms->arena,
						sizeof (SpcSignerInfo));
	if (!signerInfo_list[0]) {
		err = PORT_GetError();
		goto err_list;
	}

	if (type == PE_SIGNER_INFO)
		rc = generate_spc_signer_info(cms, signerInfo_list[0]);
	else if (type == AUTHVAR_SIGNER_INFO)
		rc = generate_authvar_signer_info(cms, signerInfo_list[0]);
	else
		goto err_item;
	if (rc < 0) {
		err = PORT_GetError();
		goto err_item;
	}

	*signerInfo_list_p = signerInfo_list;
	return 0;
err_item:
#if 0
	PORT_ZFree(signerInfo_list[0], sizeof (SpcSignerInfo));
#endif
err_list:
#if 0
	PORT_ZFree(signerInfo_list, sizeof (SpcSignerInfo *) * 2);
#endif
	PORT_SetError(err);
	return -1;
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
	.sub = &SECOID_AlgorithmIDTemplate,
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
generate_spc_signed_data(cms_context *cms, SECItem *sdp)
{
	SignedData sd;

	if (!sdp)
		return -1;

	memset(&sd, '\0', sizeof (sd));
	void *mark = PORT_ArenaMark(cms->arena);

	if (SEC_ASN1EncodeInteger(cms->arena, &sd.version, 1) == NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode integer");
	}

	if (generate_algorithm_id_list(cms, &sd.algorithms) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	if (generate_spc_content_info(cms, &sd.cinfo) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	if (generate_certificate_list(cms, &sd.certificates) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	sd.crls = NULL;

	if (generate_signerInfo_list(cms, &sd.signerInfos, PE_SIGNER_INFO) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	SECItem encoded = { 0, };
	if (SEC_ASN1EncodeItem(cms->arena, &encoded, &sd, SignedDataTemplate)
			== NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode SignedData");
	}

	ContentInfo sdw;
	memset(&sdw, '\0', sizeof (sdw));

	SECOidData *oid = SECOID_FindOIDByTag(SEC_OID_PKCS7_SIGNED_DATA);

	memcpy(&sdw.contentType, &oid->oid, sizeof (sdw.contentType));
	memcpy(&sdw.content, &encoded, sizeof (sdw.content));

	SECItem wrapper = { 0, };
	if (SEC_ASN1EncodeItem(cms->arena, &wrapper, &sdw,
			ContentInfoTemplate) == NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode SignedData");
	}

	memcpy(sdp, &wrapper, sizeof(*sdp));
	PORT_ArenaUnmark(cms->arena, mark);
	return 0;
}

int
generate_authvar_signed_data(cms_context *cms, SECItem *sdp)
{
	SignedData sd;

	if (!sdp)
		return -1;

	memset(&sd, '\0', sizeof (sd));
	void *mark = PORT_ArenaMark(cms->arena);

	if (SEC_ASN1EncodeInteger(cms->arena, &sd.version, 1) == NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode integer");
	}

	if (generate_algorithm_id_list(cms, &sd.algorithms) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	if (generate_authvar_content_info(cms, &sd.cinfo) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	if (generate_certificate_list(cms, &sd.certificates) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	sd.crls = NULL;

	if (generate_signerInfo_list(cms, &sd.signerInfos, AUTHVAR_SIGNER_INFO) < 0) {
		PORT_ArenaRelease(cms->arena, mark);
		return -1;
	}

	SECItem encoded = { 0, };
	if (SEC_ASN1EncodeItem(cms->arena, &encoded, &sd, SignedDataTemplate)
			== NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode SignedData");
	}

	ContentInfo sdw;
	memset(&sdw, '\0', sizeof (sdw));

	SECOidData *oid = SECOID_FindOIDByTag(SEC_OID_PKCS7_SIGNED_DATA);

	memcpy(&sdw.contentType, &oid->oid, sizeof (sdw.contentType));
	memcpy(&sdw.content, &encoded, sizeof (sdw.content));

	SECItem wrapper = { 0, };
	if (SEC_ASN1EncodeItem(cms->arena, &wrapper, &sdw,
			ContentInfoTemplate) == NULL) {
		save_port_err(PORT_ArenaRelease(cms->arena, mark));
		cmsreterr(-1, cms, "could not encode SignedData");
	}

	memcpy(sdp, &wrapper, sizeof(*sdp));
	PORT_ArenaUnmark(cms->arena, mark);
	return 0;
}
