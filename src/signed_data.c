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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pesign.h"

#include <nspr4/prerror.h>

#include <nss3/nss.h>
#include <nss3/cms.h>

typedef struct {
	enum {
		PW_NONE = 0,
		PW_FROMFILE = 1,
		PW_PLAINTEXT = 2,
		PW_EXTERNAL = 3
		} source;
	char *data;
} secuPWData;

int generate_spc_signed_data(SECItem *sdp,
					SpcContentInfo *cip,
					SECOidTag hashalg)
{
	int rc = -1;
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
}
