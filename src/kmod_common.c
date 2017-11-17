/*
 * Copyright 2017 Endless Mobile, Inc.
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
 * Author(s): Daniel Drake <drake@endlessm.com>
 */

#include <stdint.h>

#include "pesign.h"

#include <prerror.h>

int
kmod_generate_digest(cms_context *cms, unsigned char *addr, size_t len)
{
	int rc;

	rc = generate_digest_begin(cms);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "failed to begin digest: %d", rc);
		return rc;
	}

	generate_digest_step(cms, addr, len);

	rc = generate_digest_finish(cms);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "failed to finish digest: %d", rc);
		return rc;
	}

	return 0;
}

struct write_sig_info {
	int outfd;
	int rc;
	size_t sig_len;
};

static void
kmod_signature_out(void *arg, const char *buf, unsigned long len)
{
	struct write_sig_info *info = (struct write_sig_info *) arg;
	int rc;

	rc = write_file(info->outfd, buf, len);
	if (rc < 0) {
		info->rc = rc;
		return;
	}

	info->sig_len += len;
}

ssize_t
kmod_write_signature(cms_context *cms, int outfd)
{
	SEC_PKCS7ContentInfo *cinfo;
	SECItem *digest = cms->digests[cms->selected_digest].pe_digest;
	SECStatus rv;
	struct write_sig_info info = {
		.outfd = outfd,
	};
	ssize_t rc = -1;

	cinfo = SEC_PKCS7CreateSignedData(cms->cert,
					  certUsageObjectSigner, NULL,
					  digest_get_digest_oid(cms),
					  digest, NULL, NULL);
	if (!cinfo) {
		cms->log(cms, LOG_ERR, "failed to create signed data: %s",
			 PORT_ErrorToString(PORT_GetError()));
		return -1;
	}

	rv = SEC_PKCS7Encode(cinfo, kmod_signature_out, &info, NULL, NULL,
			     NULL);
	if (rv != SECSuccess) {
		cms->log(cms, LOG_ERR, "failed to encode signed data: %d", rv);
		goto out;
	}

	if (info.rc != 0) {
		cms->log(cms, LOG_ERR, "Signed data encode error %d", info.rc);
		rc = info.rc;
		goto out;
	}

	rc = info.sig_len;

out:
	SEC_PKCS7DestroyContentInfo(cinfo);
	return rc;
}

static const char magic_number[] = "~Module signature appended~\n";
#define PKEY_ID_PKCS7 2

struct module_signature {
	uint8_t algo;		/* Public-key crypto algorithm [0] */
	uint8_t hash;		/* Digest algorithm [0] */
	uint8_t id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t signer_len;	/* Length of signer's name [0] */
	uint8_t key_id_len;	/* Length of key identifier [0] */
	uint8_t __pad[3];
	uint32_t sig_len;	/* Length of signature data */
};

int
kmod_write_sig_info(cms_context *cms, int fd, uint32_t sig_len)
{
	struct module_signature sig_info = { .id_type = PKEY_ID_PKCS7 };

	sig_info.sig_len = htonl(sig_len);
	if (write_file(fd, &sig_info, sizeof(sig_info)) < 0) {
		cms->log(cms, LOG_ERR, "failed to write sig_info: %m");
		return -1;
	}

	if (write_file(fd, magic_number, sizeof(magic_number) - 1) < 0) {
		cms->log(cms, LOG_ERR, "failed to write magic: %m");
		return -1;
	}

	return 0;
}
