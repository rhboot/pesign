// SPDX-License-Identifier: GPLv2
/*
 * file_kmod.c - our kmod file type helpers.
 * Copyright 2017 Endless Mobile, Inc.
 *
 * Author(s): Daniel Drake <drake@endlessm.com>
 */
#include "fix_coverity.h"

#include <stdint.h>

#include "pesign.h"
#include "signed_data.h"

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

ssize_t
kmod_write_signature(cms_context *cms, int outfd)
{
	SECItem sd_der;
	ssize_t rc = -1;

	memset(&sd_der, '\0', sizeof(sd_der));

	/* Use generate_spc_signed_data() instead of SEC_PKCS7CreateSignedData()
	 * to avoid strict certificate chain validation that fails for self-signed
	 * certificates even when trust flags are properly set. */
	rc = generate_spc_signed_data(cms, &sd_der);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "failed to create signed data: %s (%s)",
			 PORT_ErrorToString(PORT_GetError()),
			 PORT_ErrorToName(PORT_GetError()));
		return -1;
	}

	rc = write_file(outfd, sd_der.data, sd_der.len);
	if (rc < 0) {
		cms->log(cms, LOG_ERR, "failed to write signature: %m");
		return -1;
	}

	return sd_der.len;
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
