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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <errno.h>

#include "efitypes.h"
#include "siglist.h"

struct efi_signature_data {
	efi_guid_t		SignatureOwner;
	union {
		uint8_t		Sha256SignatureData[32];
		uint8_t		Rsa2048SignatureData[256];
		uint8_t		Rsa2048Sha256SignatureData[256];
		uint8_t		Sha1SignatureData[20];
		uint8_t		Rsa2048Sha1SignatureData[256];
		uint8_t		X509SignatureData[1];
		uint8_t		Sha224SignatureData[28];
		uint8_t		Sha384SignatureData[48];
		uint8_t		Sha512SignatureData[64];
		uint8_t		SignatureData[1];
	};
};

struct efi_signature_list {
	efi_guid_t			SignatureType;
	uint32_t			SignatureListSize;
	uint32_t			SignatureHeaderSize;
	uint32_t			SignatureSize;
};

struct signature_list {
	efi_guid_t			SignatureType;
	uint32_t			SignatureListSize;
	uint32_t			SignatureHeaderSize;
	uint32_t			SignatureSize;
	struct efi_signature_data	**Signatures;
	void *realized;
};

struct sig_type {
	efi_guid_t type;
	uint32_t size;
};

static struct sig_type sig_types[] = {
	{ EFI_CERT_SHA256_GUID,		32 },
	{ EFI_CERT_RSA2048_GUID,	256 },
	{ EFI_CERT_RSA2048_SHA256_GUID,	256 },
	{ EFI_CERT_SHA1_GUID,		20 },
	{ EFI_CERT_RSA2048_SHA1_GUID,	256 },
	{ EFI_CERT_X509_GUID,		0 },
	{ EFI_CERT_SHA224_GUID,		28 },
	{ EFI_CERT_SHA384_GUID,		48 },
	{ EFI_CERT_SHA512_GUID,		64 },
};
static int num_sig_types = sizeof (sig_types) / sizeof (struct sig_type);

static int32_t
get_sig_type_size(efi_guid_t sig_type)
{
	for (int i = 0; i < num_sig_types; i++) {
		if (!memcmp(&sig_type, &sig_types[i].type, sizeof (sig_type)))
			return sig_types[i].size;
	}
	return -1;
}

signature_list *
signature_list_new(efi_guid_t SignatureType)
{
	int32_t size = get_sig_type_size(SignatureType);
	if (size < 0)
		return NULL;

	signature_list *sl = calloc(1, sizeof (*sl));
	if (!sl)
		return NULL;

	sl->SignatureType = SignatureType;
	sl->SignatureSize = size + sizeof (efi_guid_t);
	sl->SignatureListSize = sizeof (struct efi_signature_list);

	return sl;
}

static int
resize_entries(signature_list *sl, uint32_t newsize)
{
	int count = (sl->SignatureListSize - sizeof (struct efi_signature_list)) / sl->SignatureSize;
	for (int i = 0; i < count; i++) {
		struct efi_signature_data *sd = sl->Signatures[i];
		struct efi_signature_data *new_sd = calloc(1, newsize);

		if (!new_sd)
			return -errno;

		memcpy(new_sd, sd, sl->SignatureSize);
		free(sd);
		sl->Signatures[i] = new_sd;
	}
	sl->SignatureSize = newsize;
	sl->SignatureListSize = sizeof (struct efi_signature_list) + count * newsize;
	return 0;
}

int
signature_list_add_sig(signature_list *sl, efi_guid_t owner,
			uint8_t *sig, uint32_t sigsize)
{
	if (!sl)
		return -1;

	if (sl->realized) {
		free(sl->realized);
		sl->realized = NULL;
	}

	efi_guid_t x509_guid = EFI_CERT_X509_GUID;

	if (memcmp(&sl->SignatureType, &x509_guid, sizeof (efi_guid_t)) == 0) {
		if (sigsize > sl->SignatureSize)
			resize_entries(sl, sigsize);
	} else if (sigsize != get_sig_type_size(sl->SignatureType)) {
		fprintf(stderr, "sigsize: %d sl->SignatureSize: %d\n",
			sigsize, sl->SignatureSize);
		errno = EINVAL;
		return -1;
	}

	struct efi_signature_data *sd = calloc(1, sl->SignatureSize);
	if (!sd)
		return -1;
	memcpy(&sd->SignatureOwner, &owner, sizeof (owner));
	memcpy(sd->SignatureData, sig, sl->SignatureSize -
						sizeof (efi_guid_t));

	int count = (sl->SignatureListSize - sizeof (struct efi_signature_list)) / sl->SignatureSize;
	struct efi_signature_data **sdl = calloc(count+1,
					sizeof (struct efi_signature_data *));
	if (!sdl) {
		free(sd);
		return -1;
	}

	memcpy(sdl, sl->Signatures, count * sl->SignatureSize);
	sdl[count] = sd;
	sl->SignatureListSize += sl->SignatureSize;

	free(sl->Signatures);
	sl->Signatures = sdl;

	return 0;
}

#if 0
int
signature_list_parse(signature_list *sl, uint8_t *data, size_t len)
{
	if (!sl)
		return -1;

	if (sl->realized) {
		free(sl->realized);
		sl->realized = NULL;
	}

	efi_signature_list *esl = data;
	efi_signature_data *esd = NULL;

}
#endif

int
signature_list_realize(signature_list *sl, void **out, size_t *outsize)
{
	if (sl->realized) {
		free(sl->realized);
		sl->realized = NULL;
	}

	int count = (sl->SignatureListSize - sizeof (struct efi_signature_list)) / sl->SignatureSize;
	struct efi_signature_list *esl = NULL;
	uint32_t size = sizeof (*esl) +
			+ count * sl->SignatureSize;

	void *ret = calloc(1, size);
	if (!ret)
		return -1;
	esl = ret;

	memcpy(esl, sl, sizeof (*esl));

	uint8_t *pos = ret + sizeof (*esl);
	for (int i = 0; i < count; i++) {
		memcpy(pos, sl->Signatures[i], sl->SignatureSize);
		pos += sl->SignatureSize;
	}

	sl->realized = ret;

	*out = ret;
	*outsize = size;
	return 0;
}

void
signature_list_free(signature_list *sl)
{
	if (sl->realized)
		free(sl->realized);

	int count = (sl->SignatureListSize - sizeof (struct efi_signature_list)) / sl->SignatureSize;
	for (int i = 0; i < count; i++)
		free(sl->Signatures[i]);

	free(sl);
}
