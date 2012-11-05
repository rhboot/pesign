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

#include "pesign.h"

struct cert_list_entry {
	win_certificate wc;
	uint8_t data[];
};

static int
generate_cert_list(SECItem **signatures, int num_signatures,
		void **cert_list, size_t *cert_list_size)
{
	size_t cl_size = 0;
	for (int i = 0; i < num_signatures; i++) {
		cl_size += sizeof (win_certificate);
		cl_size += signatures[i]->len;
	}

	uint8_t *data = malloc(cl_size);
	if (!data)
		return -1;

	*cert_list = (void *)data;
	*cert_list_size = cl_size;

	for (int i = 0; i < num_signatures; i++) {
		struct cert_list_entry *cle = (struct cert_list_entry *)data;
		cle->wc.length = signatures[i]->len +
			sizeof (win_certificate);
		cle->wc.revision = WIN_CERT_REVISION_2_0;
		cle->wc.cert_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
		memcpy(&cle->data[0], signatures[i]->data,
					signatures[i]->len);
		data += sizeof (win_certificate) + signatures[i]->len;
	}

	return 0;
}

static int
implant_cert_list(Pe *pe, void *cert_list, size_t cert_list_size)
{
	return pe_populatecert(pe, cert_list, cert_list_size);
}

int
finalize_signatures(SECItem **sigs, int num_sigs, Pe *pe)
{
	void *clist = NULL;
	size_t clist_size = 0;

	if (generate_cert_list(sigs, num_sigs,
				&clist, &clist_size) < 0)
		return -1;

	if (implant_cert_list(pe, clist, clist_size) < 0) {
		free(clist);
		return -1;
	}
	free(clist);
	return 0;
}

int
cert_iter_init(cert_iter *iter, Pe *pe)
{
	iter->pe = pe;
	iter->n = 0;
	iter->certs = 0;
	iter->size = -1;

	data_directory *dd;

	int rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return -1;

	void *map;
	size_t map_size;

	map = pe_rawfile(pe, &map_size);
	if (!map)
		return -1;

	iter->certs = map + dd->certs.virtual_address;
	if (dd->certs.virtual_address) {
		iter->size = dd->certs.size;
	}

	return rc;
}

int
next_cert(cert_iter *iter, void **cert, ssize_t *cert_size)
{
	if (!iter)
		return -1;
	if (!iter->certs)
		return -1;

	if (iter->n >= iter->size) {
done:
		*cert = NULL;
		*cert_size = -1;
		return 0;
	}

	off_t n = iter->n;
	void *certs = iter->certs;
	size_t size = iter->size;

	void *map = NULL;
	size_t map_size = 0;

	map = pe_rawfile(iter->pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	while (1) {
		win_certificate *tmpcert;
		if (n + sizeof (*tmpcert) >= size)
			goto done;

		tmpcert = (win_certificate *)((uint8_t *)certs + n);

		if ((uint64_t)tmpcert > (uint64_t)map + map_size)
			return -1;

		/* length _includes_ the size of the structure. */
		uint32_t length = le32_to_cpu(tmpcert->length);

		if (length < sizeof (*tmpcert))
			return -1;

		n += sizeof (*tmpcert);
		length -= sizeof (*tmpcert);

		if (n + length > size)
			goto done;

		if (length == 0)
			continue;

		uint16_t rev = le16_to_cpu(tmpcert->revision);
		if (rev != WIN_CERT_REVISION_2_0)
			continue;

		if (cert)
			*cert = (uint8_t *)tmpcert + sizeof(*tmpcert);
		if (cert_size)
			*cert_size = length;

		iter->n += sizeof (*tmpcert) + length;

		return 1;
	}
}

ssize_t
available_cert_space(Pe *pe)
{
	cert_iter iter;
	int rc = cert_iter_init(&iter, pe);
	if (rc < 0)
		return -1;

	data_directory *dd;

	rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		return -1;

	ssize_t totalsize = dd->certs.size;
	ssize_t foundsize = 0;

	void *data;
	ssize_t datalen;

	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;
		foundsize += datalen;
	}

	return totalsize - foundsize;
}

ssize_t calculate_signature_space(cms_context *cms, Pe *pe)
{
	int rc;

	SECItem sig = { 0, };

	rc = generate_spc_signed_data(cms, &sig);
	if (rc < 0)
err:
		return rc;

	data_directory *dd = NULL;
	rc = pe_getdatadir(pe, &dd);
	if (rc < 0)
		goto err;

	ssize_t ret = sig.len + dd->certs.size + sizeof(win_certificate) -
						available_cert_space(pe);

	//free(sig.data);

	return ret;
}

int
parse_signatures(SECItem ***sigs, int *num_sigs, Pe *pe)
{
	cert_iter iter;
	int rc = cert_iter_init(&iter, pe);
	if (rc < 0)
		return -1;

	void *data;
	ssize_t datalen;
	int nsigs = 0;

	rc = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;
		nsigs++;
	}

	if (nsigs == 0) {
		*num_sigs = 0;
		*sigs = NULL;
		return 0;
	}

	SECItem **signatures = calloc(nsigs, sizeof (SECItem *));
	if (!signatures)
		return -1;

	rc = cert_iter_init(&iter, pe);
	if (rc < 0)
		goto err;

	int i = 0;
	while (1) {
		rc = next_cert(&iter, &data, &datalen);
		if (rc <= 0)
			break;

		signatures[i] = calloc(1, sizeof (SECItem));
		if (!signatures[i])
			goto err;

		signatures[i]->data = calloc(1, datalen);
		if (!signatures[i]->data)
			goto err;

		memcpy(signatures[i]->data, data, datalen);
		signatures[i]->len = datalen;
		signatures[i]->type = siBuffer;
		i++;
	}

	*num_sigs = nsigs;
	*sigs = signatures;

	return 0;
err:
	if (signatures) {
		for (i = 0; i < nsigs; i++) {
			if (signatures[i]) {
				if (signatures[i]->data)
					free(signatures[i]->data);
				free(signatures[i]);
			}
		}
		free(signatures);
	}
	return -1;
}


