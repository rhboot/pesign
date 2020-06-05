// SPDX-License-Identifier: GPLv2
/*
 * wincert.c - implement the PE authenticode certification database
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "pesign.h"

typedef win_certificate_pkcs_signed_data_t cert_list_entry_t;

/*
 * gcc's leak checker simply cannot believe that this code does not leak the
 * allocation for data, either (bizarrely) on every iteration of the loop that
 * fills it or when generate_cert_list() returns, even though the trace it
 * gives you stops right before the call to free()
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
static int
generate_cert_list(SECItem **signatures, int num_signatures,
		   void **cert_list, size_t *cert_list_size)
{
	size_t cl_size = 0;
	for (int i = 0; i < num_signatures; i++) {
		cl_size += sizeof (win_certificate_header_t);
		cl_size += signatures[i]->len;
		cl_size += ALIGNMENT_PADDING(cl_size, 8);
	}

	uint8_t *data = calloc(cl_size, sizeof(uint8_t));
	if (!data)
		return -1;

	*cert_list = (void *)data;
	*cert_list_size = cl_size;

	for (int i = 0; i < num_signatures; i++) {
		/* pe-coff 8.2 adds some text that says each cert list
		 * entry is 8-byte aligned, so that means we need to align
		 * them here. */
		cert_list_entry_t *cle = (cert_list_entry_t *)data;
		cle->hdr.length = signatures[i]->len +
			sizeof (win_certificate_header_t);
		cle->hdr.revision = WIN_CERT_REVISION_2_0;
		cle->hdr.cert_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
		memcpy(&cle->data[0], signatures[i]->data,
					signatures[i]->len);
		data += sizeof (win_certificate_header_t) + signatures[i]->len;
		data += ALIGNMENT_PADDING(signatures[i]->len, 8);
	}

	return 0;
}

static int
implant_cert_list(Pe *pe, void *cert_list, size_t cert_list_size)
{
	if (!pe) {
		errno = EINVAL;
		return -1;
	}

	int rc = pe_alloccert(pe, cert_list_size);
	if (rc < 0)
		return rc;

	return pe_populatecert(pe, cert_list, cert_list_size);
}

int
finalize_signatures(SECItem **sigs, int num_sigs, Pe *pe)
{
	void *clist = NULL;
	size_t clist_size = 0;

	if (!pe) {
		errno = EINVAL;
		return -1;
	}

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
#pragma GCC diagnostic pop

int
cert_iter_init(cert_iter *iter, Pe *pe)
{
	if (!pe) {
		errno = EINVAL;
		return -1;
	}

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

	size_t n = iter->n;
	void *certs = iter->certs;
	size_t size = iter->size;

	void *map = NULL;
	size_t map_size = 0;

	map = pe_rawfile(iter->pe, &map_size);
	if (!map || map_size < 1)
		return 0;

	while (1) {
		win_certificate_header_t *tmpcert;
		if (n + sizeof (*tmpcert) >= size)
			goto done;

		tmpcert = (win_certificate_header_t *)((uint8_t *)certs + n);

		if ((intptr_t)tmpcert > (intptr_t)((intptr_t)map + map_size))
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
		iter->n += ALIGNMENT_PADDING(iter->n, 8);

		return 1;
	}
}

static ssize_t
get_current_sigspace_size(Pe *pe)
{
	data_directory *dd;

	int rc = pe_getdatadir(pe, &dd);
	if (rc < 0) {
		fprintf(stderr, "Could not get data directory: %m\n");
		exit(1);
	}

	return dd->certs.size;
}

static ssize_t
get_current_sigspace_in_use(Pe *pe)
{
	cert_iter iter;
	int rc = cert_iter_init(&iter, pe);
	if (rc < 0)
		return -1;

	ssize_t foundsize = 0;

	intptr_t prevdata = 0;
	ssize_t prevdatalen = 0;

	while (1) {
		intptr_t data = 0;
		ssize_t datalen = 0;
		rc = next_cert(&iter, (void **)&data, &datalen);
		if (rc <= 0) {
			if (prevdata != 0)
				foundsize = (prevdata + prevdatalen) -
						(intptr_t)iter.certs;
			break;
		}
		prevdata = data;
		prevdatalen = datalen;
	}

	return foundsize;
}

static ssize_t
get_total_sigspace_size(cms_context *cms, Pe *pe, SECItem *sig)
{
	ssize_t ret = 0;
	/* first, see if we need some padding to make the original structure
	 * in the data directory */
	if (cms->num_signatures == 0) {
		void *map = NULL;
		size_t map_size = 0;
		map = pe_rawfile(pe, &map_size);
		if (!map || map_size < 1) {
			fprintf(stderr, "Could not get raw PE map: %m\n");
			exit(1);
		}

		ret += ALIGNMENT_PADDING(map_size, 8);
	}

	/* if there is a previous dd->certs, we need to find out if any is
	 * spare room in it */
	ssize_t in_use = get_current_sigspace_in_use(pe);
	if (in_use > 0) {
		in_use += ALIGNMENT_PADDING(in_use, 8);
		ret += in_use;
	}

	/* at this point ret is any amount of padding we need plus any number
	 * of previous entries.  Add the amount for this entry, which *doesn't*
	 * yet include any padding. */
	ret += sizeof(win_certificate_header_t);
	ret += sig->len;

	/* and finally, the spec actually says:
	 * | Notice that certificates always start on an octaword boundary.
	 * | If a certificate is not an even number of octawords long, it
	 * | is zero padded to the next octaword boundary. However, the length
	 * | of the certificate does not include this padding and so any
	 * | certificate navigation software must be sure to round up to the
	 * | next octaword to locate another certificate.
	 * which sort of accidentally says we pad if we need to, whether or
	 * not there's anythign coming next.  A+ writing here.
	 */
	ret += ALIGNMENT_PADDING(ret, 8);
	return ret;
}

ssize_t
available_cert_space(Pe *pe)
{
	return get_current_sigspace_size(pe) -
		get_current_sigspace_in_use(pe);
}

ssize_t
calculate_signature_space(cms_context *cms, Pe *pe)
{
	SECItem sig = { 0, };

	int rc = generate_spc_signed_data(cms, &sig);
	if (rc < 0) {
		fprintf(stderr, "Could not generate signed data: %m\n");
		exit(1);
	}

	ssize_t ret = get_total_sigspace_size(cms, pe, &sig);
	free_poison(sig.data, sig.len);
	return ret;
}

ssize_t
get_sigspace_extend_amount(cms_context *cms, Pe *pe, SECItem *sig)
{
	ssize_t total = get_total_sigspace_size(cms, pe, sig);
	return total - get_current_sigspace_size(pe);
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
				if (signatures[i]->data) /* <-- see below */
					free(signatures[i]->data);
				free(signatures[i]);
				/*
				 * in gcc-10.1.1-1.fc32 , -fanalyzer believes the test
				 * above is a use-after free.  I really don't see how,
				 * but this somehow convinces it there's nothing wrong
				 * there.
				 */
				signatures[i] = NULL;
			}
		}
		free(signatures);
	}
	return -1;
}
