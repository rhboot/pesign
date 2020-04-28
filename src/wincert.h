// SPDX-License-Identifier: GPLv2
/*
 * wincert.h - types and headers to iterate the certificates in authenticode
 *             signatures
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef PESIGN_WINCERT_H
#define PESIGN_WINCERT_H 1

#include <efisec.h>

typedef struct cert_iter {
	Pe *pe;
	size_t n;
	void *certs;
	size_t size;
} cert_iter;

extern int cert_iter_init(cert_iter *iter, Pe *pe);
extern int next_cert(cert_iter *iter, void **cert, ssize_t *cert_size);
extern ssize_t available_cert_space(Pe *pe);
extern ssize_t calculate_signature_space(cms_context *cms, Pe *pe);
extern int parse_signatures(SECItem ***sigs, int *num_sigs, Pe *pe);
extern int finalize_signatures(SECItem **sigs, int num_sigs, Pe *pe);
extern size_t get_reserved_sig_space(cms_context *cms, Pe *pe);
extern ssize_t get_sigspace_extend_amount(cms_context *cms, Pe *pe, SECItem *sig);

#endif /* PESIGN_WINCERT_H */
