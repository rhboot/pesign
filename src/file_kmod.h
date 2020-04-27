// SPDX-License-Identifier: GPLv2
/*
 * file_kmod.h - decls for our kmod file type helpers.
 * Copyright 2017 Endless Mobile, Inc.
 *
 * Author(s): Daniel Drake <drake@endlessm.com>
 */
#ifndef KMOD_COMMON_H
#define KMOD_COMMON_H 1

#include <stdint.h>
#include "pesign_context.h"

int kmod_generate_digest(cms_context *cms, unsigned char *addr, size_t len);
ssize_t kmod_write_signature(cms_context *cms, int outfd);
int kmod_write_sig_info(cms_context *cms, int fd, uint32_t sig_len);

#endif

