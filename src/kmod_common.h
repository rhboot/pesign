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

#ifndef KMOD_COMMON_H
#define KMOD_COMMON_H 1

#include <stdint.h>
#include "pesign_context.h"

int kmod_generate_digest(cms_context *cms, unsigned char *addr, size_t len);
ssize_t kmod_write_signature(cms_context *cms, int outfd);
int kmod_write_sig_info(cms_context *cms, int fd, uint32_t sig_len);

#endif

