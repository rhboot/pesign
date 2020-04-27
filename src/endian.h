// SPDX-License-Identifier: GPLv2
/*
 * endian.h - endian swizzling helpers
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef ENDIAN_H
#define ENDIAN_H

#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le16(x) (x)
#define cpu_to_le32(x) (x)
#define cpu_to_le64(x) (x)
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_be16(x) __builtin_bswap16(x)
#define cpu_to_be32(x) __builtin_bswap32(x)
#define cpu_to_be64(x) __builtin_bswap64(x)
#define be16_to_cpu(x) __builtin_bswap16(x)
#define be32_to_cpu(x) __builtin_bswap32(x)
#define be64_to_cpu(x) __builtin_bswap64(x)
#else
#define cpu_to_be16(x) (x)
#define cpu_to_be32(x) (x)
#define cpu_to_be64(x) (x)
#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#define be64_to_cpu(x) (x)
#define cpu_to_le16(x) __builtin_bswap16(x)
#define cpu_to_le32(x) __builtin_bswap32(x)
#define cpu_to_le64(x) __builtin_bswap64(x)
#define le16_to_cpu(x) __builtin_bswap16(x)
#define le32_to_cpu(x) __builtin_bswap32(x)
#define le64_to_cpu(x) __builtin_bswap64(x)
#endif

#endif /* ENDIAN_H */
/* vim:set shiftwidth=8 softtabstop=8: */
