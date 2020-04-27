// SPDX-License-Identifier: GPLv2
/*
 * endian.h - helpers for cross-endian data access
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef ENDIAN_H
#define ENDIAN_H

#include <endian.h>
#include <stdint.h>
#include <string.h>

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

static inline uint32_t UNUSED
SwapBytes32(uint32_t x)
{
	return __builtin_bswap32(x);
}

static inline int UNUSED
cmp_le16(uint16_t *ledata, uint16_t *cpudata)
{
	uint16_t tmp = le16_to_cpu(*ledata);
	return memcmp(&tmp, cpudata, sizeof(*cpudata));
}

static inline int UNUSED
cmp_le32(uint32_t *ledata, uint32_t *cpudata)
{
	uint32_t tmp = le32_to_cpu(*ledata);
	return memcmp(&tmp, cpudata, sizeof(*cpudata));
}

#endif /* ENDIAN_H */
/* vim:set shiftwidth=8 softtabstop=8: */
