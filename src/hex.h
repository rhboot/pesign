// SPDX-License-Identifier: GPLv2
/*
 * hex.h - hexidecimal conversion helpers
 * Copyright Peter Jones <pjones@redhat.com>
 */
#ifndef HEX_H_
#define HEX_H_

static inline uint8_t hexchar_to_bin(char hex)
{
	if (hex >= '0' && hex <= '9')
		return hex - '0';
	if (hex >= 'A' && hex <= 'F')
		return hex - 'A' + 10;
	if (hex >= 'a' && hex <= 'f')
		return hex - 'a' + 10;
	return -1;
}

static inline int
hex_to_bin(const char *hex, uint8_t *out, size_t size)
{
	for (size_t i = 0, j = 0; j < size; i+= 2, j++) {
		uint8_t val;

		val = hexchar_to_bin(hex[i]);
		if (val > 15)
			goto out_of_range;
		out[j] = (val & 0xf) << 4;

		val = hexchar_to_bin(hex[i+1]);
		if (val > 15)
			goto out_of_range;
		out[j] |= val & 0xf;
	}

	errno = 0;
	return 0;
out_of_range:
	errno = ERANGE;
	return -1;
}

#endif /* !HEX_H_ */
// vim:fenc=utf-8:tw=75:noet
