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
#ifndef PESIGN_UTIL_H
#define PESIGN_UTIL_H 1

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#define xfree(x) ({if (x) { free(x); x = NULL; }})

#define save_errno(x)					\
	({						\
		typeof (errno) __saved_errno = errno;	\
		x;					\
		errno = __saved_errno;			\
	})

static inline int
__attribute__ ((unused))
read_file(int fd, char **bufp, size_t *lenptr) {
    int alloced = 0, size = 0, i = 0;
    char * buf = NULL;

    do {
	size += i;
	if ((size + 1024) > alloced) {
	    alloced += 4096;
	    buf = realloc(buf, alloced + 1);
	}
    } while ((i = read(fd, buf + size, 1024)) > 0);

    if (i < 0) {
        free(buf);
	return -1;
    }

    *bufp = buf;
    *lenptr = size;

    return 0;
}

static int
compare_shdrs (const void *a, const void *b)
{
	const struct section_header *shdra = (const struct section_header *)a;
	const struct section_header *shdrb = (const struct section_header *)b;
	int rc;

	if (shdra->data_addr > shdrb->data_addr)
		return 1;
	if (shdrb->data_addr > shdra->data_addr)
		return -1;

	if (shdra->virtual_address > shdrb->virtual_address)
		return 1;
	if (shdrb->virtual_address > shdra->virtual_address)
		return -1;

	rc = strcmp(shdra->name, shdrb->name);
	if (rc != 0)
		return rc;

	if (shdra->virtual_size > shdrb->virtual_size)
		return 1;
	if (shdrb->virtual_size > shdra->virtual_size)
		return -1;

	if (shdra->raw_data_size > shdrb->raw_data_size)
		return 1;
	if (shdrb->raw_data_size > shdra->raw_data_size)
		return -1;

	return 0;
}

static void
__attribute__ ((unused))
sort_shdrs (struct section_header *shdrs, size_t sections)
{
	qsort(shdrs, sections, sizeof(*shdrs), compare_shdrs);
}

static void
__attribute__ ((unused))
free_poison(void  *addrv, ssize_t len)
{
	uint8_t *addr = addrv;
	char poison_pills[] = "\xa5\x5a";
	for (int x = 0; x < len; x++)
		addr[x] = poison_pills[x % 2];
}

#if defined(DAEMON_H)
static inline uint32_t
__attribute__ ((unused))
pesignd_string_size(char *buffer)
{
	pesignd_string *s;
	return sizeof(s->size) + (buffer ? strlen(buffer) : 0) + 1;
}

static inline void
__attribute__ ((unused))
pesignd_string_set(pesignd_string *str, char *value)
{
	str->size = (value ? strlen(value) : 0) + 1;
	if (value)
		strcpy((char *)str->value, value);
	else
		str->value[0] = '\0';
}

static inline pesignd_string *
__attribute__ ((unused))
pesignd_string_next(pesignd_string *str)
{
	char *buffer = (char *)str;
	buffer += sizeof(str->size) + str->size;
	return (pesignd_string *)buffer;
}
#endif /* defined(DAEMON_H) */

#endif /* PESIGN_UTIL_H */
