// SPDX-License-Identifier: GPLv2
/*
 * text.c - helpers for text strings
 * Copyright Peter Jones <pjones@redhat.com>
 */
#include "compiler.h"
#include "text.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

const char * const eol_chars = "\f\r\v\n";
// static const char * const whitespace_chars = "\t ";
const char * const whitespace_and_eol_chars = "\t \f\r\v\n";

// static const char * const binary_digits = "01";
static const char * const octal_digits = "01234567";
// static const char * const decimal_digits = "0123456789";
static const char * const hex_digits = "0123456789abcdefABCDEF";

static const char * const cnt_nl = "\\\n";
static const char * const cnt_lfnl = "\\\r\n";
static const char * const cnt_lf = "\\\r";
static const char * const cnt_ff = "\\\f";
static const char * const cnt_vt = "\\\v";

static const char * const line_continuation_strs[] = {
	cnt_nl,
	cnt_lfnl,
	cnt_lf,
	cnt_ff,
	cnt_vt,
	NULL
};

/*
 * unbreak_line_coninutations: remove all line continuations
 * @buf:	the buffer to operate on
 * @bufsz:	the size of the buffer
 */
void
unbreak_line_continuations(char *buf, size_t bufsz)
{
	char *to = buf;
	bool found = true;

	while (found) {
		found = false;

		for (unsigned int i = 0; line_continuation_strs[i]; i++) {
			size_t cntsz = strlen(line_continuation_strs[i]);
			char *needle = strstr(to, line_continuation_strs[i]);
			char *from;
			size_t sz;

			if (!needle)
				continue;

			found = true;
			from = needle + cntsz;
			sz = bufsz - (from - buf);

			to = needle;
			memmove(to, from, sz);
		}
	}
}

/*
 * stresccspn:	calculate the number of bytes which do not contain escape
 *		sequences.
 * @buf:	the buffer to search
 *
 * Returns the size of the initial segment of buf which does not contain
 * any escape sequences.  If no escape sequence is found, buf[return] will
 * point to the NUL terminator.
 */
size_t stresccspn(const char * const buf)
{
	size_t span = strcspn(buf, "\\");

	return span;
}

/*
 * escape_func: parse the value for one single escape character
 * @delimiter:	the delimiter as to which kind of escape sequence this is
 *		(i.e. 'x' for \x1abc)
 * @buf:	the buffer being parsed
 * @val:	the parsed value is placed in val
 * @valsz:	how many bytes of val are meaningful
 *
 * Returns the number of bytes of buf to advance to skip the escape
 * sequence, including the delimiter character but not the initial escape
 * character.  If the initial segment of buf is not an escape sequence,
 * *valsz and the return value will both be 0.
 */
typedef size_t (*escape_func)(uint32_t delimiter, const char * const buf,
			      char val[9], size_t *valsz);

static size_t
simple_escape_sequence(uint32_t delimiter, const char * const buf UNUSED,
		       char val[9], size_t *valsz)
{
	val[0] = delimiter & 0xffu;
	*valsz = 1;

	return 1;
}

static size_t
digits_escape_sequence(uint32_t delimiter, const char * const buf,
		       char val[2], size_t *valsz)
{
	size_t span;
	unsigned long long ul;
	char tmpbuf[4] = { 0, };
	int base;

	if (delimiter == 'x') {
		span = strspn(buf, hex_digits);
		base = 16;
		if (span > 2)
			span = 2;
		strncpy(tmpbuf, buf, span);
	} else {
		span = strspn(buf, octal_digits);
		base = 8;
		if (span > 2)
			span = 2;
		tmpbuf[0] = delimiter & 0xffu;
		strncpy(&tmpbuf[1], buf, span);
		span += 1;
	}
	if (span == 0) {
		val[0] = delimiter & 0xffu;
		*valsz = 1;
		return 1;
	}

	tmpbuf[span+1] = '\0';
	ul = strtoul(tmpbuf, NULL, base);

	val[0] = ul & 0xffu;
	*valsz = 1;

	return span;
}

struct escape_handler {
	const char * const escapes;
	escape_func func;
};
static struct escape_handler escape_handlers[] = {
	{.escapes = " \"\'\?\a\b\f\n\r\t\v\\",
	 .func = simple_escape_sequence },
	{.escapes = "x01234567",
	 .func = digits_escape_sequence },
	{.escapes = 0,
	 .func = NULL }
};

/*
 * parse_escape: parses one escape string
 * @buf:	the buffer being parsed
 * @val:	the parsed value is placed in val
 * @valsz:	how many bytes of val are meaningful
 *
 * Returns the number of bytes of buf to advance to skip the escape
 * sequence.  If the initial segment of buf is not an escape sequence,
 * *valsz and the return value will both be 0.
 */
static size_t
parse_escape(const char * const buf, char val[9], size_t *valsz)
{
	struct escape_handler *eh = NULL;

	if (buf[0] != '\\')
		return 0;

	for(size_t i = 0; escape_handlers[i].escapes != 0; i++) {
		char *match;
		eh = &escape_handlers[i];

		match = strchrnul(eh->escapes, buf[1]);
		if (match[0] != buf[1])
			continue;
	}
	if (eh && eh->func)
		return eh->func(buf[1], &buf[2], val, valsz);
	return 0;
}

/*
 * strescspn:	calculate the size of an escape sequence.
 * @buf:	a NUL-terminated utf-8 buffer.
 *
 * returns the number of bytes which are part of a single escape sequence.
 * If no escape sequnce can be parsed, returns 0.
 */
size_t strescspn(const char * const buf)
{
	size_t advance = 0, valsz = 0;
	char val[9] = { 0, };

	if (!buf[0] || buf[0] != '\\')
		return 0;

	advance = parse_escape(&buf[1], val, &valsz);
	if (advance == 0) {
		/*
		 * If we come to illegal escape values like "\\xzz" then
		 * we just use the delimiter character (in this case 'x'),
		 * so the span here is 2.
		 */
		return 2;
	}
	return valsz + 1;
}

/*
 * resolve_escapes: parse all instances of escape sequences in buf
 * @buf:	the buffer to operate on
 *
 * Returns the size of buf once escape sequnces have been replaced.
 */
size_t
resolve_escapes(char *buf)
{
	size_t to = 0;
	for (size_t from = 0; buf[from]; from++) {
		size_t advance, valsz = 0;
		char val[9];
		if (buf[from] != '\\') {
			buf[to++] = buf[from];
			continue;
		}

		advance = parse_escape(&buf[from], val, &valsz);
		if (advance == 0) {
			/*
			 * If we come to illegal escape values like "\\xzz"
			 * then just move the '\\' out of the way...
			 */
			buf[to++] = buf[++from];
			continue;
		}

		for (size_t j = 0; j < valsz; j++)
			buf[to+j] = val[j];
		to += advance + 1;
	}
	buf[to++] = '\0';
	return to;
}

// vim:fenc=utf-8:tw=75:noet
