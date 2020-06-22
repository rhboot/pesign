// SPDX-License-Identifier: GPLv2
/*
 * text.c - helpers for text strings
 * Copyright Peter Jones <pjones@redhat.com>
 */
#ifndef TEXT_H_
#define TEXT_H_

#include <unistd.h>

/*
 * Characters that can be considered whitespace or end-of-line markers.
 */
extern const char * const eol_chars;
extern const char * const whitespace_and_eol_chars;

/*
 * unbreak_line_coninutations: remove all line continuations
 * @buf:	the buffer to operate on
 * @bufsz:	the size of the buffer
 */
extern void unbreak_line_continuations(char *buf, size_t bufsz);

/*
 * strescspn:	calculate the size of an escape sequence.
 * @buf:	a NUL-terminated utf-8 buffer.
 *
 * returns the number of bytes which are part of a single escape sequence.
 * If no escape sequnce can be parsed, returns 0.
 */
extern size_t strescspn(const char * const buf);

/*
 * stresccspn:	calculate the number of bytes which do not contain escape
 *		sequences.
 * @buf:	the buffer to search
 *
 * Returns the size of the initial segment of buf which does not contain
 * any escape sequences.  If no escape sequence is found, buf[return] will
 * point to the NUL terminator.
 */
extern size_t stresccspn(const char * const buf);

/*
 * resolve_escapes: parse all instances of escape sequences in buf
 * @buf:	the buffer to operate on
 *
 * Returns the size of buf once escape sequnces have been replaced.
 */
extern size_t resolve_escapes(char *buf);

#endif /* !TEXT_H_ */
// vim:fenc=utf-8:tw=75:noet
