// SPDX-License-Identifier: GPLv2
/*
 * ucs2.h - helpers for 16-bit unicode
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef UCS2_H
#define UCS2_H 1

extern size_t ucs2_strlen(const uint16_t *s);
extern uint16_t *ucs2_strdup(const uint16_t *s);
extern uint16_t *ascii_to_ucs2(const char *s);

#endif /* UCS2_H */
