/*
* Copyright 2012 Red Hat, Inc.
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
#ifndef UCS2_H
#define UCS2_H 1

extern size_t ucs2_strlen(const uint16_t *s);
extern uint16_t *ucs2_strdup(const uint16_t *s);
extern uint16_t *ascii_to_ucs2(const char *s);

#endif /* UCS2_H */
