/*
 * Copyright 2011 Red Hat, Inc.
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
#ifndef PESIGN_H
#define PESIGN_H 1

#include <stdlib.h>
#define xfree(x) ({if (x) { free(x); x = NULL; }})

#include <libdpe/libdpe.h>
#include <libdpe/pe.h>
#include "util.h"
#include "context.h"
#include "actions.h"
#include "endian.h"
#include "oid.h"
#include "wincert.h"

#include "cms_common.h"
#include "content_info.h"
#include "signer_info.h"
#include "signed_data.h"

#endif /* PESIGN_H */
