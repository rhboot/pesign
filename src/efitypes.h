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
#ifndef EFI_TYPES_H
#define EFI_TYPES_H 1

#include <efivar.h>

typedef unsigned long efi_status_t;
typedef uint16_t efi_char16_t;

typedef struct {
	uint16_t	year;
	uint8_t		month;
	uint8_t		day;
	uint8_t		hour;
	uint8_t		minute;
	uint8_t		second;
	uint8_t		pad1;
	uint32_t	nanosecond;
	int16_t		timezone;
	uint8_t		daylight;
	uint8_t		pad2;
} efi_time_t;

struct efi_variable {
	efi_char16_t *VariableName;
	efi_guid_t VendorGuid;
	unsigned long DataSize;
	uint8_t *Data;
	efi_status_t Status;
	uint32_t Attributes;
};

#define EFI_VARIABLE_NON_VOLATILE	0x0000000000000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS	0x0000000000000002
#define EFI_VARIABLE_RUNTIME_ACCESS	0x0000000000000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD	0x0000000000000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS	0x0000000000000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x0000000000000020
#define EFI_VARIABLE_APPEND_WRITE	0x0000000000000040

#define EFI_GLOBAL_PLATFORM_KEY L"PK"
#define EFI_GLOBAL_KEY_EXCHANGE_KEY L"KEK"
#define EFI_IMAGE_SECURITY_DATABASE L"db"
#define EFI_IMAGE_SECURITY_DATABASE1 L"dbx"

#endif /* EFI_TYPES_H */
