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

#include <nss3/seccomon.h>
#include <nss3/secitem.h>
#include <nss3/secoid.h>
#include <nss3/cms.h>

#include "oid.h"

static uint8_t oiddata[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0c,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01,
};

#define OID(num, desc_s, oidtype, length, value)		\
	{ num, .sod = {						\
		.desc = desc_s, .oid = {			\
			.type = oidtype,			\
			.data = value,				\
			.len = length }				\
		}						\
	}

static struct {
	ms_oid_t oid;
	SECOidData sod;
} oids[] = {
	OID(SPC_INDIRECT_DATA_OBJID, "Indirect Data", siBuffer, 10,
		&oiddata[0]),
	OID(SPC_STATEMENT_TYPE_OBJID, "Statement Type", siBuffer, 10,
		&oiddata[10]),
	OID(SPC_SP_OPUS_INFO_OBJID, "Opus Info", siBuffer, 10, &oiddata[20]),
	OID(SPC_PE_IMAGE_DATA_OBJID, "PE Image Data", siBuffer, 10,
		&oiddata[30]),
	OID(SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID, "Individual Key", siBuffer,
		10, &oiddata[40]),
	OID(szOID_CERTSRV_CA_VERSION, "Certification server CA version",
		siAsciiString, 9, &oiddata[50]),
	{ END_OID_LIST }
};

#undef OID

SECStatus
register_oids(void)
{
	for (int i = 0; oids[i].oid != END_OID_LIST; i++) {
		SECOidTag rc;
		rc = SECOID_AddEntry(&oids[i].sod);
		oids[i].sod.offset = rc;
		if (rc == SEC_OID_UNKNOWN) {
			printf("SECOid_AddEntry() failed\n");
			return SECFailure;
		}
	}
	return SECSuccess;
}

SECOidTag
find_ms_oid_tag(ms_oid_t moid)
{
	if (moid >= END_OID_LIST || moid < 0)
		return SEC_OID_UNKNOWN;

	return oids[moid].sod.offset;
}

int get_ms_oid_secitem(ms_oid_t moid, SECItem *si)
{
	if (moid >= END_OID_LIST || moid < 0)
		return -1;
	memcpy(si, &oids[moid].sod.oid, sizeof (*si));

	return 0;
}
