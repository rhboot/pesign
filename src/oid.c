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

#include "fix_coverity.h"

#include <stdint.h>
#include <syslog.h>

#include <prerror.h>
#include <seccomon.h>
#include <secitem.h>
#include <secoid.h>

#include "pesign.h"

static uint8_t oiddata[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0b,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0f,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x15,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01,
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x92, 0x08, 0x10, 0x01, 0x02,
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
	OID(SPC_INDIRECT_DATA_OBJID, "Indirect Data", siDEROID, 10,
		&oiddata[0]),
	OID(SPC_STATEMENT_TYPE_OBJID, "Statement Type", siDEROID, 10,
		&oiddata[10]),
	OID(SPC_PE_IMAGE_DATA_OBJID, "PE Image Data", siDEROID, 10,
		&oiddata[20]),
	OID(SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID, "Individual Key", siDEROID,
		10, &oiddata[30]),
	OID(szOID_CERTSRV_CA_VERSION, "Certification server CA version",
		siAsciiString, 9, &oiddata[40]),
	OID(SHIM_EKU_MODULE_SIGNING_ONLY,
		"Certificate is used for kernel modules only", siDEROID, 10,
		&oiddata[49]),
	{ .oid = END_OID_LIST }
};

#undef OID

SECStatus
register_oids(cms_context *cms)
{
	for (int i = 0; oids[i].oid != END_OID_LIST; i++) {
		SECOidTag rc;
		rc = SECOID_AddEntry(&oids[i].sod);
		oids[i].sod.offset = rc;
		if (rc == SEC_OID_UNKNOWN) {
			cms->log(cms, LOG_ERR, "SECOid_AddEntry() failed: %s",
				PORT_ErrorToString(PORT_GetError()));
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
