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
#ifndef OID_H
#define OID_H 1

typedef enum {
	SPC_INDIRECT_DATA_OBJID,		/* 1.3.6.1.4.1.311.2.1.4 */
	SPC_STATEMENT_TYPE_OBJID,		/* 1.3.6.1.4.1.311.2.1.11 */
	SPC_SP_OPUS_INFO_OBJID,			/* 1.3.6.1.4.1.311.2.1.12 */
	SPC_PE_IMAGE_DATA_OBJID,		/* 1.3.6.1.4.1.311.2.1.15 */
	SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID,	/* 1.3.6.1.4.1.311.2.1.21 */
	szOID_CERTSRV_CA_VERSION,		/* 1.3.6.1.4.1.311.21.1 */
	END_OID_LIST
} ms_oid_t;

extern SECStatus register_oids(void);
extern SECOidTag find_ms_oid_tag(ms_oid_t moid);

#endif /* OID_H */
