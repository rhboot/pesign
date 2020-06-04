// SPDX-License-Identifier: GPLv2
/*
 * oid.h - helpers for OID usage
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef OID_H
#define OID_H 1

typedef enum {
	SPC_INDIRECT_DATA_OBJID,		/* 1.3.6.1.4.1.311.2.1.4 */
	SPC_STATEMENT_TYPE_OBJID,		/* 1.3.6.1.4.1.311.2.1.11 */
	SPC_PE_IMAGE_DATA_OBJID,		/* 1.3.6.1.4.1.311.2.1.15 */
	SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID,	/* 1.3.6.1.4.1.311.2.1.21 */
	szOID_CERTSRV_CA_VERSION,		/* 1.3.6.1.4.1.311.21.1 */
	SHIM_EKU_MODULE_SIGNING_ONLY,		/* 1.3.6.1.4.1.2312.16.1.2 */
	SPC_UEFI_SB_CA,				/* 1.3.6.1.4.1.311.80.2.1 */
	END_OID_LIST
} ms_oid_t;

extern SECStatus register_oids(cms_context *cms);
extern SECOidTag find_ms_oid_tag(ms_oid_t moid);
extern int get_ms_oid_secitem(ms_oid_t moid, SECItem *si);

#endif /* OID_H */
