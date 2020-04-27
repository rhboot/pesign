// SPDX-License-Identifier: GPLv2
/*
 * signer_info.h - types and decls to implement the authenticode
 *                 signer_info structure
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#ifndef SIGNER_INFO
#define SIGNER_INFO 1

typedef struct {
	SECItem issuer;
	SECItem serial;
} IssuerAndSerialNumber;
extern SEC_ASN1Template IssuerAndSerialNumberTemplate[];

enum SignerType {
	signerTypeIssuerAndSerialNumber = 1,
	signerTypeSubjectKeyIdentifier = 2,
};

typedef struct {
	int signerType; /* actually the enum above, but enum ABI ew. */
	struct {
		IssuerAndSerialNumber iasn;
		SECItem subjectKeyID;
	} signerValue;
} SignerIdentifier;
extern SEC_ASN1Template SignerIdentifierTemplate[];

typedef struct {
	SECItem attrType;
	SECItem **attrValues;
} Attribute;
extern SEC_ASN1Template AttributeTemplate[];

typedef struct {
	SECItem attributes;
} AttributeSet;
extern SEC_ASN1Template AttributeSetTemplate[];

typedef struct {
	SECItem CMSVersion;
	SignerIdentifier sid;
	SECAlgorithmID digestAlgorithm;
	SECItem signedAttrs;
	SECAlgorithmID signatureAlgorithm;
	SECItem signature;
	SECItem unsignedAttrs;
} SpcSignerInfo;
extern SEC_ASN1Template SpcSignerInfoTemplate[];

extern int generate_signed_attributes(cms_context *cms, SECItem *sattrs);
extern int generate_spc_signer_info(cms_context *cms, SpcSignerInfo *sip);
extern int generate_authvar_signer_info(cms_context *cms, SpcSignerInfo *sip);

#endif /* SIGNER_INFO */
