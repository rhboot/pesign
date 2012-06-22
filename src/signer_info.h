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

extern int generate_spc_signer_info(SpcSignerInfo *sip, cms_context *ctx);

#endif /* SIGNER_INFO */
