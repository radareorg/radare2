#ifndef R_PKCS7_H
#define R_PKCS7_H

typedef struct r_pkcs7_certificaterevocationlists_t {
	ut32 length;
	RX509CertificateRevocationList **elements;
} RPKCS7CertificateRevocationLists;

typedef struct r_pkcs7_extendedcertificatesandcertificates_t {
	ut32 length;
	RX509Certificate **elements;
} RPKCS7ExtendedCertificatesAndCertificates;

typedef struct r_pkcs7_digestalgorithmidentifiers_t {
	ut32 length;
	RX509AlgorithmIdentifier **elements;
} RPKCS7DigestAlgorithmIdentifiers;

typedef struct r_pkcs7_contentinfo_t {
	RASN1String *contentType; //OID
	RASN1Object *content; // optional. oid structure definition
} RPKCS7ContentInfo;

typedef struct r_pkcs7_issuerandserialnumber_t {
	RX509Name issuer;
	RASN1Object *serialNumber;
} RPKCS7IssuerAndSerialNumber;

typedef struct r_pkcs7_attribute_t {
	RASN1String *oid; //OID
	RASN1Object *data; // optional. oid structure definition
} RPKCS7Attribute;

typedef struct r_pkcs7_attributes_t {
	ut32 length;
	RPKCS7Attribute **elements;
} RPKCS7Attributes;

typedef struct r_pkcs7_signerinfo_t {
	ut32 version;
	RPKCS7IssuerAndSerialNumber issuerAndSerialNumber;
	RX509AlgorithmIdentifier digestAlgorithm;
	RPKCS7Attributes authenticatedAttributes; //Optional
	RX509AlgorithmIdentifier digestEncryptionAlgorithm;
	RASN1Object *encryptedDigest;
	RPKCS7Attributes unauthenticatedAttributes; //Optional
} RPKCS7SignerInfo;

typedef struct r_pkcs7_signerinfos_t {
	ut32 length;
	RPKCS7SignerInfo **elements;
} RPKCS7SignerInfos;

typedef struct r_pkcs7_signeddata_t {
	ut32 version;
	RPKCS7DigestAlgorithmIdentifiers digestAlgorithms;
	RPKCS7ContentInfo contentInfo;
	RPKCS7ExtendedCertificatesAndCertificates certificates; //Optional
	RPKCS7CertificateRevocationLists crls; //Optional
	RPKCS7SignerInfos signerinfos;
} RPKCS7SignedData;

typedef struct r_pkcs7_container_t {
	RASN1String *contentType;
	RPKCS7SignedData signedData;
} RPKCS7Container;

R_API bool r_pkcs7_parse_certificaterevocationlists (RPKCS7CertificateRevocationLists *crls, RASN1Object *object);
R_API void r_pkcs7_free_certificaterevocationlists (RPKCS7CertificateRevocationLists *crls);

R_API bool r_pkcs7_parse_extendedcertificatesandcertificates (RPKCS7ExtendedCertificatesAndCertificates *ecac, RASN1Object *object);
R_API void r_pkcs7_free_extendedcertificatesandcertificates (RPKCS7ExtendedCertificatesAndCertificates *ecac);

R_API bool r_pkcs7_parse_digestalgorithmidentifier (RPKCS7DigestAlgorithmIdentifiers *dai, RASN1Object *object);
R_API void r_pkcs7_free_digestalgorithmidentifier (RPKCS7DigestAlgorithmIdentifiers *dai);

R_API bool r_pkcs7_parse_contentinfo (RPKCS7ContentInfo* ci, RASN1Object *object);
R_API void r_pkcs7_free_contentinfo (RPKCS7ContentInfo* ci);

R_API bool r_pkcs7_parse_issuerandserialnumber (RPKCS7IssuerAndSerialNumber* iasu, RASN1Object *object);
R_API void r_pkcs7_free_issuerandserialnumber (RPKCS7IssuerAndSerialNumber* iasu);

R_API RPKCS7Attribute* r_pkcs7_parse_attribute (RASN1Object *object);
R_API void r_pkcs7_free_attribute (RPKCS7Attribute* attribute);

R_API bool r_pkcs7_parse_attributes (RPKCS7Attributes* attribute, RASN1Object *object);
R_API void r_pkcs7_free_attributes (RPKCS7Attributes* attribute);

R_API bool r_pkcs7_parse_signerinfo (RPKCS7SignerInfo* si, RASN1Object *object);
R_API void r_pkcs7_free_signerinfo (RPKCS7SignerInfo* si);

R_API bool r_pkcs7_parse_signerinfos (RPKCS7SignerInfos* ss, RASN1Object *object);
R_API void r_pkcs7_free_signerinfos (RPKCS7SignerInfos* ss);

R_API bool r_pkcs7_parse_signeddata (RPKCS7SignedData *sd, RASN1Object *object);
R_API void r_pkcs7_free_signeddata (RPKCS7SignedData* sd);

R_API RPKCS7Container *r_pkcs7_parse_container (const ut8 *buffer, ut32 length);
R_API void r_pkcs7_free_container (RPKCS7Container* container);
char* r_pkcs7_generate_string (RPKCS7Container* container);

#endif /* R_PKCS7_H */

