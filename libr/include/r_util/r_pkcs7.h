#ifndef R_PKCS7_H
#define R_PKCS7_H

#ifdef __cplusplus
extern "C" {
#endif

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
	RASN1Binary *content; // optional. oid structure definition
} RPKCS7ContentInfo;

typedef struct r_pkcs7_issuerandserialnumber_t {
	RX509Name issuer;
	RASN1Binary *serialNumber;
} RPKCS7IssuerAndSerialNumber;

typedef struct r_pkcs7_attribute_t {
	RASN1String *oid; //OID
	RASN1Binary *data; // optional. oid structure definition
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
	RASN1Binary *encryptedDigest;
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
} RCMS;

R_API RCMS *r_pkcs7_parse_cms(const ut8 *buffer, ut32 length);
R_API void r_pkcs7_free_cms(RCMS* container);
R_API char *r_pkcs7_cms_to_string(RCMS* container);
R_API RJSVar *r_pkcs7_cms_json(RCMS* container);

#ifdef __cplusplus
}
#endif

#endif /* R_PKCS7_H */
