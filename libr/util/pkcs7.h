#ifndef R_PKCS7_INTERNAL_H
#define R_PKCS7_INTERNAL_H


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

R_API char* r_x509_signedinfo_dump (RPKCS7SignerInfo *si, char* buffer, ut32 length, const char* pad);

#endif /* R_PKCS7_INTERNAL_H */

