#ifndef R_X509_H
#define R_X509_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Following RFC 5280 
 */

typedef struct r_x509_validity_t {
	RASN1String *notBefore;
	RASN1String *notAfter;
} RX509Validity;

typedef struct r_x509_name_t {
	ut32 length;
	RASN1String **oids;
	RASN1String **names;
} RX509Name;

typedef struct r_x509_algorithmidentifier_t {
	RASN1String *algorithm; // OBJECT IDENTIFIER
	RASN1String *parameters; // OPTIONAL
} RX509AlgorithmIdentifier;

/*
//SubjectKeyIdentifier OCTET STRING so it should be an ASN1Object

typedef struct r_x509_keyusage_t {
	ut8 digitalSignature : 1;
	ut8 contentCommitment : 1;
	ut8 keyEncipherment : 1;
	ut8 dataEncipherment : 1;
	ut8 keyAgreement : 1;
	ut8 keyCertSign : 1;
	ut8 cRLSign : 1;
	ut8 encipherOnly : 1;
	ut8 decipherOnly : 1;
} X509KeyUsage;
 */

typedef struct r_x509_authoritykeyidentifier_t {
	RASN1Binary *keyIdentifier;
	RX509Name authorityCertIssuer;
	RASN1Binary *authorityCertSerialNumber;
} RX509AuthorityKeyIdentifier;

typedef struct r_x509_subjectpublickeyinfo_t {
	RX509AlgorithmIdentifier algorithm;
	//This is a bit string, but it encapsulate mod + pubkey
	RASN1Binary *subjectPublicKey; // BIT STRING
	//This struct won't follow RFC,
	//just because it should be seen as this.
	RASN1Binary *subjectPublicKeyExponent;
	RASN1Binary *subjectPublicKeyModule;
} RX509SubjectPublicKeyInfo;

typedef struct r_x509_extension_t {
	RASN1String *extnID; // OBJECT IDENTIFIER
	bool critical;
	RASN1Binary *extnValue; // OCTET STRING
} RX509Extension;

typedef struct r_x509_extensions_t {
	ut32 length;
	RX509Extension **extensions;
} RX509Extensions;

typedef struct r_x509_tbscertificate_t {
	ut32 version; //INTEGER
	RASN1String *serialNumber; // INTEGER
	RX509AlgorithmIdentifier signature;
	RX509Name issuer;
	RX509Validity validity;
	RX509Name subject;
	RX509SubjectPublicKeyInfo subjectPublicKeyInfo;
	RASN1Binary *issuerUniqueID; // BIT STRING
	RASN1Binary *subjectUniqueID; // BIT STRING
	RX509Extensions extensions;
} RX509TBSCertificate;

typedef struct r_x509_certificate_t {
	RX509TBSCertificate tbsCertificate;
	RX509AlgorithmIdentifier algorithmIdentifier;
	RASN1Binary *signature; // BIT STRING
} RX509Certificate;


// RFC 1422

typedef struct r_x509_crlentry {
	RASN1Binary *userCertificate; //INTEGER ?
	RASN1String *revocationDate; //UTCTime
} RX509CRLEntry;

typedef struct r_x509_certificaterevocationlist {
	RX509AlgorithmIdentifier signature;
	RX509Name issuer;
	RASN1String *lastUpdate; //UTCTime
	RASN1String *nextUpdate; //UTCTime
	ut32 length;
	RX509CRLEntry **revokedCertificates;
} RX509CertificateRevocationList;

R_API RX509CertificateRevocationList* r_x509_parse_crl(RASN1Object *object);
// R_API void r_x509_free_crl(RX509CertificateRevocationList *crl);
// R_API void r_x509_crl_dump(RX509CertificateRevocationList *crl, const char* pad);
R_API char *r_x509_crl_to_string(RX509CertificateRevocationList *crl, const char* pad);
R_API void r_x509_crl_json(PJ* pj, RX509CertificateRevocationList *crl);

R_API RX509Certificate *r_x509_parse_certificate(RASN1Object *object);
R_API RX509Certificate *r_x509_parse_certificate2(const ut8 *buffer, ut32 length);
R_API void r_x509_free_certificate(RX509Certificate* certificate);
R_API char *r_x509_certificate_to_string(RX509Certificate* certificate, const char* pad);
R_API void r_x509_certificate_json(PJ* pj, RX509Certificate *certificate);
R_API void r_x509_certificate_dump(RX509Certificate* cert, const char* pad, RStrBuf *sb);


#ifdef __cplusplus
}
#endif

#endif /* R_X509_H */

