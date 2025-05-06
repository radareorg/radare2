#ifndef R_X509_INTERNAL_H
#define R_X509_INTERNAL_H

R_IPI bool r_x509_algorithmidentifier_parse(RX509AlgorithmIdentifier *ai, RASN1Object *object);
R_IPI void r_x509_algorithmidentifier_fini(RX509AlgorithmIdentifier *ai);

R_IPI void r_x509_subjectpublickeyinfo_fini(RX509SubjectPublicKeyInfo *spki);

R_IPI bool r_x509_name_parse(RX509Name *name, RASN1Object *object);
R_IPI void r_x509_name_fini(RX509Name *name);

R_IPI void r_x509_extension_fini(RX509Extension *ex);

R_IPI void r_x509_crl_free(RX509CertificateRevocationList * R_NULLABLE crl);
R_IPI void r_x509_name_dump(RX509Name* name, const char* pad, RStrBuf *sb);
R_IPI void r_x509_name_json(PJ *pj, RX509Name *name);
R_IPI void r_x509_crl_free(RX509CertificateRevocationList *crl);
R_IPI void r_x509_crlentry_dump(RX509CRLEntry *crle, const char *pad, RStrBuf *sb);

#endif /* R_X509_INTERNAL_H */

