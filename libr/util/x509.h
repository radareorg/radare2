#ifndef R_X509_INTERNAL_H
#define R_X509_INTERNAL_H

#include "asn1.h"

R_API bool r_x509_parse_validity (RX509Validity *validity, RASN1Object *object);
R_API void r_x509_free_validity (RX509Validity* validity);

R_API bool r_x509_parse_algorithmidentifier (RX509AlgorithmIdentifier *ai, RASN1Object * object);
R_API void r_x509_free_algorithmidentifier (RX509AlgorithmIdentifier * ai);

R_API bool r_x509_parse_subjectpublickeyinfo (RX509SubjectPublicKeyInfo * spki, RASN1Object *object);
R_API void r_x509_free_subjectpublickeyinfo (RX509SubjectPublicKeyInfo * spki);

R_API bool r_x509_parse_name (RX509Name *name, RASN1Object * object);
R_API void r_x509_free_name (RX509Name * name);

R_API bool r_x509_parse_extension (RX509Extension *ext, RASN1Object * object);
R_API void r_x509_free_extension (RX509Extension * ex);

R_API bool r_x509_parse_extensions (RX509Extensions *ext, RASN1Object * object);
R_API void r_x509_free_extensions (RX509Extensions* ex);

R_API bool r_x509_parse_tbscertificate (RX509TBSCertificate *tbsc, RASN1Object * object);
R_API void r_x509_free_tbscertificate (RX509TBSCertificate * tbsc);

R_API RX509CRLEntry *r_x509_parse_crlentry (RASN1Object *object);
R_API void r_x509_free_crlentry (RX509CRLEntry *entry);

R_API char* r_x509_validity_dump (RX509Validity* validity, char* buffer, ut32 length, const char* pad);
R_API char* r_x509_name_dump (RX509Name* name, char* buffer, ut32 length, const char* pad);
R_API char* r_x509_subjectpublickeyinfo_dump (RX509SubjectPublicKeyInfo* spki, char* buffer, ut32 length, const char* pad);
R_API char* r_x509_extensions_dump (RX509Extensions* exts, char* buffer, ut32 length, const char* pad);
R_API char* r_x509_tbscertificate_dump (RX509TBSCertificate* tbsc, char* buffer, ut32 length, const char* pad);
R_API char* r_x509_crlentry_dump (RX509CRLEntry *crle, char* buffer, ut32 length, const char* pad);

#endif /* R_X509_INTERNAL_H */

