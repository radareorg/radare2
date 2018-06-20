#ifndef R_ASN1_INTERNAL_H
#define R_ASN1_INTERNAL_H

R_API ut32 r_asn1_count_objects (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_create_string (const char *string, bool allocated, ut32 length);
R_API RASN1String *r_asn1_create_string2 (const char *string, bool allocated);
R_API RASN1String *r_asn1_concatenate_strings (RASN1String* s0, RASN1String* s1, bool freestr);

#endif /* R_ASN1_INTERNAL_H */

