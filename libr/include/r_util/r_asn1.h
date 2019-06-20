#ifndef R_ASN1_H
#define R_ASN1_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ASN1_JSON_NULL  "null"
#define ASN1_JSON_EMPTY "{}"

#define ASN1_OID_LEN  64

/* Masks */
#define ASN1_CLASS    0xC0 /* Bits 8 and 7 */
#define ASN1_FORM     0x20 /* Bit 6 */
#define ASN1_TAG      0x1F /* Bits 5 - 1 */
#define ASN1_LENLONG  0x80 /* long form */
#define ASN1_LENSHORT 0x7F /* Bits 7 - 1 */

/* Classes */
#define CLASS_UNIVERSAL    0x00 /* 0 = Universal (defined by ITU X.680) */
#define CLASS_APPLICATION  0x40 /* 1 = Application */
#define CLASS_CONTEXT      0x80 /* 2 = Context-specific */
#define CLASS_PRIVATE      0xC0 /* 3 = Private */

/* Forms */
#define FORM_PRIMITIVE     0x00 /* 0 = primitive */
#define FORM_CONSTRUCTED   0x20 /* 1 = constructed */

/* Tags */
#define TAG_EOC             0x00 /*  0: End-of-contents octets */
#define TAG_BOOLEAN         0x01 /*  1: Boolean */
#define TAG_INTEGER         0x02 /*  2: Integer */
#define TAG_BITSTRING       0x03 /*  2: Bit string */
#define TAG_OCTETSTRING     0x04 /*  4: Byte string */
#define TAG_NULL            0x05 /*  5: NULL */
#define TAG_OID             0x06 /*  6: Object Identifier */
#define TAG_OBJDESCRIPTOR   0x07 /*  7: Object Descriptor */
#define TAG_EXTERNAL        0x08 /*  8: External */
#define TAG_REAL            0x09 /*  9: Real */
#define TAG_ENUMERATED      0x0A /* 10: Enumerated */
#define TAG_EMBEDDED_PDV    0x0B /* 11: Embedded Presentation Data Value */
#define TAG_UTF8STRING      0x0C /* 12: UTF8 string */
#define TAG_SEQUENCE        0x10 /* 16: Sequence/sequence of */
#define TAG_SET             0x11 /* 17: Set/set of */
#define TAG_NUMERICSTRING   0x12 /* 18: Numeric string */
#define TAG_PRINTABLESTRING 0x13 /* 19: Printable string (ASCII subset) */
#define TAG_T61STRING       0x14 /* 20: T61/Teletex string */
#define TAG_VIDEOTEXSTRING  0x15 /* 21: Videotex string */
#define TAG_IA5STRING       0x16 /* 22: IA5/ASCII string */
#define TAG_UTCTIME         0x17 /* 23: UTC time */
#define TAG_GENERALIZEDTIME 0x18 /* 24: Generalized time */
#define TAG_GRAPHICSTRING   0x19 /* 25: Graphic string */
#define TAG_VISIBLESTRING   0x1A /* 26: Visible string (ASCII subset) */
#define TAG_GENERALSTRING   0x1B /* 27: General string */
#define TAG_UNIVERSALSTRING 0x1C /* 28: Universal string */
#define TAG_BMPSTRING       0x1E /* 30: Basic Multilingual Plane/Unicode string */

typedef struct r_asn1_string_t {
	ut32 length;
	const char *string;
	bool allocated;
} RASN1String;

typedef struct r_asn1_list_t {
	ut32 length;
	struct r_asn1_object_t **objects;
} ASN1List;

typedef struct r_asn1_bin_t {
	ut32 length;
	ut8 *binary;
} RASN1Binary;

typedef struct r_asn1_object_t {
	ut8 klass; /* class type */
	ut8 form; /* defines if contains data or objects */
	ut8 tag; /* tag type */
	const ut8 *sector; /* Sector containing data */
	ut32 length; /* Sector Length */
	ut64 offset; /* Object offset */
	ASN1List list; /* List of objects contained in the sector */
} RASN1Object;


R_API RASN1Object *r_asn1_create_object (const ut8 *buffer, ut32 length, const ut8 *start_pointer);
R_API RASN1Binary *r_asn1_create_binary (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_create_string (const char *string, bool allocated, ut32 length);
R_API RASN1String *r_asn1_stringify_bits (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_utctime (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_time (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_integer (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_string (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_bytes (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_boolean (const ut8 *buffer, ut32 length);
R_API RASN1String *r_asn1_stringify_oid (const ut8* buffer, ut32 length);

R_API void r_asn1_free_object (RASN1Object *object);
// R_API void r_asn1_print_object (RASN1Object *object, ut32 depth);
R_API char *r_asn1_to_string (RASN1Object *object, ut32 depth, RStrBuf *sb);
R_API void r_asn1_free_string (RASN1String *string);
R_API void r_asn1_free_binary (RASN1Binary *string);
R_API void asn1_setformat (int fmt);

#ifdef __cplusplus
}
#endif

#endif /* R_ASN1_H */

