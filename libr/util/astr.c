/* radare2 - LGPL - Copyright 2017-2018 - wargio, pancake */

#include <r_util.h>
#include "asn1_oids.h"

static const char* _hex = "0123456789abcdef";

R_API RASN1String *r_asn1_create_string (const char *string, bool allocated, ut32 length) {
	if (!string || !length) {
		return NULL;
	}
	RASN1String *s = R_NEW0 (RASN1String);
	if (s) {
		s->allocated = allocated;
		s->length = length;
		s->string = string;
	}
	return s;
}

static RASN1String *newstr(const char *string) {
	return r_asn1_create_string (string, false, strlen (string) + 1);
}

R_API RASN1String *r_asn1_concatenate_strings (RASN1String *s0, RASN1String *s1, bool freestr) {
	char* str;
	ut32 len;
	if (!s0 || !s1 || s0->length == 0 || s1->length == 0) {
		return NULL;
	}
	len = s0->length + s1->length - 1;
	str = (char*) malloc (len);
	if (!str) {
		if (freestr) {
			r_asn1_free_string (s0);
			r_asn1_free_string (s1);
		}
		return NULL;
	}
	memcpy (str, s0->string, s0->length);
	memcpy (str + s0->length - 1, s1->string, s1->length);
	if (freestr) {
		r_asn1_free_string (s0);
		r_asn1_free_string (s1);
	}
	RASN1String *res = r_asn1_create_string (str, true, len);
	if (!res) {
		free (str);
	}
	return res;
}

R_API RASN1String *r_asn1_stringify_string(const ut8 *buffer, ut32 length) {
	if (!buffer || length < 1) {
		return NULL;
	}
	char *str = r_str_ndup ((const char *)buffer, length);
	if (!str) {
		return NULL;
	}
	int str_len = strlen (str);
	r_str_filter (str, str_len);
	return r_asn1_create_string (str, true, str_len);
}

R_API RASN1String *r_asn1_stringify_utctime (const ut8 *buffer, ut32 length) {
	if (!buffer || length != 13 || buffer[12] != 'Z') {
		return NULL;
	}
	const int str_sz = 24;
	char *str = malloc (str_sz);
	if (!str) {
		return NULL;
	}
	str[0] = buffer[4];
	str[1] = buffer[5];
	str[2] = '/';
	str[3] = buffer[2];
	str[4] = buffer[3];
	str[5] = '/';
	str[6] = buffer[0] < '5' ? '2' : '1';
	str[7] = buffer[0] < '5' ? '0' : '9';
	str[8] = buffer[0];
	str[9] = buffer[1];
	str[10] = ' ';
	str[11] = buffer[6];
	str[12] = buffer[7];
	str[13] = ':';
	str[14] = buffer[8];
	str[15] = buffer[9];
	str[16] = ':';
	str[17] = buffer[10];
	str[18] = buffer[11];
	str[19] = ' ';
	str[20] = 'G';
	str[21] = 'M';
	str[22] = 'T';
	str[23] = '\0';

	RASN1String* asn1str = r_asn1_create_string (str, true, str_sz);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API RASN1String *r_asn1_stringify_time(const ut8 *buffer, ut32 length) {
	if (!buffer || length != 15 || buffer[14] != 'Z') {
		return NULL;
	}
	const int str_sz = 24;
	char *str = malloc (str_sz);
	if (!str) {
		return NULL;
	}

	str[0] = buffer[6];
	str[1] = buffer[7];
	str[2] = '/';
	str[3] = buffer[4];
	str[4] = buffer[5];
	str[5] = '/';
	str[6] = buffer[0];
	str[7] = buffer[1];
	str[8] = buffer[2];
	str[9] = buffer[3];
	str[10] = ' ';
	str[11] = buffer[8];
	str[12] = buffer[9];
	str[13] = ':';
	str[14] = buffer[10];
	str[15] = buffer[11];
	str[16] = ':';
	str[17] = buffer[12];
	str[18] = buffer[13];
	str[19] = ' ';
	str[20] = 'G';
	str[21] = 'M';
	str[22] = 'T';
	str[23] = '\0';

	RASN1String* asn1str = r_asn1_create_string (str, true, str_sz);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API RASN1String *r_asn1_stringify_bits (const ut8 *buffer, ut32 length) {
	ut32 i, j, k;
	ut64 size;
	ut8 c;
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	size = 1 + ((length - 1)* 8) - buffer[0];
	str = (char*) malloc (size);
	if (!str) {
		return NULL;
	}
	for (i = 1, j = 0; i < length && j < size; i++) {
		c = buffer[i];
		for (k = 0; k < 8 && j < size; k++, j++) {
			str[size - j - 1] = c & 0x80 ? '1' : '0';
			c <<= 1;
		}
	}
	str[size - 1] = '\0';
	RASN1String* asn1str = r_asn1_create_string (str, true, size);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API RASN1String *r_asn1_stringify_boolean (const ut8 *buffer, ut32 length) {
	if (!buffer || length != 1 || (buffer[0] != 0 && buffer[0] != 0xFF)) {
		return NULL;
	}
	return newstr (r_str_bool (buffer[0]));
}

R_API RASN1String *r_asn1_stringify_integer (const ut8 *buffer, ut32 length) {
	ut32 i, j;
	ut64 size;
	ut8 c;
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	size = 3 * length;
	str = (char*) malloc (size);
	if (!str) {
		return NULL;
	}
	memset (str, 0, size);
	for (i = 0, j = 0; i < length && j < size; i++, j += 3) {
		c = buffer[i];
		str[j + 0] = _hex[c >> 4];
		str[j + 1] = _hex[c & 15];
		str[j + 2] = ':';
	}
	str[size - 1] = '\0';
	RASN1String* asn1str = r_asn1_create_string (str, true, size);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API RASN1String* r_asn1_stringify_bytes(const ut8 *buffer, ut32 length) {
	ut32 i, j, k;
	ut64 size;
	ut8 c;
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	size = (4 * length);
	size += (64 - (size % 64));
	str = (char*) malloc (size);
	if (!str) {
		return NULL;
	}
	memset (str, 0x20, size);

	for (i = 0, j = 0, k = 48; i < length && j < size && k < size; i++, j += 3, k++) {
		c = buffer[i];
		str[j + 0] = _hex[c >> 4];
		str[j + 1] = _hex[c & 15];
		str[j + 2] = ' ';
		str[k] = (c >= ' ' && c <= '~') ? c : '.';
		if (i % 16 == 15) {
			str[j + 19] = '\n';
			j += 17;
			k += 49;
		}
	}
	str[size - 1] = '\0';
	RASN1String* asn1str = r_asn1_create_string (str, true, size);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API RASN1String *r_asn1_stringify_oid (const ut8* buffer, ut32 length) {
	const ut8 *start, *end;
	char *str, *t;
	ut32 i, slen, bits;
	ut64 oid;
	if (!buffer || !length) {
		return NULL;
	}

	str = (char*) calloc (1, ASN1_OID_LEN);
	if (!str) {
		return NULL;
	}

	end = buffer + length;
	t = str;
	slen = 0;
	bits = 0;
	oid = 0;

	for (start = buffer; start < end && slen < ASN1_OID_LEN; start++) {
		ut8 c = *start;
		oid <<= 7;
		oid |= (c & 0x7F);
		bits += 7;
		if (!(c & 0x80)) {
			if (!slen) {
				ut32 m = oid / 40;
				ut32 n = oid % 40;
				snprintf (t, ASN1_OID_LEN, "%01u.%01u", m, n);
				slen = strlen (str);
				t = str + slen;
			} else {
				snprintf (t, ASN1_OID_LEN - slen, ".%01u", (ut32) oid);
				slen = strlen (str);
				t = str + slen;
			}
			oid = 0;
			bits = 0;
		}
	}
	// incomplete oid.
	// bad structure.
	if (bits > 0) {
		free (str);
		return NULL;
	}
	i = 0;
	do {
		if (X509OIDList[i].oid[0] == str[0]) {
			if (!strncmp (str, X509OIDList[i].oid, ASN1_OID_LEN)) {
				free (str);
				return newstr (X509OIDList[i].name);
			}
		}
		++i;
	} while (X509OIDList[i].oid && X509OIDList[i].name);
	RASN1String* asn1str = r_asn1_create_string (str, true, ASN1_OID_LEN);
	if (!asn1str) {
		free (str);
	}
	return asn1str;
}

R_API void r_asn1_free_string(RASN1String* str) {
	if (str) {
		if (str->allocated) {
			free ((char*) str->string);
		}
		free (str);
	}
}

R_API RASN1String *asn1_stringify_tag(RASN1Object *object) {
	if (!object) {
		return NULL;
	}
	const char *s = "Unknown tag";
	// TODO: use array of strings
	switch (object->tag) {
	case TAG_EOC: s = "EOC"; break;
	case TAG_BOOLEAN: s = "BOOLEAN"; break;
	case TAG_INTEGER: s = "INTEGER"; break;
	case TAG_BITSTRING: s = "BIT STRING"; break;
	case TAG_OCTETSTRING: s = "OCTET STRING"; break;
	case TAG_NULL: s = "NULL"; break;
	case TAG_OID: s = "OBJECT IDENTIFIER"; break;
	case TAG_OBJDESCRIPTOR: s = "ObjectDescriptor"; break;
	case TAG_EXTERNAL: s = "EXTERNAL"; break;
	case TAG_REAL: s = "REAL"; break;
	case TAG_ENUMERATED: s = "ENUMERATED"; break;
	case TAG_EMBEDDED_PDV: s = "EMBEDDED PDV"; break;
	case TAG_UTF8STRING: s = "UTF8String"; break;
	case TAG_SEQUENCE: s = "SEQUENCE"; break;
	case TAG_SET: s = "SET"; break;
	case TAG_NUMERICSTRING: s = "NumericString"; break;
	case TAG_PRINTABLESTRING: s = "PrintableString"; break;
	case TAG_T61STRING: s = "TeletexString"; break;
	case TAG_VIDEOTEXSTRING: s = "VideotexString"; break;
	case TAG_IA5STRING: s = "IA5String"; break;
	case TAG_UTCTIME: s = "UTCTime"; break;
	case TAG_GENERALIZEDTIME: s = "GeneralizedTime"; break;
	case TAG_GRAPHICSTRING: s = "GraphicString"; break;
	case TAG_VISIBLESTRING: s = "VisibleString"; break;
	case TAG_GENERALSTRING: s = "GeneralString"; break;
	case TAG_UNIVERSALSTRING: s = "UniversalString"; break;
	case TAG_BMPSTRING: s = "BMPString"; break;
	}
	return newstr (s);
}

R_API RASN1String *asn1_stringify_sector(RASN1Object *object) {
	if (!object) {
		return NULL;
	}
	switch (object->tag) {
	case TAG_EOC:
		return NULL;
	case TAG_BOOLEAN:
		return newstr (r_str_bool (object->sector[0]));
	case TAG_REAL:
	case TAG_INTEGER:
		if (object->length < 16) {
			return r_asn1_stringify_integer (object->sector, object->length);
		} else {
			return r_asn1_stringify_bytes (object->sector, object->length);
		}
	case TAG_BITSTRING:
		//if (object->length < 8) {
		return r_asn1_stringify_bits (object->sector, object->length);
		//} else {
		//	return asn1_stringify_bytes (object->sector, object->length);
		//}
	case TAG_OCTETSTRING:
		return r_asn1_stringify_bytes (object->sector, object->length);
	case TAG_NULL:
		return NULL;
	case TAG_OID:
		return r_asn1_stringify_oid (object->sector, object->length);
		//    case TAG_OBJDESCRIPTOR:
		//    case TAG_EXTERNAL:
		//    case TAG_ENUMERATED:
		//    case TAG_EMBEDDED_PDV:
	case TAG_UTF8STRING:
		//    case TAG_SEQUENCE:
		//    case TAG_SET:
	case TAG_NUMERICSTRING:
	case TAG_PRINTABLESTRING:
		//    case TAG_T61STRING:
		//    case TAG_VIDEOTEXSTRING:
	case TAG_IA5STRING:
	case TAG_VISIBLESTRING:
		return r_asn1_stringify_string (object->sector, object->length);
	case TAG_UTCTIME:
		return r_asn1_stringify_utctime (object->sector, object->length);
	case TAG_GENERALIZEDTIME:
		return r_asn1_stringify_time (object->sector, object->length);
		//    case TAG_GRAPHICSTRING:
		//    case TAG_GENERALSTRING:
		//    case TAG_UNIVERSALSTRING:
		//    case TAG_BMPSTRING:
	}
	return NULL;
}
