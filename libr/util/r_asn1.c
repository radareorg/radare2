/* radare2 - LGPL - Copyright 2017 - wargio */

#include <r_util.h>
#include "r_oids.h"
#include <r_types.h>
#include <r_util.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "r_asn1_internal.h"

const char* _hex = "0123456789abcdef";

RASN1String *r_asn1_create_string (const char *string, bool allocated, ut32 length) {
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

RASN1String *r_asn1_create_string2 (const char *string, bool allocated) {
	return r_asn1_create_string (string, allocated, strlen (string) + 1);
}

RASN1String *r_asn1_concatenate_strings (RASN1String *s0, RASN1String *s1, bool freestr) {
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
	return r_asn1_create_string (str, true, len);
}

RASN1String *r_asn1_stringify_string (const ut8 *buffer, ut32 length) {
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	str = (char*) malloc (length + 1);
	if (!str) {
		return NULL;
	}
	memcpy (str, buffer, length);
	r_str_filter (str, length);
	str[length] = '\0';
	return r_asn1_create_string (str, true, length);
}

RASN1String *r_asn1_stringify_utctime (const ut8 *buffer, ut32 length) {
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

	return r_asn1_create_string (str, true, str_sz);
}

RASN1String *r_asn1_stringify_time (const ut8 *buffer, ut32 length) {
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

	return r_asn1_create_string (str, true, str_sz);
}

RASN1String *r_asn1_stringify_bits (const ut8 *buffer, ut32 length) {
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
	for (i = 1, j = 0; i < length && j < size; ++i) {
		c = buffer[i];
		for (k = 0; k < 8 && j < size; ++k, j++) {
			str[size - j - 1] = c & 0x80 ? '1' : '0';
			c <<= 1;
		}
	}
	str[size - 1] = '\0';
	return r_asn1_create_string (str, true, size);
}

RASN1String *r_asn1_stringify_boolean (const ut8 *buffer, ut32 length) {
	if (!buffer || length != 1 || (buffer[0] != 0 && buffer[0] != 0xFF)) {
		return NULL;
	}
	return r_asn1_create_string2 (buffer[0] != 0 ? "true" : "false", false);
}

RASN1String *r_asn1_stringify_integer (const ut8 *buffer, ut32 length) {
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
	for (i = 0, j = 0; i < length && j < size; ++i, j += 3) {
		c = buffer[i];
		str[j + 0] = _hex[c >> 4];
		str[j + 1] = _hex[c & 15];
		str[j + 2] = ':';
	}
	str[size - 1] = '\0';
	return r_asn1_create_string (str, true, size);
}

RASN1String* r_asn1_stringify_bytes (const ut8 *buffer, ut32 length) {
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

	for (i = 0, j = 0, k = 48; i < length && j < size && k < size; ++i, j += 3, k++) {
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

	return r_asn1_create_string (str, true, size);
}

RASN1String *r_asn1_stringify_oid (const ut8* buffer, ut32 length) {
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
				return r_asn1_create_string2 (X509OIDList[i].name, false);
			}
		}
		++i;
	} while (X509OIDList[i].oid && X509OIDList[i].name);
	return r_asn1_create_string (str, true, ASN1_OID_LEN);
}

static RASN1Object *asn1_parse_header (const ut8 *buffer, ut32 length) {
	RASN1Object *object;
	ut8 head, length8, byte;
	ut64 length64;
	if (!buffer || length < 2) {
		return NULL;
	}

	object = R_NEW0 (RASN1Object);
	if (!object) {
		return NULL;
	}
	head = buffer[0];
	object->klass = head & ASN1_CLASS;
	object->form = head & ASN1_FORM;
	object->tag = head & ASN1_TAG;
	length8 = buffer[1];
	if (length8 & ASN1_LENLONG) {
		length64 = 0;
		length8 &= ASN1_LENSHORT;
		if (length8 && length8 < length - 2) {
			ut8 i8;
			// can overflow.
			for (i8 = 0; i8 < length8; ++i8) {
				byte = buffer[2 + i8];
				length64 <<= 8;
				length64 |= byte;
				if (length64 > length) {
					goto out_error;
				}
			}
			object->sector = buffer + 2 + length8;
		} else {
			//indefinite
			const ut8 *from = buffer + 2;
			const ut8 *end = from + (length - 2);
			do {
				byte = *from;
				length64 <<= 8;
				length64 |= byte;
				from++;
			} while (from < end && length64 <= length && byte & 0x80);
			if (length64 > length) {
				goto out_error;
			}
			object->sector = from;
		}
		object->length = (ut32) length64;
	} else {
		object->length = (ut32) length8;
		object->sector = buffer + 2;
	}
	if (object->tag == TAG_BITSTRING && object->sector[0] == 0) {
		if (object->length > 0){
			object->sector++; //real sector starts +1
			object->length--;
		}
	}
	if (object->length > length) {
		// Malformed object - overflow from data ptr
		goto out_error;
	}
	return object;
out_error:
	free (object);
	return NULL;
}

ut32 r_asn1_count_objects (const ut8 *buffer, ut32 length) {
	ut32 counter;
	RASN1Object *object;
	const ut8 *next, *end;
	if (!buffer || !length) {
		return 0;
	}
	counter = 0;
	object = NULL;
	next = buffer;
	end = buffer + length;
	while (next >= buffer && next < end) {
		object = asn1_parse_header (next, end - next);
		if (!object || next == object->sector) {
			R_FREE (object);
			break;
		}
		next = object->sector + object->length;
		counter++;
		R_FREE (object);
	}
	R_FREE (object);
	return counter;
}

RASN1Object *r_asn1_create_object (const ut8 *buffer, ut32 length) {
	RASN1Object *object = asn1_parse_header (buffer, length);
	if (object && (object->form == FORM_CONSTRUCTED || object->tag == TAG_BITSTRING || object->tag == TAG_OCTETSTRING)) {
		ut32 i, count;
		RASN1Object *inner = NULL;
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		if (end > buffer + length) {
			free (object);
			return NULL;
		}
		count = r_asn1_count_objects (object->sector, object->length);
		if (count > 0) {
			object->list.length = count;
			object->list.objects = R_NEWS0 (RASN1Object*, count);
			if (!object->list.objects) {
				r_asn1_free_object (object);
				return NULL;
			}
			for (i = 0; next >= buffer && next < end && i < count; ++i) {
				inner = r_asn1_create_object (next, end - next);
				if (!inner || next == inner->sector) {
					r_asn1_free_object (inner);
					break;
				}
				next = inner->sector + inner->length;
				R_PTR_MOVE (object->list.objects[i], inner);
			}
		}
	}
	return object;
}

RASN1Binary *r_asn1_create_binary (const ut8 *buffer, ut32 length) {
	RASN1Binary* bin = NULL;
	ut8* buf = NULL;
	if (!buffer || !length) {
		return NULL;
	}
	buf = (ut8*) calloc (sizeof (*buf), length);
	if (!buf) {
		return NULL;
	}
	bin = R_NEW0 (RASN1Binary);
	if (!bin) {
		free (buf);
		return NULL;
	}
	memcpy (buf, buffer, length);
	bin->binary = buf;
	bin->length = length;
	return bin;
}

void r_asn1_free_object (RASN1Object *object) {
	ut32 i;
	if (!object) {
		return;
	}
	//this shall not be freed. it's a pointer into the buffer.
	object->sector = 0;
	if (object->list.objects) {
		for (i = 0; i < object->list.length; ++i) {
			r_asn1_free_object (object->list.objects[i]);
		}
		R_FREE (object->list.objects);
	}
	object->list.objects = NULL;
	object->list.length = 0;
	R_FREE (object);
}

void r_asn1_free_string (RASN1String* str) {
	if (str) {
		if (str->allocated) {
			free ((char*) str->string);
		}
		free (str);
	}
}

void r_asn1_free_binary (RASN1Binary* bin) {
	if (bin) {
		free ((char*) bin->binary);
		free (bin);
	}
}

RASN1String *asn1_stringify_tag (RASN1Object *object) {
	if (!object) {
		return NULL;
	}
	switch (object->tag) {
	case TAG_EOC:
		return r_asn1_create_string2 ("EOC", false);
	case TAG_BOOLEAN:
		return r_asn1_create_string2 ("BOOLEAN", false);
	case TAG_INTEGER:
		return r_asn1_create_string2 ("INTEGER", false);
	case TAG_BITSTRING:
		return r_asn1_create_string2 ("BIT STRING", false);
	case TAG_OCTETSTRING:
		return r_asn1_create_string2 ("OCTET STRING", false);
	case TAG_NULL:
		return r_asn1_create_string2 ("NULL", false);
	case TAG_OID:
		return r_asn1_create_string2 ("OBJECT IDENTIFIER", false);
	case TAG_OBJDESCRIPTOR:
		return r_asn1_create_string2 ("ObjectDescriptor", false);
	case TAG_EXTERNAL:
		return r_asn1_create_string2 ("EXTERNAL", false);
	case TAG_REAL:
		return r_asn1_create_string2 ("REAL", false);
	case TAG_ENUMERATED:
		return r_asn1_create_string2 ("ENUMERATED", false);
	case TAG_EMBEDDED_PDV:
		return r_asn1_create_string2 ("EMBEDDED PDV", false);
	case TAG_UTF8STRING:
		return r_asn1_create_string2 ("UTF8String", false);
	case TAG_SEQUENCE:
		return r_asn1_create_string2 ("SEQUENCE", false);
	case TAG_SET:
		return r_asn1_create_string2 ("SET", false);
	case TAG_NUMERICSTRING:
		return r_asn1_create_string2 ("NumericString", false);
	case TAG_PRINTABLESTRING:
		return r_asn1_create_string2 ("PrintableString", false);
	case TAG_T61STRING:
		return r_asn1_create_string2 ("TeletexString", false);
	case TAG_VIDEOTEXSTRING:
		return r_asn1_create_string2 ("VideotexString", false);
	case TAG_IA5STRING:
		return r_asn1_create_string2 ("IA5String", false);
	case TAG_UTCTIME:
		return r_asn1_create_string2 ("UTCTime", false);
	case TAG_GENERALIZEDTIME:
		return r_asn1_create_string2 ("GeneralizedTime", false);
	case TAG_GRAPHICSTRING:
		return r_asn1_create_string2 ("GraphicString", false);
	case TAG_VISIBLESTRING:
		return r_asn1_create_string2 ("VisibleString", false);
	case TAG_GENERALSTRING:
		return r_asn1_create_string2 ("GeneralString", false);
	case TAG_UNIVERSALSTRING:
		return r_asn1_create_string2 ("UniversalString", false);
	case TAG_BMPSTRING:
		return r_asn1_create_string2 ("BMPString", false);
	}
	return r_asn1_create_string2 ("Unknown tag", false);
}

RASN1String *asn1_stringify_sector (RASN1Object *object) {
	if (!object) {
		return NULL;
	}
	switch (object->tag) {
	case TAG_EOC:
		return NULL;
	case TAG_BOOLEAN:
		return r_asn1_create_string2 (object->sector[0] == 0 ? "false" : "true", false);
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
