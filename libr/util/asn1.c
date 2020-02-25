/* radare2 - LGPL - Copyright 2017-2018 - wargio */

#include <r_util.h>
#include <r_cons.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int ASN1_STD_FORMAT  = 1;

R_API void asn1_setformat (int fmt) {
	ASN1_STD_FORMAT = fmt;
}

static ut32 asn1_ber_indefinite (const ut8 *buffer, ut32 length) {
	if (!buffer || length < 3) {
		return 0;
	}
	const ut8* next = buffer + 2;
	const ut8* end = buffer + (length - 3);
	while (next < end) {
		if (!next[0] && !next[1]) {
			break;
		}
		if (next[0] == 0x80 && (next[-1] & ASN1_FORM) == FORM_CONSTRUCTED) {
			next --;
			int sz = asn1_ber_indefinite (next, end - next);
			if (sz < 1) {
				break;
			}
			next += sz;
		}
		next ++;
	}
	return (next - buffer) + 2;
}

static RASN1Object *asn1_parse_header (const ut8 *buffer, ut32 length, const ut8 *start_pointer) {
	ut8 head, length8, byte;
	ut64 length64;
	if (!buffer || length < 2) {
		return NULL;
	}

	RASN1Object *object = R_NEW0 (RASN1Object);
	if (!object) {
		return NULL;
	}
	head = buffer[0];
	object->offset = start_pointer ? (buffer - start_pointer) : 0;
	object->klass = head & ASN1_CLASS;
	object->form = head & ASN1_FORM;
	object->tag = head & ASN1_TAG;
	length8 = buffer[1];
	if (length8 & ASN1_LENLONG) {
		length64 = 0;
		length8 &= ASN1_LENSHORT;
		object->sector = buffer + 2;
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
			object->sector += length8;
		} else {
			length64 = asn1_ber_indefinite (object->sector, length - 2);
		}
		object->length = (ut32) length64;
	} else {
		object->length = (ut32) length8;
		object->sector = buffer + 2;
	}

	if (object->tag == TAG_BITSTRING && object->sector[0] == 0) {
		if (object->length > 0) {
			object->sector++; // real sector starts + 1
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

static ut32 r_asn1_count_objects (const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return 0;
	}
	ut32 counter = 0;
	RASN1Object *object = NULL;
	const ut8 *next = buffer;
	const ut8 *end = buffer + length;
	while (next >= buffer && next < end) {
		// i do not care about the offset now.
		object = asn1_parse_header (next, end - next, 0);
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

R_API RASN1Object *r_asn1_create_object (const ut8 *buffer, ut32 length, const ut8 *start_pointer) {
	RASN1Object *object = asn1_parse_header (buffer, length, start_pointer);
	if (object && (object->form == FORM_CONSTRUCTED || object->tag == TAG_BITSTRING || object->tag == TAG_OCTETSTRING)) {
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		if (end > buffer + length) {
			free (object);
			return NULL;
		}
		ut32 count = r_asn1_count_objects (object->sector, object->length);
		if (count > 0) {
			object->list.length = count;
			object->list.objects = R_NEWS0 (RASN1Object*, count);
			if (!object->list.objects) {
				r_asn1_free_object (object);
				return NULL;
			}
			ut32 i;
			for (i = 0; next >= buffer && next < end && i < count; ++i) {
				RASN1Object *inner = r_asn1_create_object (next, end - next, start_pointer);
				if (!inner || next == inner->sector) {
					r_asn1_free_object (inner);
					break;
				}
				next = inner->sector + inner->length;
				object->list.objects[i] = inner;
			}
		}
	}
	return object;
}

R_API RASN1Binary *r_asn1_create_binary (const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	ut8* buf = (ut8*) calloc (sizeof (*buf), length);
	if (!buf) {
		return NULL;
	}
	RASN1Binary* bin = R_NEW0 (RASN1Binary);
	if (!bin) {
		free (buf);
		return NULL;
	}
	memcpy (buf, buffer, length);
	bin->binary = buf;
	bin->length = length;
	return bin;
}

R_API void r_asn1_print_hex (RASN1Object *object, char* buffer, ut32 size, ut32 depth) {
	ut32 i;
	if (!object || !object->sector) {
		return;
	}
	char* p = buffer;
	char* end = buffer + size;
	if (depth > 0 && !ASN1_STD_FORMAT) {
		const char *pad = r_str_pad (' ', (depth * 2) - 2);
		snprintf (p, end - p, "%s", pad);
		p += strlen(pad);
	}
	for (i = 0; i < object->length && p < end; ++i) {
		snprintf (p, end - p, "%02x", object->sector[i]);
		p += 2;
	}
	if (p >= end) {
		p -= 4;
		snprintf (p, end - p, "...");
	}
}

#if !ASN1_STD_FORMAT
static void r_asn1_print_padded(RStrBuf *sb, RASN1Object *object, int depth, const char *k, const char *v) {
	const char *pad = r_str_pad (' ', (depth * 2) - 2);
	if (object->form && !*v) {
		return;
	}
	switch (object->tag) {
	case TAG_NULL:
	case TAG_EOC:
		break;
	case TAG_INTEGER:
	case TAG_REAL:
		if (*r_str_trim_head_ro (v)) {
			r_strbuf_appendf (sb, "%s%s\n%s%s\n", pad, k, pad, v);
		}
		break;
	case TAG_BITSTRING:
	default:
		if (*r_str_trim_head_ro (v)) {
			r_strbuf_appendf (sb, "%s%s\n", pad, v);
		}
		break;
	}
}
#endif

static RASN1String* r_asn1_print_hexdump_padded (RASN1Object *object, ut32 depth) {
	const char *pad;
	ut32 i, j;
	char readable[20] = {0};
	if (!object || !object->sector || object->length < 1) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (ASN1_STD_FORMAT) {
		pad = "                                        : ";
	} else {
		pad = r_str_pad (' ', depth * 2);
		r_strbuf_appendf (sb, "  ", pad);
	}

	for (i = 0, j = 0; i < object->length; i++, j++) {
		ut8 c = object->sector[i];
		if (i > 0 && (i % 16) == 0) {
			r_strbuf_appendf (sb, "|%-16s|\n%s", readable, pad);
			memset (readable, 0, sizeof (readable));
			j = 0;
		}
		r_strbuf_appendf (sb, "%02x ", c);
		readable[j] = IS_PRINTABLE(c) ? c : '.';
	}

	while ((i % 16) != 0) {
		r_strbuf_appendf (sb, "   ");
		i++;
	}
	r_strbuf_appendf (sb, "|%-16s|", readable);
	char* text = r_strbuf_drain (sb);
	RASN1String* asn1str = r_asn1_create_string (text, true, strlen (text) + 1);
	if (!asn1str) {
		/* no memory left.. */
		free (text);
	}
	return asn1str;
}

R_API char *r_asn1_to_string (RASN1Object *object, ut32 depth, RStrBuf *sb) {
	ut32 i;
	bool root = false;
	if (!object) {
		return NULL;
	}
	if (!sb) {
		sb = r_strbuf_new ("");
		root = true;
	}
	//this shall not be freed. it's a pointer into the buffer.
	RASN1String* asn1str = NULL;
	static char temp_name[4096] = {0};
	const char* name = "";
	const char* string = "";

	switch (object->klass) {
	case CLASS_UNIVERSAL: // universal
		switch (object->tag) {
		case TAG_EOC:
			name = "EOC";
			break;
		case TAG_BOOLEAN:
			name = "BOOLEAN";
			if (object->sector) {
				string = (object->sector[0] != 0) ? "true" : "false";
			}
			break;
		case TAG_INTEGER:
			name = "INTEGER";
			if (object->length < 16) {
				r_asn1_print_hex (object, temp_name, sizeof (temp_name), depth);
				string = temp_name;
			} else {
				asn1str = r_asn1_print_hexdump_padded (object, depth);
			}
			break;
		case TAG_BITSTRING:
			name = "BIT_STRING";
			if (!object->list.objects) {
				if (object->length < 16) {
					r_asn1_print_hex (object, temp_name, sizeof (temp_name), depth);
					string = temp_name;
				} else {
					asn1str = r_asn1_print_hexdump_padded (object, depth);
				}
			}
			break;
		case TAG_OCTETSTRING:
			name = "OCTET_STRING";
			if (r_str_is_printable_limited ((const char *)object->sector, object->length)) {
				asn1str = r_asn1_stringify_string (object->sector, object->length);
			} else if (!object->list.objects) {
				if (object->length < 16) {
					r_asn1_print_hex (object, temp_name, sizeof (temp_name), depth);
					string = temp_name;
				} else {
					asn1str = r_asn1_print_hexdump_padded (object, depth);
				}
			}
			break;
		case TAG_NULL:
			name = "NULL";
			break;
		case TAG_OID:
			name = "OBJECT_IDENTIFIER";
			asn1str = r_asn1_stringify_oid (object->sector, object->length);
			break;
		case TAG_OBJDESCRIPTOR:
			name = "OBJECT_DESCRIPTOR";
			break;
		case TAG_EXTERNAL:
			name = "EXTERNAL";
			break;
		case TAG_REAL:
			name = "REAL";
			asn1str = r_asn1_print_hexdump_padded (object, depth);
			break;
		case TAG_ENUMERATED:
			name = "ENUMERATED";
			break;
		case TAG_EMBEDDED_PDV:
			name = "EMBEDDED_PDV";
			break;
		case TAG_UTF8STRING:
			name = "UTF8String";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_SEQUENCE:
			name = "SEQUENCE";
			break;
		case TAG_SET:
			name = "SET";
			break;
		case TAG_NUMERICSTRING:
			name = "NumericString";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_PRINTABLESTRING:
			name = "PrintableString"; // ASCII subset
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_T61STRING:
			name = "TeletexString"; // aka T61String
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_VIDEOTEXSTRING:
			name = "VideotexString";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_IA5STRING:
			name = "IA5String"; // ASCII
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_UTCTIME:
			name = "UTCTime";
			asn1str = r_asn1_stringify_utctime (object->sector, object->length);
			break;
		case TAG_GENERALIZEDTIME:
			name = "GeneralizedTime";
			asn1str = r_asn1_stringify_time (object->sector, object->length);
			break;
		case TAG_GRAPHICSTRING:
			name = "GraphicString";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_VISIBLESTRING:
			name = "VisibleString"; // ASCII subset
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_GENERALSTRING:
			name = "GeneralString";
			break;
		case TAG_UNIVERSALSTRING:
			name = "UniversalString";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		case TAG_BMPSTRING:
			name = "BMPString";
			asn1str = r_asn1_stringify_string (object->sector, object->length);
			break;
		default:
			snprintf (temp_name, sizeof (temp_name), "Universal_%u", object->tag);
			name = temp_name;
			break;
		}
		break;
	case CLASS_APPLICATION:
		snprintf (temp_name, sizeof (temp_name), "Application_%u", object->tag);
		name = temp_name;
		break;
	case CLASS_CONTEXT:
		snprintf (temp_name, sizeof (temp_name), "Context [%u]", object->tag); // Context
		name = temp_name;
		break;
	case CLASS_PRIVATE:
		snprintf (temp_name, sizeof (temp_name), "Private_%u", object->tag);
		name = temp_name;
		break;
	}
	if (asn1str) {
		string = asn1str->string;
	}
	if (ASN1_STD_FORMAT) {
		r_strbuf_appendf (sb, "%4"PFMT64d"  ", object->offset);
		r_strbuf_appendf (sb, "%4u:%2d: %s %-20s: %s\n", object->length,
			depth, object->form ? "cons" : "prim", name, string);
		r_asn1_free_string (asn1str);
		if (object->list.objects) {
			for (i = 0; i < object->list.length; ++i) {
				r_asn1_to_string (object->list.objects[i], depth + 1, sb);
			}
		}
	} else {
		r_asn1_print_padded (sb, object, depth, name, string);
		r_asn1_free_string (asn1str);
		if (object->list.objects) {
			for (i = 0; i < object->list.length; ++i) {
				RASN1Object *obj = object->list.objects[i];
				r_asn1_to_string (obj, depth + 1, sb);
			}
		}
	}
	return root? r_strbuf_drain (sb): NULL;
}

R_API void r_asn1_free_object (RASN1Object *object) {
	ut32 i;
	if (!object) {
		return;
	}
	// This shall not be freed. it's a pointer into the buffer.
	object->sector = NULL;
	if (object->list.objects) {
		for (i = 0; i < object->list.length; ++i) {
			r_asn1_free_object (object->list.objects[i]);
		}
		R_FREE (object->list.objects);
	}
	object->list.objects = NULL;
	object->list.length = 0;
	free (object);
}

R_API void r_asn1_free_binary (RASN1Binary* bin) {
	if (bin) {
		free (bin->binary);
		free (bin);
	}
}
