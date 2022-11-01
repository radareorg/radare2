/* radare2 - LGPL - Copyright 2017-2022 - wargio, pancake */

#include <r_cons.h>
#include <r_util.h>

// XXX remove global
static R_TH_LOCAL int ASN1_STD_FORMAT = 1;
R_API void asn1_setformat(int fmt) {
	ASN1_STD_FORMAT = fmt;
}

static ut32 asn1_ber_indefinite(const ut8 *buffer, ut32 length) {
	if (!buffer || length < 3) {
		return 0;
	}
	const ut8* next = buffer + 2;
	const ut8* end = buffer + length - 3;
	while (next + 1 < end) {
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
		next++;
	}
	return (next - buffer) + 2;
}

static RASN1Object *asn1_parse_header(const ut8 *buffer_base, const ut8 *buffer, ut32 length) {
	ut8 length8, byte;
	ut64 length64;

	if (!buffer || length < 3) {
		return NULL;
	}

	RASN1Object *msg = R_NEW0 (RASN1Object);
	if (!msg) {
		return NULL;
	}
	ut8 head = buffer[0];
	msg->offset = buffer_base ? (buffer - buffer_base) : 0;
	msg->klass = head & ASN1_CLASS;
	msg->form = head & ASN1_FORM;
	msg->tag = head & ASN1_TAG;
	length8 = buffer[1];
	if (length8 & ASN1_LENLONG) {
		length64 = 0;
		length8 &= ASN1_LENSHORT;
		msg->sector = buffer + 2;
		if (length8 && length8 < length - 2) {
			ut8 i8;
			// can overflow.
			for (i8 = 0; i8 < length8; i8++) {
				byte = buffer[2 + i8];
				length64 <<= 8;
				length64 |= byte;
				if (length64 > length) {
					goto out_error;
				}
			}
			msg->sector += length8;
		} else {
			if (length < 3) {
				goto out_error;
			}
			length64 = asn1_ber_indefinite (msg->sector, length - 2);
		}
		msg->length = (ut32) length64;
	} else {
		msg->length = (ut32) length8;
		msg->sector = buffer + 2;
	}
	if (msg->tag == TAG_BITSTRING && msg->sector[0] == 0) {
		if (msg->length > 0) {
			msg->sector++; // real sector starts + 1
			msg->length--;
		}
	}
	if (msg->length > length) {
		// Malformed msg - overflow from data ptr
		goto out_error;
	}
	return msg;
out_error:
	free (msg);
	return NULL;
}

static ut32 asn1_count_objects(const ut8 *buffer, ut32 length) {
	r_return_val_if_fail (buffer, 0);
	if (!length) {
		return 0;
	}
	ut32 counter = 0;
	RASN1Object *msg = NULL;
	const ut8 *next = buffer;
	const ut8 *end = buffer + length;
	while (next >= buffer && next < end) {
		// i do not care about the offset now.
		msg = asn1_parse_header (buffer, next, (size_t)(end - next));
		if (!msg || next == msg->sector) {
			R_FREE (msg);
			break;
		}
		next = msg->sector + msg->length;
		counter++;
		R_FREE (msg);
	}
	R_FREE (msg);
	return counter;
}

// should be internal -- rename object to message imho
R_API RASN1Object *r_asn1_object_parse(const ut8 *buffer_base, const ut8 *buffer, ut32 length, int fmtmode) {
	RASN1Object *object = asn1_parse_header (buffer_base, buffer, length);
	if (object && (object->form == FORM_CONSTRUCTED || object->tag == TAG_BITSTRING || object->tag == TAG_OCTETSTRING)) {
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		if (end > buffer + length) {
			free (object);
			return NULL;
		}
		ut32 count = asn1_count_objects (object->sector, object->length);
		if (count > 0) {
			object->list.length = count;
			object->list.objects = R_NEWS0 (RASN1Object*, count);
			if (!object->list.objects) {
				r_asn1_object_free (object);
				return NULL;
			}
			ut32 i;
			for (i = 0; next >= buffer && next < end && i < count; i++) {
				RASN1Object *inner = r_asn1_object_parse (buffer_base, next, end - next, fmtmode);
				if (!inner || next == inner->sector) {
					r_asn1_object_free (inner);
					break;
				}
				next = inner->sector + inner->length;
				object->list.objects[i] = inner;
			}
		}
	}
	return object;
}

R_API char *r_asn1_oid(RAsn1 *a) {
	char *res = NULL;
	RASN1String *s = r_asn1_stringify_oid (a->buffer, a->length);
	if (s) {
		res = strdup (s->string);
		r_asn1_string_free (s);
	}
	return res;
}

R_API RAsn1 *r_asn1_new(const ut8 *buffer, int length, int fmtmode) {
	RAsn1 *a = R_NEW0 (RAsn1);
	a->buffer = buffer;
	a->length = length;
	a->fmtmode = fmtmode;
	switch (fmtmode) {
	case 'j':
		a->pj = pj_new ();
		break;
	}
	a->root = r_asn1_object_parse (buffer, buffer, length, fmtmode);
	return a;
}

R_API void r_asn1_free(RAsn1 *a) {
	if (a) {
		r_asn1_object_free (a->root);
		r_strbuf_free (a->sb);
		pj_free (a->pj);
		free (a);
	}
}

R_API RASN1Binary *r_asn1_create_binary(const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	ut8* buf = (ut8*) calloc (1, length);
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

R_API void r_asn1_print_hex(RASN1Object *msg, char* buffer, ut32 size, ut32 depth) {
	ut32 i;
	if (!msg || !msg->sector) {
		return;
	}
	char* p = buffer;
	char* end = buffer + size;
	if (depth > 0 && !ASN1_STD_FORMAT) {
		const char *pad = r_str_pad (' ', (depth * 2) - 2);
		snprintf (p, end - p, "%s", pad);
		p += strlen (pad);
	}
	for (i = 0; i < msg->length && p < end; i++) {
		snprintf (p, end - p, "%02x", msg->sector[i]);
		p += 2;
	}
	if (p >= end) {
		p -= 4;
		snprintf (p, end - p, "...");
	}
}

#if !ASN1_STD_FORMAT
static void asn1_printkv(RStrBuf *sb, RASN1Object *msg, int depth, const char *k, const char *v) {
	const char *pad = r_str_pad (' ', (depth * 2) - 2);
	if (msg->form && !*v) {
		return;
	}
	switch (msg->tag) {
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

static RASN1String* asn1_hexdump(RASN1Object *msg, ut32 depth, int fmtmode) {
	const char *pad;
	ut32 i, j;
	char readable[20] = {0};
	if (!msg || !msg->sector || msg->length < 1) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (fmtmode) {
		pad = "                                        : ";
	} else {
		pad = r_str_pad (' ', depth * 2);
		r_strbuf_append (sb, "  ");
	}

	for (i = 0, j = 0; i < msg->length; i++, j++) {
		ut8 c = msg->sector[i];
		if (i > 0 && (i % 16) == 0) {
			r_strbuf_appendf (sb, "|%-16s|\n%s", readable, pad);
			memset (readable, 0, sizeof (readable));
			j = 0;
		}
		r_strbuf_appendf (sb, "%02x ", c);
		readable[j] = IS_PRINTABLE (c) ? c : '.';
	}

	while ((i % 16) != 0) {
		r_strbuf_append (sb, "   ");
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

// XXX this function signature is confusing
R_API char *r_asn1_object_tostring(RASN1Object *msg, ut32 depth, RStrBuf *sb, int fmtmode) {
	bool root = false;
	// RStrBuf *sb = msg->sb;
	if (!sb) {
		sb = r_strbuf_new ("");
		root = true;
	}
	if (!msg) {
		return NULL;
	}
	char temp_name[4096] = {0};
	ut32 i;
	// this shall not be freed. it's a pointer into the buffer.
	RASN1String* asn1str = NULL;
	const char* name = "";
	const char* string = "";

	switch (msg->klass) {
	case CLASS_UNIVERSAL: // universal
		switch (msg->tag) {
		case TAG_EOC:
			name = "EOC";
			break;
		case TAG_BOOLEAN:
			name = "BOOLEAN";
			if (msg->sector) {
				string = r_str_bool (msg->sector[0] != 0);
			}
			break;
		case TAG_INTEGER:
			name = "INTEGER";
			if (msg->length < 16) {
				r_asn1_print_hex (msg, temp_name, sizeof (temp_name), depth);
				string = temp_name;
			} else {
				asn1str = asn1_hexdump (msg, depth, fmtmode);
			}
			break;
		case TAG_BITSTRING:
			name = "BIT_STRING";
			if (!msg->list.objects) {
				if (msg->length < 16) {
					r_asn1_print_hex (msg, temp_name, sizeof (temp_name), depth);
					string = temp_name;
				} else {
					asn1str = asn1_hexdump (msg, depth, fmtmode);
				}
			}
			break;
		case TAG_OCTETSTRING:
			name = "OCTET_STRING";
			if (r_str_is_printable_limited ((const char *)msg->sector, msg->length)) {
				asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			} else if (!msg->list.objects) {
				if (msg->length < 16) {
					r_asn1_print_hex (msg, temp_name, sizeof (temp_name), depth);
					string = temp_name;
				} else {
					asn1str = asn1_hexdump (msg, depth, fmtmode);
				}
			}
			break;
		case TAG_NULL:
			name = "NULL";
			break;
		case TAG_OID:
			name = "OBJECT_IDENTIFIER";
			asn1str = r_asn1_stringify_oid (msg->sector, msg->length);
			break;
		case TAG_OBJDESCRIPTOR:
			name = "OBJECT_DESCRIPTOR";
			break;
		case TAG_EXTERNAL:
			name = "EXTERNAL";
			break;
		case TAG_REAL:
			name = "REAL";
			asn1str = asn1_hexdump (msg, depth, fmtmode);
			break;
		case TAG_ENUMERATED:
			name = "ENUMERATED";
			break;
		case TAG_EMBEDDED_PDV:
			name = "EMBEDDED_PDV";
			break;
		case TAG_UTF8STRING:
			name = "UTF8String";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_SEQUENCE:
			name = "SEQUENCE";
			break;
		case TAG_SET:
			name = "SET";
			break;
		case TAG_NUMERICSTRING:
			name = "NumericString";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_PRINTABLESTRING:
			name = "PrintableString"; // ASCII subset
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_T61STRING:
			name = "TeletexString"; // aka T61String
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_VIDEOTEXSTRING:
			name = "VideotexString";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_IA5STRING:
			name = "IA5String"; // ASCII
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_UTCTIME:
			name = "UTCTime";
			asn1str = r_asn1_stringify_utctime (msg->sector, msg->length);
			break;
		case TAG_GENERALIZEDTIME:
			name = "GeneralizedTime";
			asn1str = r_asn1_stringify_time (msg->sector, msg->length);
			break;
		case TAG_GRAPHICSTRING:
			name = "GraphicString";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_VISIBLESTRING:
			name = "VisibleString"; // ASCII subset
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_GENERALSTRING:
			name = "GeneralString";
			break;
		case TAG_UNIVERSALSTRING:
			name = "UniversalString";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		case TAG_BMPSTRING:
			name = "BMPString";
			asn1str = r_asn1_stringify_string (msg->sector, msg->length);
			break;
		default:
			snprintf (temp_name, sizeof (temp_name), "Universal_%u", msg->tag);
			name = temp_name;
			break;
		}
		break;
	case CLASS_APPLICATION:
		snprintf (temp_name, sizeof (temp_name), "Application_%u", msg->tag);
		name = temp_name;
		break;
	case CLASS_CONTEXT:
		snprintf (temp_name, sizeof (temp_name), "Context [%u]", msg->tag); // Context
		name = temp_name;
		break;
	case CLASS_PRIVATE:
		snprintf (temp_name, sizeof (temp_name), "Private_%u", msg->tag);
		name = temp_name;
		break;
	}
	if (asn1str) {
		string = asn1str->string;
	}
	if (fmtmode) {
		r_strbuf_appendf (sb, "%4"PFMT64d"  ", msg->offset);
		r_strbuf_appendf (sb, "%4u:%2d: %s %-20s: %s\n", msg->length,
			depth, msg->form ? "cons" : "prim", name, string);
		r_asn1_string_free (asn1str);
		if (msg->list.objects) {
			for (i = 0; i < msg->list.length; i++) {
				r_asn1_object_tostring (msg->list.objects[i], depth + 1, sb, fmtmode);
			}
		}
	} else {
		asn1_printkv (sb, msg, depth, name, string);
		r_asn1_string_free (asn1str);
		if (msg->list.objects) {
			for (i = 0; i < msg->list.length; i++) {
				RASN1Object *obj = msg->list.objects[i];
				r_asn1_object_tostring (obj, depth + 1, sb, fmtmode);
			}
		}
	}
	return root? r_strbuf_drain (sb): NULL;
}

R_API void r_asn1_object_free(RASN1Object *obj) {
	if (!obj) {
		return;
	}
	// This shall not be freed. it's a pointer into the buffer.
	obj->sector = NULL;
	if (obj->list.objects) {
		ut32 i;
		for (i = 0; i < obj->list.length; i++) {
			r_asn1_object_free (obj->list.objects[i]);
		}
		R_FREE (obj->list.objects);
	}
	obj->list.objects = NULL;
	obj->list.length = 0;
	free (obj);
}

R_API void r_asn1_binary_free(RASN1Binary* bin) {
	if (bin) {
		free (bin->binary);
		free (bin);
	}
}
