/* radare2 - LGPL - Copyright 2017-2025 - wargio, pancake */

#define R_LOG_ORIGIN "asn1"

// R2R db/cmd/cmd_pFa db/cmd/cmd_pFb db/cmd/cmd_pFp
// R2R db/cmd/cmd_print

#include <r_util.h>

#define FASTERASN 1

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
	RASN1Object *obj = R_NEW0 (RASN1Object);
	ut8 head = buffer[0];
	obj->offset = buffer_base? (buffer - buffer_base): 0;
	obj->klass = head & ASN1_CLASS;
	obj->form = head & ASN1_FORM;
	obj->tag = head & ASN1_TAG;
	length8 = buffer[1];
	// Save initial position for header length calculation
	const ut8 *initial_pos = buffer;
	if (length8 & ASN1_LENLONG) {
		length64 = 0;
		length8 &= ASN1_LENSHORT;
		obj->sector = buffer + 2;
		// Check for indefinite length.
		if (length8) {
			// Length over 6 bytes is not allowed.
			if (length8 > length - 1 || length8 > 6) {
				R_LOG_DEBUG ("ASN.1: length error");
				goto out_error;
			}
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
			obj->sector += length8;
		} else {
			if (length < 3) {
				goto out_error;
			}
			length64 = asn1_ber_indefinite (obj->sector, length - 2);
		}
		obj->length = (ut32) length64;
	} else {
		obj->length = (ut32) length8;
		obj->sector = buffer + 2;
	}
	obj->bitlength = 8 * obj->length;
#if FASTERASN
	// Calculate headerlength before BITSTRING adjustment
	obj->headerlength = obj->sector - initial_pos;
#endif
	if (obj->tag == TAG_BITSTRING) {
		if (obj->length > 0) {
			obj->length--;
			obj->bitlength = obj->length * 8 - obj->sector[0];
			obj->sector++; // real sector starts + 1
		}
	}
	const int left = length - (obj->sector - buffer);
	if (obj->length > left) {
		R_LOG_DEBUG ("Wrap down from %d to %d", obj->length, left);
		obj->length = left;
	}
	if (obj->length > length) {
		R_LOG_DEBUG ("Truncated object");
		goto out_error;
	}
	return obj;
out_error:
	free (obj);
	return NULL;
}

static ut32 asn1_count_objects(const ut8 *buffer, ut32 length) {
	R_RETURN_VAL_IF_FAIL (buffer, 0);
	if (!length) {
		return 0;
	}
	st32 counter = 0;
	const ut8 *next = buffer;
	const ut8 *end = buffer + length;
	while (next >= buffer && next < end) {
		// i do not care about the offset now.
		RASN1Object *obj = asn1_parse_header (buffer, next, (size_t)(end - next));
		if (!obj || next == obj->sector) {
			R_FREE (obj);
			break;
		}
		next = obj->sector + obj->length;
		counter++;
		R_FREE (obj);
	}
	return counter;
}

// should be internal -- rename object to message imho
R_API RASN1Object *r_asn1_object_parse(const ut8 *buffer_base, const ut8 *buffer, ut32 length, int fmtmode) {
	RASN1Object *object = asn1_parse_header (buffer_base, buffer, length);
	if (object && (object->form == FORM_CONSTRUCTED)) {
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		const ut8 *bend = buffer + length;
		if (end > bend) {
			free (object);
			return NULL;
		}
		if (end > buffer + length) {
			free (object);
			return NULL;
		}
		ut32 count = asn1_count_objects (object->sector, object->length);
		if (count == -1) {
			return NULL;
		}
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

R_API RAsn1 *r_asn1_new(const ut8 *buffer, int length, int fmtmode) {
	RAsn1 *a = R_NEW0 (RAsn1);
	a->buffer = buffer;
	a->length = length;
	a->fmtmode = fmtmode;
	switch (fmtmode) {
	case 'j':
		a->pj = pj_new ();
		pj_o (a->pj);
		pj_ka (a->pj, "root");
		break;
	}
	a->root = r_asn1_object_parse (buffer, buffer, length, fmtmode);
	if (a->root == NULL) {
		return NULL;
	}
	if (fmtmode == 'j') {
		pj_end (a->pj);
	}
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

R_API char *r_asn1_oid(RAsn1 *a) {
	char *res = NULL;
	RASN1String *s = r_asn1_stringify_oid (a->buffer, a->length);
	if (s) {
		if (a->fmtmode == 'j') {
			res = r_str_newf ("{\"oid\":\"%s\"}", s->string);
		} else {
			res = strdup (s->string);
		}
		r_asn1_string_free (s);
	}
	return res;
}

R_API char *r_asn1_tostring(RAsn1 *a) {
	PJ *pj = (a->fmtmode == 'j')? pj_new (): NULL;
	char *res = r_asn1_object_tostring (a->root, 0, NULL, pj, a->fmtmode);
	if (pj) {
		free (res);
		res = pj_drain (pj);
		return res;
	}
	return res;
}

R_API RASN1Binary *r_asn1_binary_new(const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	ut8* buf = (ut8*) calloc (1, length);
	if (!buf) {
		return NULL;
	}
	RASN1Binary* bin = R_NEW0 (RASN1Binary);
	memcpy (buf, buffer, length);
	bin->binary = buf;
	bin->length = length;
	return bin;
}

static void asn1_hexstring(RASN1Object *obj, char* buffer, ut32 size, ut32 depth, int fmtmode) {
	ut32 i;
	if (!obj || !obj->sector) {
		return;
	}
	char* p = buffer;
	char* end = buffer + size;
	if (depth > 0 && fmtmode == 'q') {
		const char *pad = r_str_pad (' ', (depth * 2) - 2);
		snprintf (p, end - p, "%s", pad);
		p += strlen (pad);
	}
	for (i = 0; i < obj->length && p < end; i++) {
		snprintf (p, end - p, "%02x", obj->sector[i]);
		p += 2;
	}
	if (p >= end) {
		p -= 4;
		snprintf (p, end - p, "...");
	}
}

static void asn1_printkv(RStrBuf *sb, RASN1Object *obj, int depth, const char *k, const char *v) {
	const char *pad = r_str_pad (' ', (depth * 2) - 2);
	if (obj->form && !*v) {
		return;
	}
	switch (obj->tag) {
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

static RASN1String* asn1_hexdump(RASN1Object *obj, ut32 depth, int fmtmode) {
	const char *pad;
	ut32 i, j;
	char readable[20] = {0};
	if (!obj || !obj->sector || obj->length < 1) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (fmtmode == 'j') {
		pad = "";
	} else if (fmtmode != 'q') {
		pad = "                                        : ";
	} else {
		pad = r_str_pad (' ', depth * 2);
		r_strbuf_append (sb, "  ");
	}

	const int length = obj->length;
	if (fmtmode == 'j') {
		for (i = 0; i < length; i++) {
			ut8 c = obj->sector[i];
			r_strbuf_appendf (sb, "%02x", c);
		}
	} else {
		for (i = 0, j = 0; i < length; i++, j++) {
			ut8 c = obj->sector[i];
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
	}
	char* text = r_strbuf_drain (sb);
	RASN1String* as = r_asn1_string_new (text, true, strlen (text) + 1);
	if (!as) {
		/* no memory left.. */
		free (text);
	}
	return as;
}

#if FASTERASN
/* This function is no longer needed when R2_600 is enabled, as headerlength is stored in the object */
#else
ut8 asn1_compute_header_length (ut8 klass, ut8 form, ut8 tag, ut32 content_length) {
	ut8 identifier_length;
	if (tag < 31) {
		identifier_length = 1;
	} else {
		identifier_length = 1;
		ut8 tag_octets = 0;
		while (tag > 0) {
			tag_octets++;
			tag >>= 7;
		}
		identifier_length += tag_octets;
	}
	ut8 length_field_length;
	if (content_length <= 127) {
		length_field_length = 1;
	} else {
		length_field_length = 1;
		ut8 length_octets = 0;
		while (content_length > 0) {
			length_octets++;
			content_length >>= 8;
		}
		length_field_length += length_octets;
	}
	ut8 header_length = identifier_length + length_field_length;
	return header_length;
}
#endif

// XXX this function signature is confusing
R_API char *r_asn1_object_tostring(RASN1Object *obj, ut32 depth, RStrBuf *sb, PJ *pj, int fmtmode) {
	bool root = false;
	if (!obj) {
		return NULL;
	}
	if (!sb) {
		sb = r_strbuf_new ("");
		root = true;
	}
	char temp_name[4096] = {0};
	ut32 i;
#if FASTERASN
	// Use the pre-calculated headerlength from the object
	ut8 hlen = obj->headerlength;
#else
	ut8 hlen = 0;
#endif
	// this shall not be freed. it's a pointer into the buffer.
	RASN1String* asn1str = NULL;
	const char* name = "";
	const char* string = "";

	switch (obj->klass) {
	case CLASS_UNIVERSAL: // universal
		switch (obj->tag) {
		case TAG_EOC:
			name = "EOC";
			break;
		case TAG_BOOLEAN:
			name = "BOOLEAN";
			if (obj->sector) {
				string = r_str_bool (obj->sector[0] != 0);
			}
			break;
		case TAG_INTEGER:
			name = "INTEGER";
			if (obj->length < 16) {
				asn1_hexstring (obj, temp_name, sizeof (temp_name), depth, fmtmode);
				string = temp_name;
			} else {
				asn1str = asn1_hexdump (obj, depth, fmtmode);
			}
			break;
		case TAG_BITSTRING:
			name = "BIT_STRING";
			if (!obj->list.objects) {
				if (obj->length < 16) {
					asn1_hexstring (obj, temp_name, sizeof (temp_name), depth, fmtmode);
					string = temp_name;
				} else {
					asn1str = asn1_hexdump (obj, depth, fmtmode);
				}
			}
			break;
		case TAG_OCTETSTRING:
			name = "OCTET_STRING";
			if (r_str_is_printable_limited ((const char *)obj->sector, obj->length)) {
				asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			} else if (!obj->list.objects) {
				if (obj->length < 16) {
					asn1_hexstring (obj, temp_name, sizeof (temp_name), depth, fmtmode);
					string = temp_name;
				} else {
					asn1str = asn1_hexdump (obj, depth, fmtmode);
				}
			}
			break;
		case TAG_NULL:
			name = "NULL";
			break;
		case TAG_OID:
			name = "OBJECT_IDENTIFIER";
			asn1str = r_asn1_stringify_oid (obj->sector, obj->length);
			break;
		case TAG_OBJDESCRIPTOR:
			name = "OBJECT_DESCRIPTOR";
			break;
		case TAG_EXTERNAL:
			name = "EXTERNAL";
			break;
		case TAG_REAL:
			name = "REAL";
			asn1str = asn1_hexdump (obj, depth, fmtmode);
			break;
		case TAG_ENUMERATED:
			name = "ENUMERATED";
			break;
		case TAG_EMBEDDED_PDV:
			name = "EMBEDDED_PDV";
			break;
		case TAG_UTF8STRING:
			name = "UTF8String";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_SEQUENCE:
			name = "SEQUENCE";
			break;
		case TAG_SET:
			name = "SET";
			break;
		case TAG_NUMERICSTRING:
			name = "NumericString";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_PRINTABLESTRING:
			name = "PrintableString"; // ASCII subset
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_T61STRING:
			name = "TeletexString"; // aka T61String
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_VIDEOTEXSTRING:
			name = "VideotexString";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_IA5STRING:
			name = "IA5String"; // ASCII
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_UTCTIME:
			name = "UTCTime";
			asn1str = r_asn1_stringify_utctime (obj->sector, obj->length);
			break;
		case TAG_GENERALIZEDTIME:
			name = "GeneralizedTime";
			asn1str = r_asn1_stringify_time (obj->sector, obj->length);
			break;
		case TAG_GRAPHICSTRING:
			name = "GraphicString";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_VISIBLESTRING:
			name = "VisibleString"; // ASCII subset
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_GENERALSTRING:
			name = "GeneralString";
			break;
		case TAG_UNIVERSALSTRING:
			name = "UniversalString";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		case TAG_BMPSTRING:
			name = "BMPString";
			asn1str = r_asn1_stringify_string (obj->sector, obj->length);
			break;
		default:
			snprintf (temp_name, sizeof (temp_name), "Universal_%u", obj->tag);
			name = temp_name;
			break;
		}
		break;
	case CLASS_APPLICATION:
		snprintf (temp_name, sizeof (temp_name), "Application_%u", obj->tag);
		name = temp_name;
		break;
	case CLASS_CONTEXT:
		snprintf (temp_name, sizeof (temp_name), "Context [%u]", obj->tag); // Context
		name = temp_name;
		break;
	case CLASS_PRIVATE:
		snprintf (temp_name, sizeof (temp_name), "Private_%u", obj->tag);
		name = temp_name;
		break;
	}
	if (asn1str) {
		string = asn1str->string;
	}

#if FASTERASN
	// We already have the header length stored in the object
#else
	// Compute header length
	hlen = asn1_compute_header_length (obj->klass, obj->form, obj->tag, obj->length);
#endif
	// Adapt size for BITSTRING
	if (obj->tag == TAG_BITSTRING) {
		obj->length++;
	}

	switch (fmtmode) {
	case 'q': // pFaq
		// QUIET MODE
		asn1_printkv (sb, obj, depth, name, string);
		if (obj->list.objects) {
			for (i = 0; i < obj->list.length; i++) {
				RASN1Object *o = obj->list.objects[i];
				char *s = r_asn1_object_tostring (o, depth + 1, sb, pj, fmtmode);
				eprintf ("-> %s\n", s);
				free (s);
			}
		}
		break;
	case 'r':
		// TODO: add comments
		break;
	case 'j': // pFaj
		// return pj_drain (pj);
		pj_o (pj);
		pj_kn (pj, "offset", obj->offset);
		pj_kn (pj, "length", obj->length);
		pj_ks (pj, "form", obj->form? "cons": "prim");
		pj_ks (pj, "name", name);
		if (R_STR_ISNOTEMPTY (string)) {
			pj_ks (pj, "value", string);
		}
		if (obj->list.objects) {
			pj_ka (pj, "children");
			for (i = 0; i < obj->list.length; i++) {
				char *s = r_asn1_object_tostring (obj->list.objects[i], depth + 1, sb, pj, fmtmode);
				free (s);
			}
			pj_end (pj);
		}
		pj_end (pj);
		break;
	case 't': // pFat
		if (root) {
			r_strbuf_append (sb, ".\n");
		} else {
			for (i = 0; i < depth; i++) {
				r_strbuf_append (sb, "│ ");
			}
		}
		if (obj->tag == TAG_SEQUENCE || obj->tag == TAG_SET || obj->klass == CLASS_CONTEXT) {
			r_strbuf_append (sb, "├─┬ ");
		} else {
			if (obj->list.objects) {
				r_strbuf_append (sb, "├── ");
			} else {
				r_strbuf_append (sb, "└── ");
			}
		}
#if FASTERASN
		r_strbuf_appendf (sb, " [@ 0x%" PFMT64x "](0x%x + 0x%x)", obj->offset, hlen, obj->length);
#else
		r_strbuf_appendf (sb, " [@ 0x%" PFMT64x "](0x%x + 0x%x)", obj->offset, hlen, obj->length);
#endif
		if (obj->tag == TAG_BITSTRING || obj->tag == TAG_INTEGER || obj->tag == TAG_GENERALSTRING) {
			asn1_hexstring (obj, temp_name, sizeof (temp_name), depth, fmtmode);
			if (strlen (temp_name) > 100) {
				r_strbuf_append (sb, " - ");
				r_strbuf_append_n (sb, temp_name, 100);
				r_strbuf_append (sb, "...");
			} else {
				r_strbuf_appendf (sb, " - %s", temp_name);
			}
		} else if (obj->tag == TAG_SEQUENCE || obj->tag == TAG_SET) {
			r_strbuf_appendf (sb, " - %02x", obj->tag | 0x20);
		} else {
			if (strlen (string) > 100) {
				r_strbuf_append (sb, " - ");
				r_strbuf_append_n (sb, string, 100);
				r_strbuf_append (sb, "...");
			} else {
				r_strbuf_appendf (sb, " - %s", string);
			}
		}
		r_strbuf_append (sb, "\n");

		if (obj->list.objects) {
			for (i = 0; i < obj->list.length; i++) {
				r_asn1_object_tostring (obj->list.objects[i], depth + 1, sb, pj, fmtmode);
			}
		}
		break;
	case 0: // verbose default
	default:
		if (root) {
			r_strbuf_appendf (sb, "%8s %4s %s %6s %5s %4s %-20s: %s", "OFFSET", "HDR", "+", "OBJ", "DEPTH", "FORM", "NAME", "VALUE\n");
		}
		r_strbuf_appendf (sb, "%#8" PFMT64x, obj->offset);
#if FASTERASN
		r_strbuf_appendf (sb, " %#4x + %#6x %5d %4s %-20s: ", hlen, obj->length, depth, obj->form? "cons": "prim", name);
#else
		r_strbuf_appendf (sb, " %#4x + %#6x %5d %4s %-20s: ", hlen, obj->length, depth, obj->form? "cons": "prim", name);
#endif
		if (obj->tag == TAG_BITSTRING || obj->tag == TAG_INTEGER || obj->tag == TAG_GENERALSTRING) {
			asn1_hexstring (obj, temp_name, sizeof (temp_name), depth, fmtmode);
			if (strlen (temp_name) > 100) {
				r_strbuf_append_n (sb, temp_name, 100);
				r_strbuf_append (sb, "...");
			} else {
				r_strbuf_appendf (sb, "%s", temp_name);
			}
		} else if (obj->tag == TAG_SEQUENCE || obj->tag == TAG_SET) {
			r_strbuf_appendf (sb, "%02x", obj->tag | 0x20);
		} else {
			if (strlen (string) > 100) {
				r_strbuf_append_n (sb, string, 100);
				r_strbuf_append (sb, "...");
			} else {
				r_strbuf_appendf (sb, "%s", string);
			}
		}

		// We may have a bit length diffrent than the length
		if (obj->length * 8 != obj->bitlength) {
			r_strbuf_appendf (sb, " (%u bits)", obj->bitlength);
		}
		r_strbuf_append (sb, "\n");
		if (obj->list.objects) {
			for (i = 0; i < obj->list.length; i++) {
				r_asn1_object_tostring (obj->list.objects[i], depth + 1, sb, pj, fmtmode);
			}
		}
		break;
	}
	r_asn1_string_free (asn1str);
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
