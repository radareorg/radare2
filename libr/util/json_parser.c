/* radare - LGPL - Copyright 2020 - thestr4ng3r, Yaroslav Stavnichiy */

#include <errno.h>

#include <r_util/r_utf8.h>
#include <r_util/r_hex.h>
#include <r_util/r_json.h>

#if 0
// optional error printing
#define R_JSON_REPORT_ERROR(msg, p) fprintf(stderr, "R_JSON PARSE ERROR (%d): " msg " at %s\n", __LINE__, p)
#else
#define R_JSON_REPORT_ERROR(msg, p) do { (void)(msg); (void)(p); } while (0)
#endif

static RJson *json_new(void) {
	return R_NEW0 (RJson);
}

static RJson *create_json(RJsonType type, const char *key, RJson *parent) {
	RJson *js = json_new ();
	if (!js) {
		return NULL;
	}
	js->type = type;
	js->key = key;
	if (!parent->children.last) {
		parent->children.first = parent->children.last = js;
	} else {
		parent->children.last->next = js;
		parent->children.last = js;
	}
	parent->children.count++;
	return js;
}

R_API void r_json_free(RJson *js) {
	if (!js) {
		return;
	}
	if (js->type == R_JSON_OBJECT || js->type == R_JSON_ARRAY) {
		RJson *p = js->children.first;
		RJson *p1;
		while (p) {
			p1 = p->next;
			r_json_free (p);
			p = p1;
		}
	}
	free (js);
}

static char *unescape_string(char *s, char **end) {
	char *p = s;
	char *d = s;
	char c;
	while ((c = *p++)) {
		if (c == '"') {
			*d = '\0';
			*end = p;
			return s;
		}
		if (c == '\\') {
			switch (*p) {
			case '\\':
			case '/':
			case '"':
				*d++ = *p++;
				break;
			case 'b':
				*d++ = '\b';
				p++;
				break;
			case 'f':
				*d++ = '\f';
				p++;
				break;
			case 'n':
				*d++ = '\n';
				p++;
				break;
			case 'r':
				*d++ = '\r';
				p++;
				break;
			case 't':
				*d++ = '\t';
				p++;
				break;
			case 'u': { // unicode
				char *ps = p - 1;
				ut8 high = 0, low = 0;
				if (r_hex_to_byte (&high, p[1]) || r_hex_to_byte (&high, p[2])
						|| r_hex_to_byte (&low, p[3]) || r_hex_to_byte (&low, p[4])) {
					R_JSON_REPORT_ERROR ("invalid unicode escape", p - 1);
					return NULL;
				}
				RRune codepoint = (RRune)high << 8 | (RRune)low;
				if ((codepoint & 0xfc00) == 0xd800) { // high surrogate; need one more unicode to succeed
					p += 6;
					high = low = 0;
					if (p[-1] != '\\' || *p != 'u'
							|| r_hex_to_byte (&high, p[1]) || r_hex_to_byte (&high, p[2])
							|| r_hex_to_byte (&low, p[3]) || r_hex_to_byte (&low, p[4])) {
						R_JSON_REPORT_ERROR ("invalid unicode surrogate", ps);
						return NULL;
					}
					RRune codepoint2 = (RRune)high << 8 | (RRune)low;
					if ((codepoint2 & 0xfc00) != 0xdc00) {
						R_JSON_REPORT_ERROR ("invalid unicode surrogate", ps);
						return NULL;
					}
					codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (codepoint2 - 0xdc00);
				}
				int sz = r_utf8_encode ((ut8 *)d, codepoint);
				if (!s) {
					R_JSON_REPORT_ERROR ("invalid codepoint", ps);
					return NULL;
				}
				d += sz;
				p += 5;
				break;
			}
			default:
				// leave untouched
				*d++ = c;
				break;
			}
		} else {
			*d++ = c;
		}
	}
	R_JSON_REPORT_ERROR ("no closing quote for string", s);
	return NULL;
}

static char *skip_block_comment(char *ps) {
	// ps is at "/* ..."
	// caller must ensure that ps[0], ps[1] and ps[2] are valid.
	char *p = ps + 2;
	if (!*p) {
		R_JSON_REPORT_ERROR ("endless comment", ps);
		return NULL;
	}
	REPEAT:
	p = strchr (p + 1, '/');
	if (!p) {
		R_JSON_REPORT_ERROR ("endless comment", ps);
		return NULL;
	}
	if (p[-1] != '*') {
		goto REPEAT;
	}
	return p + 1;
}

static char *skip_whitespace(char *p) {
	while (*p) {
		if (*p == '/') {
			if (p[1] == '/') { // line comment
				char *ps = p;
				p = strchr (p + 2, '\n');
				if (!p) {
					R_JSON_REPORT_ERROR ("endless comment", ps);
					return NULL; // error
				}
				p++;
			} else if (p[1] == '*') { // block comment
				p = skip_block_comment (p);
				if (!p) {
					return NULL;
				}
				continue;
			} else {
				R_JSON_REPORT_ERROR ("unexpected chars", p);
				return NULL; // error
			}
			continue;
		} else if (!IS_WHITECHAR (*p)) {
			break;
		}
		p++;
	}
	return p;
}

static char *parse_key(const char **key, char *p) {
	// on '}' return with *p=='}'
	p = skip_whitespace (p);
	if (!p) {
		return NULL;
	}
	char c;
	while ((c = *p++)) {
		if (c == '"') {
			*key = unescape_string (p, &p);
			if (!*key) {
				return NULL; // propagate error
			}
			p = skip_whitespace (p);
			if (!p) {
				return NULL;
			}
			if (*p == ':') {
				return p + 1;
			}
			R_JSON_REPORT_ERROR ("unexpected chars", p);
			return NULL;
		}
		if (c == '}') {
			return p - 1;
		}
		R_JSON_REPORT_ERROR ("unexpected chars", p - 1);
		return NULL; // error
	}
	R_JSON_REPORT_ERROR ("unexpected chars", p - 1);
	return NULL; // error
}

static char *parse_value(RJson *parent, const char *key, char *p) {
	RJson *js;
	p = skip_whitespace (p);
	if (!p) {
		return NULL;
	}
	switch (*p) {
	case '\0':
		R_JSON_REPORT_ERROR ("unexpected end of text", p);
		return NULL; // error
	case '{':
		js = create_json (R_JSON_OBJECT, key, parent);
		p++;
		while (1) {
			const char *new_key = NULL;
			p = parse_key (&new_key, p);
			if (!p) {
				return NULL; // error
			}
			if (*p != '}') {
				p = parse_value (js, new_key, p);
				if (!p) {
					return NULL; // error
				}
			}
			p = skip_whitespace (p);
			if (!p) {
				return NULL;
			}
			if (*p == ',') {
				char *commapos = p;
				p++;
				p = skip_whitespace (p);
				if (!p) {
					return NULL;
				}
				if (*p == '}') {
					R_JSON_REPORT_ERROR ("trailing comma", commapos);
					return NULL;
				}
			} else if (*p == '}') {
				return p + 1; // end of object
			} else {
				R_JSON_REPORT_ERROR ("unexpected chars", p);
				return NULL;
			}
		}
	case '[':
		js = create_json (R_JSON_ARRAY, key, parent);
		p++;
		while (1) {
			p = parse_value (js, 0, p);
			if (!p) {
				return NULL; // error
			}
			p = skip_whitespace (p);
			if (!p) {
				return NULL;
			}
			if (*p == ',') {
				char *commapos = p;
				p++;
				p = skip_whitespace (p);
				if (!p) {
					return NULL;
				}
				if (*p == ']') {
					R_JSON_REPORT_ERROR ("trailing comma", commapos);
					return NULL;
				}
			} else if (*p == ']') {
				return p + 1; // end of array
			} else {
				R_JSON_REPORT_ERROR ("unexpected chars", p);
				return NULL;
			}
		}
	case ']':
		return p;
	case '"':
		p++;
		js = create_json (R_JSON_STRING, key, parent);
		js->str_value = unescape_string (p, &p);
		if (!js->str_value) {
			return NULL; // propagate error
		}
		return p;
	case '-':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9': {
		js = create_json (R_JSON_INTEGER, key, parent);
		errno = 0;
		char *pe;
		if (*p == '-') {
			js->num.s_value = (st64)strtoll (p, &pe, 10);
		} else {
			js->num.u_value = (ut64)strtoull (p, &pe, 10);
		}
		if (pe == p || errno == ERANGE) {
			R_JSON_REPORT_ERROR ("invalid number", p);
			return NULL; // error
		}
		if (*pe == '.' || *pe == 'e' || *pe == 'E') { // double value
			js->type = R_JSON_DOUBLE;
			errno = 0;
			js->num.dbl_value = strtod (p, &pe);
			if (pe == p || errno == ERANGE) {
				R_JSON_REPORT_ERROR ("invalid fractional number", p);
				return NULL; // error
			}
		} else {
			if (*p == '-') {
				js->num.dbl_value = js->num.s_value;
			} else {
				js->num.dbl_value = js->num.u_value;
			}
		}
		return pe;
	}
	case 't':
		if (!strncmp (p, "true", 4)) {
			js = create_json (R_JSON_BOOLEAN, key, parent);
			js->num.u_value = 1;
			return p + 4;
		}
		R_JSON_REPORT_ERROR ("unexpected chars", p);
		return NULL; // error
	case 'f':
		if (!strncmp (p, "false", 5)) {
			js = create_json (R_JSON_BOOLEAN, key, parent);
			js->num.u_value = 0;
			return p + 5;
		}
		R_JSON_REPORT_ERROR ("unexpected chars", p);
		return NULL; // error
	case 'n':
		if (!strncmp (p, "null", 4)) {
			create_json (R_JSON_NULL, key, parent);
			return p + 4;
		}
		R_JSON_REPORT_ERROR ("unexpected chars", p);
		return NULL; // error
	default:
		R_JSON_REPORT_ERROR ("unexpected chars", p);
		return NULL; // error
	}
	return NULL;
}

R_API RJson *r_json_parse(char *text) {
	RJson js = {0};
	if (!parse_value (&js, 0, text)) {
		if (js.children.first) {
			r_json_free (js.children.first);
		}
		return 0;
	}
	return js.children.first;
}

R_API const RJson *r_json_get(const RJson *json, const char *key) {
	RJson *js;
	for (js = json->children.first; js; js = js->next) {
		if (js->key && !strcmp (js->key, key)) {
			return js;
		}
	}
	return NULL;
}

R_API const RJson *r_json_item(const RJson *json, size_t idx) {
	RJson *js;
	for (js = json->children.first; js; js = js->next) {
		if (!idx--) {
			return js;
		}
	}
	return NULL;
}

