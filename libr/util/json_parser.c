/* radare - LGPL - Copyright 2020-2025 - thestr4ng3r, Yaroslav Stavnichiy, pancake */

#define R_LOG_ORIGIN "json.parse"

#include <errno.h>

#include <r_util.h>
#include <r_util/r_utf8.h>
#include <r_util/r_hex.h>
#include <r_util/r_json.h>

static RJson *create_json(RJsonType type, const char *key, RJson *parent) {
	RJson *js = R_NEW0 (RJson);
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
					R_LOG_ERROR ("invalid unicode escape (%s)", p - 1);
					return NULL;
				}
				RRune codepoint = (RRune)high << 8 | (RRune)low;
				if ((codepoint & 0xfc00) == 0xd800) { // high surrogate; need one more unicode to succeed
					p += 6;
					high = low = 0;
					if (p[-1] != '\\' || *p != 'u'
							|| r_hex_to_byte (&high, p[1]) || r_hex_to_byte (&high, p[2])
							|| r_hex_to_byte (&low, p[3]) || r_hex_to_byte (&low, p[4])) {
						R_LOG_ERROR ("invalid unicode surrogate (%s)", ps);
						return NULL;
					}
					RRune codepoint2 = (RRune)high << 8 | (RRune)low;
					if ((codepoint2 & 0xfc00) != 0xdc00) {
						R_LOG_ERROR ("invalid unicode surrogate (%s)", ps);
						return NULL;
					}
					codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (codepoint2 - 0xdc00);
				}
				int sz = r_utf8_encode ((ut8 *)d, codepoint);
				if (!s) {
					R_LOG_ERROR ("invalid codepoint (%s)", ps);
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
	R_LOG_ERROR ("no closing quote for string (%s)", s);
	return NULL;
}

static char *skip_block_comment(char *ps) {
	// ps is at "/* ..."
	// caller must ensure that ps[0], ps[1] and ps[2] are valid.
	char *p = ps + 2;
	if (!*p) {
		R_LOG_ERROR ("endless comment (%s)", ps);
		return NULL;
	}
	REPEAT:
	p = strchr (p + 1, '/');
	if (!p) {
		R_LOG_ERROR ("endless comment (%s)", ps);
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
					R_LOG_ERROR ("endless comment (%s)", ps);
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
				R_LOG_ERROR ("unexpected chars (%s)", p);
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
	// on '}' return with *p == '}'
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
			R_LOG_ERROR ("unexpected chars (%s)", p);
			return NULL;
		}
		if (c == '}') {
			return p - 1;
		}
		R_LOG_ERROR ("unexpected chars (%s)", p - 1);
		return NULL; // error
	}
	R_LOG_ERROR ("unexpected chars (%s)", p - 1);
	return NULL; // error
}

static char *parse_value(RJson *parent, const char * R_NULLABLE key, char *p) {
	R_RETURN_VAL_IF_FAIL (parent && p, NULL);
	RJson *js;
	p = skip_whitespace (p); // TODO: use r_str_trim_head_ro()
	if (!p) {
		return NULL;
	}
	switch (*p) {
	case '\0':
		R_LOG_ERROR ("unexpected end of text (%s)", p);
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
					R_LOG_ERROR ("trailing comma (%s)", commapos);
					return NULL;
				}
			} else if (*p == '}') {
				return p + 1; // end of object
			} else {
				R_LOG_ERROR ("unexpected chars (%s)", p);
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
					R_LOG_ERROR ("trailing comma (%s)", commapos);
					return NULL;
				}
			} else if (*p == ']') {
				return p + 1; // end of array
			} else {
				R_LOG_ERROR ("unexpected chars (%s)", p);
				return NULL;
			}
		}
	case ']':
		return p;
	case '"':
		p++;
		js = create_json (R_JSON_STRING, key, parent);
		if (js) {
			js->str_value = unescape_string (p, &p);
			if (!js->str_value) {
				return NULL; // propagate error
			}
			return p;
		}
		return NULL;
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
			R_LOG_ERROR ("invalid number (%s)", p);
			return NULL; // error
		}
		if (*pe == '.' || *pe == 'e' || *pe == 'E') { // double value
			js->type = R_JSON_DOUBLE;
			errno = 0;
			js->num.dbl_value = strtod (p, &pe);
			if (pe == p || errno == ERANGE) {
				R_LOG_ERROR ("invalid fractional number (%s)", p);
				return NULL; // error
			}
		} else {
			if (*p == '-') {
				js->num.dbl_value = (double) js->num.s_value;
			} else {
				js->num.dbl_value = (double) js->num.u_value;
			}
		}
		return pe;
	}
	case 't':
		if (r_str_startswith (p, "true")) {
			js = create_json (R_JSON_BOOLEAN, key, parent);
			if (js) {
				js->num.u_value = 1;
				return p + 4;
			}
			return NULL;
		}
		R_LOG_ERROR ("unexpected chars (%s)", p);
		return NULL; // error
	case 'f':
		if (r_str_startswith (p, "false")) {
			js = create_json (R_JSON_BOOLEAN, key, parent);
			if (R_LIKELY (js)) {
				js->num.u_value = 0;
				return p + 5;
			}
			return NULL;
		}
		R_LOG_ERROR ("unexpected chars (%s)", p);
		return NULL; // error
	case 'n':
		if (r_str_startswith (p, "null")) {
			create_json (R_JSON_NULL, key, parent);
			return p + 4;
		}
		R_LOG_ERROR ("unexpected chars (%s)", p);
		return NULL; // error
	default:
		R_LOG_ERROR ("unexpected chars (%s)", p);
		return NULL; // error
	}
	return NULL;
}

R_API R_MUSTUSE RJson *r_json_parse(R_BORROW char *text) {
	R_RETURN_VAL_IF_FAIL (text, NULL);
	RJson js = {0};
	bool res = parse_value (&js, 0, text);
	if (!res) {
		r_json_free (js.children.first);
		return NULL;
	}
	return js.children.first;
}

R_API const RJson *r_json_get(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json, NULL);
	RJson *js;
	for (js = json->children.first; js; js = js->next) {
		if (js->key && !strcmp (js->key, key)) {
			return js;
		}
	}
	return NULL;
}

R_API st64 r_json_get_num(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, 0);

	const RJson *field = r_json_get (json, key);
	if (!field) {
		return 0;
	}
	switch (field->type) {
	case R_JSON_STRING:
		return r_num_get (NULL, field->str_value);
	case R_JSON_INTEGER:
		return field->num.s_value;
	case R_JSON_BOOLEAN:
		return field->num.u_value;
	case R_JSON_DOUBLE:
		return (int)field->num.dbl_value;
	default:
		return 0;
	}
}

R_API const char *r_json_get_str(const RJson *json, const char *key) {
	R_RETURN_VAL_IF_FAIL (json && key, NULL);

	const RJson *field = r_json_get (json, key);
	if (!field || field->type != R_JSON_STRING) {
		return NULL;
	}

	return field->str_value;
}


R_API const RJson *r_json_item(const RJson *json, size_t idx) {
	R_RETURN_VAL_IF_FAIL (json, NULL);
	RJson *js;
	for (js = json->children.first; js; js = js->next) {
		if (!idx--) {
			return js;
		}
	}
	return NULL;
}

R_API const char *r_json_type(const RJson *json) {
	R_RETURN_VAL_IF_FAIL (json, NULL);
	switch (json->type) {
	case R_JSON_ARRAY:
		return "array";
	case R_JSON_OBJECT:
		return "object";
	case R_JSON_INTEGER:
		return "integer";
	case R_JSON_BOOLEAN:
		return "boolean";
	case R_JSON_DOUBLE:
		return "double";
	case R_JSON_STRING:
		return "string";
	case R_JSON_NULL:
		return "null";
	}
	return "";
}
