/* radare - LGPL - Copyright 2007-2025 - pancake */

#include <r_util.h>

static const char abc[] = "0123456789abcdef";

static int hex_digit_value(char c) {
	if (isdigit (c)) {
		return c - '0';
	}
	const char lc = tolower (c);
	if (lc >= 'a' && lc <= 'f') {
		return lc - 'a' + 10;
	}
	return -1;
}

// XXX this function returns true when there's an error wtf
R_API bool r_hex_to_byte(ut8 *val, ut8 c) {
	R_RETURN_VAL_IF_FAIL (val, false);
	int v = hex_digit_value (c);
	if (v != -1) {
		*val <<= 4;
		*val |= v & 0xf;
		return false;
	}
	return true;
}

// takes 'c' byte and fills 2 bytes in the val string
R_API void r_hex_from_byte(char *val, ut8 c) {
	val[0] = abc[(c >> 4) & 0xf];
	val[1] = abc[c & 0xf];
	// val[2] = 0
}

R_API char *r_hex_from_py_str(char *out, const char *code) {
	if (r_str_startswith (code, "'''")) {
		const char *s = code + 2;
		return r_hex_from_c_str (out, &s);
	}
	return r_hex_from_c_str (out, &code);
}

static const char *skip_comment_py(const char *code) {
	if (*code != '#') {
		return code;
	}
	char *end = strchr (code, '\n');
	if (end) {
		code = end;
	}
	return code + 1;
}

R_API char *r_hex_from_py_array(char *out, const char *code) {
	R_RETURN_VAL_IF_FAIL (out && code, NULL);
	if (*code != '[' || !strchr (code, ']')) {
		return NULL;
	}
	code++;
	for (; *code; code++) {
		char *comma = strchr (code, ',');
		if (!comma) {
			comma = strchr (code, ']');
		}
		if (!comma) {
			break;
		}
		char * _word = r_str_ndup (code, comma - code);
		const char *word = _word;
		while (*word == ' ' || *word == '\t' || *word == '\n') {
			word++;
			word = skip_comment_py (word);
		}
		if (isdigit (*word)) {
			ut8 n = (ut8)r_num_math (NULL, word);
			*out++ = abc[(n >> 4) & 0xf];
			*out++ = abc[n & 0xf];
		}
		free (_word);
		code = comma;
		if (*code == ']') {
			break;
		}
	}
	return out;
}

R_API char* r_hex_from_py(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	char * const ret = malloc (strlen (code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	const char *tmp_code = strchr (code, '=');
	if (tmp_code) {
		code = tmp_code;
	}
	for (; *code && *code != '[' && *code != '\''
	  && *code != '"'; code++) {
		code = skip_comment_py (code);
	}
	if (*code == '[') {
		out = r_hex_from_py_array (out, code);
	} else if (*code == '"' || *code == '\'') {
		out = r_hex_from_py_str (out, code);
	}
	if (!out) {
		free (ret);
		return NULL;
	}
	*out = '\0';
	return ret;
}

R_API char *r_hex_from_c_str(char *out, const char **code) {
	R_RETURN_VAL_IF_FAIL (out && code, NULL);
	const char *iter = *code;
	if (*iter != '\'' && *iter != '"') {
		return NULL;
	}
	const char end_char = *iter;
	iter++;
	for (; *iter && *iter != end_char; iter++) {
		if (*iter == '\\') {
			iter++;
			switch (iter[0]) {
			case 'e': *out++ = '1'; *out++ = 'b'; break;
			case 'r': *out++ = '0'; *out++ = 'd'; break;
			case 'n': *out++ = '0'; *out++ = 'a'; break;
			case 'x': {
				ut8 c1 = iter[1];
				ut8 c2 = iter[2];
				iter += 2;
				if (c1 == '\0' || c2 == '\0') {
					return NULL;
				}
				if (strchr (abc, c1) && strchr (abc, c2)) {
					*out++ = tolower (c1);
					*out++ = tolower (c2);
				} else {
					return NULL;
				}
				break;
			  }
			default:
				if (iter[0] == end_char) {
					*out++ = abc[*iter >> 4];
					*out++ = abc[*iter & 0xf];
				}
				return NULL;
			}
		} else {
			*out++ = abc[*iter >> 4];
			*out++ = abc[*iter & 0xf];
		}
	}
	*code = iter;
	return out;
}

static const char *skip_comment_c(const char *code) {
	if (r_str_startswith (code, "/*")) {
		char *end = strstr (code, "*/");
		if (end) {
			code = end + 2;
		} else {
			R_LOG_ERROR ("Missing closing comment");
		}
	} else if (r_str_startswith (code, "//")) {
		char *end = strchr (code, '\n');
		if (end) {
			code = end + 2;
		}
	}
	return code;
}

R_API char *r_hex_from_c_array(char *out, const char *code) {
	R_RETURN_VAL_IF_FAIL (out && code, NULL);
	if (*code != '{' || !strchr (code, '}')) {
		return NULL;
	}
	code++;
	for (; *code; code++) {
		const char *comma = strchr (code, ',');
		if (!comma) {
			comma = strchr (code, '}');
		}
		char * _word = r_str_ndup (code, comma - code);
		const char *word = _word;
		word = skip_comment_c (word);
		while (*word == ' ' || *word == '\t' || *word == '\n') {
			word++;
			word = skip_comment_c (word);
		}
		if (isdigit (*word)) {
			ut8 n = (ut8)r_num_math (NULL, word);
			*out++ = abc[(n >> 4) & 0xf];
			*out++ = abc[n & 0xf];
		}
		free (_word);
		code = comma;
		if (*code == '}') {
			break;
		}
	}
	return out;
}

/* convert:
 *    char *foo = "\x41\x23\x42\x1b";
 * into:
 *    4123421b
 */
R_API char *r_hex_from_c(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	char * const ret = malloc (strlen (code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	const char *tmp_code = strchr (code, '=');
	if (tmp_code) {
		code = tmp_code;
	}
	for (; *code != '\0' && *code != '{' && *code != '"'; code++) {
		code = skip_comment_c (code);
	}
	if (*code == '{') {
		out = r_hex_from_c_array (out, code);
	} else if (*code == '"') {
		const char *s1, *s2;
		s1 = code;
		do {
			code = s1;
			out = r_hex_from_c_str (out, &code);
			if (!out) {
				break;
			}
			s1 = strchr (code + 1, '"');
			s2 = strchr (code + 1, ';');
		} while (s1 && s2 && (s1 <= s2));
	}
	if (!out) {
		free (ret);
		return NULL;
	}
	*out = '\0';
	return ret;
}

R_API char *r_hex_from_js(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	char *s1 = strchr (code, '\'');
	char *s2 = strchr (code, '"');

	/* there are no strings in the input */
	if (!s1 || !s2) {
		return NULL;
	}

	char *start;
	char *end;
	if (s1 < s2) {
		start = s1;
		end = strchr (start + 1, '\'');
	} else {
		start = s2;
		end = strchr (start + 1, '"');
	}

	/* the string isn't properly terminated */
	if (!end) {
		return NULL;
	}

	size_t slen = end - start;
	char *str = r_str_ndup (start + 1, slen - 1);

	/* assuming base64 input, output will always be shorter */
	ut8 *b64d = malloc (slen);
	if (!b64d) {
		free (str);
		return NULL;
	}

	int olen = r_base64_decode (b64d, str, slen - 1);
	free (str);
	if (!b64d) {
		free (b64d);
		return NULL;
	}

	char *out = r_hex_bin2strdup (b64d, olen);
	free (b64d);
	return out;
}

/* convert
 * "\x41\x23\x42\x1b"
 * "\x41\x23\x42\x1b"
 * into
 * 4123421b4123421b
 */
R_API char *r_hex_no_code(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	char * const ret = calloc (1, strlen (code) * 3);
	if (!ret) {
		return NULL;
	}
	*ret = '\0';
	char *out = ret;
	out = r_hex_from_c_str (out, &code);
	code = strchr (code + 1, '"');
	if (!out) {
		free (ret);
		return NULL;
	}
	*out = '\0';
	while (out && code) {
		*out = '\0';
		out = r_hex_from_c_str (out, &code);
		code = strchr (code + 1, '"');
	}
	return ret;
}

R_API char *r_hex_from_code(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	if (!strchr (code, '=')) {
		return r_hex_no_code (code);
	}
	/* C language */
	if (strstr (code, "char") || strstr (code, "int")) {
		return r_hex_from_c (code);
	}
	/* JavaScript */
	if (strstr (code, "var")) {
		return r_hex_from_js (code);
	}
	/* Python */
	return r_hex_from_py (code);
}

/* int byte = r_hex_pair2bin("A0"); */
// (0A) => 10 || -1 (on error)
R_API int r_hex_pair2bin(const char *arg) {
	R_RETURN_VAL_IF_FAIL (arg, 0);
	ut8 *ptr, c = 0, d = 0;
	ut32 j = 0;

	for (ptr = (ut8*)arg; ;ptr = ptr + 1) {
		if (!*ptr || *ptr == ' ' || j == 2) {
			break;
		}
		d = c;
		if (*ptr != '.' && r_hex_to_byte (&c, *ptr)) {
			R_LOG_ERROR ("Invalid hexa string at char '%c' (%s)", *ptr, arg);
			return -1;
		}
		c |= d;
		if (j++ == 0) {
			c <<= 4;
		}
	}
	return (int)c;
}

R_API int r_hex_bin2str(const ut8 *in, int len, char *out) {
	R_RETURN_VAL_IF_FAIL (in && len > 0, 0);
	int i, idx;
	char tmp[8];
	for (idx = i = 0; i < len; i++, idx += 2)  {
		r_hex_from_byte (tmp, in[i]);
		memcpy (out + idx, tmp, 2);
	}
	out[idx] = 0;
	return len;
}

R_API char *r_hex_bin2strdup(const ut8 *in, int len) {
	R_RETURN_VAL_IF_FAIL (in && len > 0, NULL);
	int i, idx;

	if ((len + 1) * 2 < len) {
		return NULL;
	}
	char *out = malloc ((len + 1) * 2);
	if (!out) {
		return NULL;
	}
	char tmp[5];
	for (i = idx = 0; i < len; i++, idx += 2)  {
		r_hex_from_byte (tmp, in[i]);
		memcpy (out+idx, tmp, 2);
	}
	out[idx] = 0;
	return out;
}

R_API int r_hex_str2bin(const char *in, ut8 *out) {
	R_RETURN_VAL_IF_FAIL (in, 0);
	long nibbles = 0;

	while (in && *in) {
		ut8 tmp;
		/* skip hex prefix */
		if (*in == '0' && in[1] == 'x') {
			in += 2;
		}
		/* read hex digits */
		while (!r_hex_to_byte (out ? &out[nibbles/2] : &tmp, *in)) {
			nibbles++;
			in++;
		}
		if (*in == '\0') {
			break;
		}
		/* comments */
		if (*in == '#' || (*in == '/' && in[1] == '/')) {
			if ((in = strchr (in, '\n'))) {
				in++;
			}
			continue;
		} else if (*in == '/' && in[1] == '*') {
			if ((in = strstr (in, "*/"))) {
				in += 2;
			}
			continue;
		} else if (!IS_WHITESPACE (*in) && *in != '\n') {
			/* this is not a valid string */
			return 0;
		}
		/* ignore character */
		in++;
	}

	if (nibbles % 2) {
		if (out) {
			r_hex_to_byte (&out[nibbles / 2], '0');
		}
		return -((nibbles + 1) / 2);
	}

	return nibbles / 2;
}

// get the hex chars from start of string, until first non-hex char, as a heap
// allocated ut8* buffer
R_API int r_hex_str2bin_until_new(const char *in, ut8 **out) {
	R_RETURN_VAL_IF_FAIL (in && out, -1);
	size_t len = strlen (in);
	if (len <= 1) {
		return 0;
	}
	len = (len + 1) / 2;

	int ret = -1;
	size_t nibbles = 0;
	ut8 *buf = calloc (1, len);
	if (buf) {
		while (!r_hex_to_byte (buf + (nibbles / 2), *in)) {
			nibbles++;
			in++;
		}

		if (!nibbles || nibbles % 2) {
			ret = 0;
		} else {
			ret = nibbles / 2;
			*out = (ut8*)realloc (buf, ret);
			if (!*out) {
				ret = -1;
			}
		}

		if (ret <= 0) {
			free (buf);
		}
	}
	return ret;
}

R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask) {
	R_RETURN_VAL_IF_FAIL (in && out && mask, -1);
	ut8 *ptr;
	int ilen = strlen (in) + 1;
	memcpy (out, in, ilen);
	for (ptr = out; *ptr; ptr++) {
		if (*ptr == '.') {
			*ptr = '0';
		}
	}
	int len = r_hex_str2bin ((char*)out, out);
	bool has_nibble = false;
	if (len < 0) {
		has_nibble = true;
		len = -(len + 1);
	}
	if (len != -1) {
		memcpy (mask, in, ilen);
		if (has_nibble) {
			memcpy (mask + ilen, "f0", 3);
		}
		for (ptr = mask; *ptr; ptr++) {
			if (IS_HEXCHAR (*ptr)) {
				*ptr = 'f';
			} else if (*ptr == '.') {
				*ptr = '0';
			}
		}
		len = r_hex_str2bin ((char*)mask, mask);
		if (len < 0) {
			len++;
		}
	}
	return len;
}

R_API st64 r_hex_bin_truncate(ut64 in, int n) {
	switch (n) {
	case 1:
		if ((in & UT8_GT0)) {
			return UT64_8U | in;
		}
		return in&UT8_MAX;
	case 2:
		if ((in & UT16_GT0)) {
			return UT64_16U | in;
		}
		return in&UT16_MAX;
	case 4:
		if ((in & UT32_GT0)) {
			return UT64_32U | in;
		}
		return in&UT32_MAX;
	case 8:
		return in&UT64_MAX;
	}
	return in;
}

// Check if str contains only hexadecimal characters and return length of bytes
R_API int r_hex_str_is_valid(const char* str) {
	R_RETURN_VAL_IF_FAIL (str, -1);
	int i, len = 0;
	if (r_str_startswith (str, "0x")) {
		str += 2;
	}
	for (i = 0; str[i] != '\0'; i++) {
		if (IS_HEXCHAR (str[i])) {
			len++;
		}
		if (IS_HEXCHAR (str[i]) || IS_WHITESPACE (str[i])) {
			continue;
		}
		return -1; //if we're here, then str isn't valid
	}
	return len;
}
