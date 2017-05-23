/* radare - LGPL - Copyright 2007-2016 - pancake */

#include "r_types.h"
#include "r_util.h"
#include <stdio.h>

/* int c; ret = hex_to_byte(&c, 'c'); */
R_API int r_hex_to_byte(ut8 *val, ut8 c) {
	if (IS_DIGIT(c)) {
		*val = (ut8)(*val) * 16 + (c - '0');
	} else if (c >= 'A' && c <= 'F') {
		*val = (ut8)(*val) * 16 + (c - 'A' + 10);
	} else if (c >= 'a' && c <= 'f') {
		*val = (ut8)(*val) * 16 + (c - 'a' + 10);
	} else {
		return 1;
	}
	return 0;
}

/* convert:
 *    char *foo = "\x41\x23\x42\x1b";
 * into:
 *    4123421b
 */
R_API char *r_hex_from_c(const char *code) {
	const char abc[] = "0123456789abcdefABCDEF";
	bool parse_on = false;
	int parse_mode = 0;
	char *out, *ret;
	int is_hexa = 0;

	if (code) {
		ret = malloc (strlen (code) * 3);
	} else {
		ret = malloc (3);
	}
	if (!ret) return NULL;
	*ret = 0;
	out = ret;
	if (code) {
		for (;*code; code++) {
			if (!strncmp (code, "/*", 2)) {
				/* skip comments */
				char *end = strstr (code, "*/");
				if (end) {
					code = end + 1;
				} else {
					eprintf ("Missing closing comment\n");
				}
				continue;
			}
			if (!strncmp (code, "//", 2)) {
				char *end = strchr (code, '\n');
				if (end) {
					code = end;
				}
				continue;
			}
			if (parse_on) {
				if (*code == '}' || *code == '"') {
					parse_on = false;
					// stop parsing after the first string statement
					break;
				}
			} else {
				if (*code == '{') {
					parse_mode = *code;
					for (code++;*code; code++) {
						if (IS_WHITESPACE (*code))
							continue;
						if (IS_DIGIT (*code)) {
							parse_on = true;
							break;
						} else {
							parse_on = false;
							parse_mode = 0;
							break;
						}
					}
				}
			}
			if (parse_on && parse_mode == '{') {
				char *comma = strchr (code, ',');
				if (!comma) comma = strchr (code, '}');
				if (comma) {
					char *word = r_str_ndup (code, comma - code);
					if (IS_DIGIT (*word)) {
						ut8 n = (ut8)r_num_math (NULL, word);
						*out++ = abc[(n >> 4) & 0xf];
						*out++ = abc[n & 0xf];
					} else {
						parse_on = false;
					}
					code = comma;
					free (word);
				}
			} else if (*code == '"') {
				if (code[1] == '\\') {
					parse_on = true;
				} else {
					parse_on = !parse_on;
					parse_mode = *code;
				}
			} else if (parse_on) {
				if (*code == '\\') {
					code++;
					switch (code[0]) {
					case 'e': *out++='1';*out++='b';break;
					case 'r': *out++='0';*out++='d';break;
					case 'n': *out++='0';*out++='a';break;
					case 'x': is_hexa ++; break;
					default: goto error;
					}
				} else {
					if (is_hexa) {
						if (strchr (abc, *code)) {
							*out++ = *code;
							if (++is_hexa == 3)
								is_hexa = 0;
						} else goto error;
					} else {
						*out++ = abc[*code >>4];
						*out++ = abc[*code & 0xf];
					}
				}
			}
		}
	}
	*out++ = 0;
	return ret;
error:
	free (ret);
	return NULL;
}

/* int byte = hexpair2bin("A0"); */
// (0A) => 10 || -1 (on error)
R_API int r_hex_pair2bin(const char *arg) {
	ut8 *ptr, c = 0, d = 0;
	ut32 j = 0;

	for (ptr = (ut8*)arg; ;ptr = ptr + 1) {
		if (!*ptr || *ptr==' ' || j==2) {
			break;
		}
		d = c;
		if (*ptr!='.' && r_hex_to_byte (&c, *ptr)) {
			eprintf ("Invalid hexa string at char '%c' (%s).\n",
				*ptr, arg);
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
	int i, idx;
	char tmp[5];
	if (len < 0)
		return 0;
	for (idx = i = 0; i < len; i++, idx += 2)  {
		snprintf (tmp, sizeof (tmp), "%02x", in[i]);
		memcpy (out+idx, tmp, 2);
	}
	out[idx] = 0;
	return len;
}

R_API char *r_hex_bin2strdup(const ut8 *in, int len) {
	int i, idx;
	char tmp[5], *out;

	if ((len + 1) * 2 < len) return NULL;
	out = malloc ((len + 1) * 2);
	if (!out) return NULL;
	for (i = idx = 0; i < len; i++, idx += 2)  {
		snprintf (tmp, sizeof (tmp), "%02x", in[i]);
		memcpy (out+idx, tmp, 2);
	}
	out[idx] = 0;
	return out;
}

R_API int r_hex_str2bin(const char *in, ut8 *out) {
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
		if (out) r_hex_to_byte (&out[nibbles/2], '0');
		return -(nibbles+1) / 2;
	}

	return nibbles / 2;
}

R_API int r_hex_str2binmask(const char *in, ut8 *out, ut8 *mask) {
	ut8 *ptr;
	int len, ilen = strlen (in)+1;
	int has_nibble = 0;
	memcpy (out, in, ilen);
	for (ptr=out; *ptr; ptr++) if (*ptr=='.') *ptr = '0';
	len = r_hex_str2bin ((char*)out, out);
	if (len<0) { has_nibble = 1; len = -(len+1); }
	if (len != -1) {
		memcpy (mask, in, ilen);
		if (has_nibble)
			memcpy (mask+ilen, "f0", 3);
		for (ptr=mask; *ptr; ptr++) *ptr = (*ptr=='.')?'0':'f';
		len = r_hex_str2bin ((char*)mask, mask);
		if (len<0) len++;
	}
	return len;
}

R_API st64 r_hex_bin_truncate (ut64 in, int n) {
	switch (n) {
	case 1:
		if ((in&UT8_GT0))
			return UT64_8U|in;
		return in&UT8_MAX;
	case 2:
		if ((in&UT16_GT0))
			return UT64_16U|in;
		return in&UT16_MAX;
	case 4:
		if ((in&UT32_GT0))
			return UT64_32U|in;
		return in&UT32_MAX;
	case 8:
		return in&UT64_MAX;
	}
	return in;
}

// Check if str contains only hexademical characters and return length of bytes
R_API int r_hex_str_is_valid(const char* str) {
	int i;
	if (!strncmp (str, "0x", 2)) {
		str += 2;
	}
	for (i = 0; str[i] != '\0' && str[i] != ' '; i++) {
		if (ISHEXCHAR (str[i])) {
			continue;
		}
		return -1; //if we're here, then str isnt valid
	}
	return i;
}
