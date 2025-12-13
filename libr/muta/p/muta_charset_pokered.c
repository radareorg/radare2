/* radare - MIT - Copyright 2025 - pancake */

#include <r_muta.h>

typedef struct {
	const char *str;
	ut8 byte;
} MutaCharsetMap;

static const MutaCharsetMap pokered_table[] = {
	{ "<NULL>", 0x00 },
	{ "<PAGE>", 0x49 },
	{ "<pkmn>", 0x4a },
	{ "<_CONT>", 0x4b },
	{ "<SCROLL>", 0x4c },
	{ "<NEXT>", 0x4e },
	{ "<LINE>", 0x4f },
	{ "@", 0x50 },
	{ "<PARA>", 0x51 },
	{ "<PLAYER>", 0x52 },
	{ "<RIVAL>", 0x53 },
	{ "#", 0x54 },
	{ "<CONT>", 0x55 },
	{ "<……>", 0x56 },
	{ "<DONE>", 0x57 },
	{ "<PROMPT>", 0x58 },
	{ "<TARGET>", 0x59 },
	{ "<USER>", 0x5a },
	{ "<PC>", 0x5b },
	{ "<TM>", 0x5c },
	{ "<TRAINER>", 0x5d },
	{ "<ROCKET>", 0x5e },
	{ "<DEXDEND>", 0x5f },
	{ "<BOLD_A>", 0x60 },
	{ "<BOLD_B>", 0x61 },
	{ "<BOLD_C>", 0x62 },
	{ "<BOLD_D>", 0x63 },
	{ "<BOLD_E>", 0x64 },
	{ "<BOLD_F>", 0x65 },
	{ "<BOLD_G>", 0x66 },
	{ "<BOLD_H>", 0x67 },
	{ "<BOLD_I>", 0x68 },
	{ "<BOLD_V>", 0x69 },
	{ "<BOLD_S>", 0x6a },
	{ "<BOLD_L>", 0x6b },
	{ "<BOLD_M>", 0x6c },
	{ "<COLON>", 0x6d },
	{ "-", 0x7f },
	{ "A", 0x80 },
	{ "B", 0x81 },
	{ "C", 0x82 },
	{ "D", 0x83 },
	{ "E", 0x84 },
	{ "F", 0x85 },
	{ "G", 0x86 },
	{ "H", 0x87 },
	{ "I", 0x88 },
	{ "J", 0x89 },
	{ "K", 0x8a },
	{ "L", 0x8b },
	{ "M", 0x8c },
	{ "N", 0x8d },
	{ "O", 0x8e },
	{ "P", 0x8f },
	{ "Q", 0x90 },
	{ "R", 0x91 },
	{ "S", 0x92 },
	{ "T", 0x93 },
	{ "U", 0x94 },
	{ "V", 0x95 },
	{ "W", 0x96 },
	{ "X", 0x97 },
	{ "Y", 0x98 },
	{ "Z", 0x99 },
	{ "(", 0x9a },
	{ ")", 0x9b },
	{ ":", 0x9c },
	{ ";", 0x9d },
	{ "[", 0x9e },
	{ "]", 0x9f },
	{ "a", 0xa0 },
	{ "b", 0xa1 },
	{ "c", 0xa2 },
	{ "d", 0xa3 },
	{ "e", 0xa4 },
	{ "f", 0xa5 },
	{ "g", 0xa6 },
	{ "h", 0xa7 },
	{ "i", 0xa8 },
	{ "j", 0xa9 },
	{ "k", 0xaa },
	{ "l", 0xab },
	{ "m", 0xac },
	{ "n", 0xad },
	{ "o", 0xae },
	{ "p", 0xaf },
	{ "q", 0xb0 },
	{ "r", 0xb1 },
	{ "s", 0xb2 },
	{ "t", 0xb3 },
	{ "u", 0xb4 },
	{ "v", 0xb5 },
	{ "w", 0xb6 },
	{ "x", 0xb7 },
	{ "y", 0xb8 },
	{ "z", 0xb9 },
	{ "'d", 0xbb },
	{ "'l", 0xbc },
	{ "'s", 0xbd },
	{ "é", 0xe0 },
	{ "-", 0xe3 },
	{ "'r", 0xe4 },
	{ "?", 0xe6 },
	{ "!", 0xe7 },
	{ "0", 0xf6 },
	{ "1", 0xf7 },
	{ "2", 0xf8 },
	{ "3", 0xf9 },
	{ "4", 0xfa },
	{ "5", 0xfb },
	{ "6", 0xfc },
	{ "7", 0xfd },
	{ "8", 0xfe },
	{ "9", 0xff },
	{ NULL, 0 }
};

static const char *decode_byte(ut8 b) {
	const MutaCharsetMap *m;
	for (m = pokered_table; m->str; m++) {
		if (m->byte == b) {
			return m->str;
		}
	}
	return NULL;
}

static bool encode_utf8(const char *utf8, ut8 *out) {
	const MutaCharsetMap *m;
	for (m = pokered_table; m->str; m++) {
		if (!strcmp (m->str, utf8)) {
			*out = m->byte;
			return true;
		}
	}
	return false;
}

static ut8 *pokered_decode(const ut8 *in, int in_len, int *out_len) {
	const ut8 *ptr = in;
	const ut8 *end = in + in_len;
	ut8 *out = NULL;
	int outcap = 0;
	int outpos = 0;

	while (ptr < end) {
		ut8 b = *ptr++;
		const char *decoded = decode_byte (b);
		const char *text;
		int len;

		if (decoded) {
			text = decoded;
			len = strlen (decoded);
		} else {
			static char tmp[6];
			snprintf (tmp, sizeof (tmp), "\\x%02x", b);
			text = tmp;
			len = strlen (tmp);
		}

		if (outpos + len > outcap) {
			while (outpos + len > outcap) {
				outcap = outcap? outcap * 2: 64;
			}
			ut8 *tmpbuf = realloc (out, outcap);
			if (!tmpbuf) {
				free (out);
				*out_len = 0;
				return NULL;
			}
			out = tmpbuf;
		}

		memcpy (out + outpos, text, len);
		outpos += len;
	}

	*out_len = outpos;
	return out;
}

static ut8 *pokered_encode(const ut8 *in, int in_len, int *out_len) {
	const char *str = (const char *)in;
	const char *end = str + in_len;
	ut8 *out = malloc (in_len); // pessimistic allocation
	if (!out) {
		*out_len = 0;
		return NULL;
	}
	int outpos = 0;

	while (str < end && *str) {
		ut8 b;
		bool found = false;

		// Try to match longer tokens first (up to 7 chars for <BOLD_M>)
		int i;
		for (i = 7; i >= 1; i--) {
			if (str + i <= end) {
				char tok[16] = { 0 };
				strncpy (tok, str, i);
				if (encode_utf8 (tok, &b)) {
					out[outpos++] = b;
					str += i;
					found = true;
					break;
				}
			}
		}

		if (!found) {
			// Single char or escape
			char tok[16] = { 0 };
			int len = 1;

			if (*str == '\\') {
				// handle escapes
				if (str[1] == 's') {
					len = 2;
					tok[0] = ' ';
				} else if (str[1] == 't') {
					len = 2;
					tok[0] = '\t';
				} else if (str[1] == 'n') {
					len = 2;
					tok[0] = '\n';
				} else {
					tok[0] = *str;
				}
			} else {
				tok[0] = *str;
			}

			if (encode_utf8 (tok, &b)) {
				out[outpos++] = b;
			} else {
				out[outpos++] = '?';
			}
			str += len;
		}
	}

	*out_len = outpos;
	return out;
}

static bool check(const char *algo) {
	return !strcmp (algo, "pokered");
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = pokered_encode (buf, len, &olen);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		obuf = pokered_decode (buf, len, &olen);
		break;
	}
	if (!obuf) {
		return false;
	}
	if (olen > 0) {
		r_muta_session_append (cj, obuf, olen);
	}
	free (obuf);
	return true;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_charset_pokered = {
	.meta = {
		.name = "pokered",
		.license = "MIT",
		.desc = "Pokemon Red charset",
	},
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_MUTA,
	.data = &r_muta_plugin_charset_pokered
};
#endif
