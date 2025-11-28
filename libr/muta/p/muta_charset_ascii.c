/* radare - MIT - Copyright 2025 - pancake */

#include <r_muta.h>

typedef struct {
	const char *str;
	ut8 byte;
} MutaCharsetMap;

static const MutaCharsetMap ascii_table[] = {
	{ "\n", 0x0a },
	{ "\t", 0x09 },
	{ " ", 0x20 },
	{ "!", 0x21 },
	{ "\"", 0x22 },
	{ "#", 0x23 },
	{ "$", 0x24 },
	{ "%", 0x25 },
	{ "&", 0x26 },
	{ "'", 0x27 },
	{ "(", 0x28 },
	{ ")", 0x29 },
	{ "*", 0x2a },
	{ "+", 0x2b },
	{ ",", 0x2c },
	{ "-", 0x2d },
	{ ".", 0x2e },
	{ "/", 0x2f },
	{ "0", 0x30 },
	{ "1", 0x31 },
	{ "2", 0x32 },
	{ "3", 0x33 },
	{ "4", 0x34 },
	{ "5", 0x35 },
	{ "6", 0x36 },
	{ "7", 0x37 },
	{ "8", 0x38 },
	{ "9", 0x39 },
	{ ":", 0x3a },
	{ ";", 0x3b },
	{ "<", 0x3c },
	{ "=", 0x3d },
	{ ">", 0x3e },
	{ "?", 0x3f },
	{ "@", 0x40 },
	{ "A", 0x41 },
	{ "B", 0x42 },
	{ "C", 0x43 },
	{ "D", 0x44 },
	{ "E", 0x45 },
	{ "F", 0x46 },
	{ "G", 0x47 },
	{ "H", 0x48 },
	{ "I", 0x49 },
	{ "J", 0x4a },
	{ "K", 0x4b },
	{ "L", 0x4c },
	{ "M", 0x4d },
	{ "N", 0x4e },
	{ "O", 0x4f },
	{ "P", 0x50 },
	{ "Q", 0x51 },
	{ "R", 0x52 },
	{ "S", 0x53 },
	{ "T", 0x54 },
	{ "U", 0x55 },
	{ "V", 0x56 },
	{ "W", 0x57 },
	{ "X", 0x58 },
	{ "Y", 0x59 },
	{ "Z", 0x5a },
	{ "[", 0x5b },
	{ "\\", 0x5c },
	{ "]", 0x5d },
	{ "^", 0x5e },
	{ "_", 0x5f },
	{ "`", 0x60 },
	{ "a", 0x61 },
	{ "b", 0x62 },
	{ "c", 0x63 },
	{ "d", 0x64 },
	{ "e", 0x65 },
	{ "f", 0x66 },
	{ "g", 0x67 },
	{ "h", 0x68 },
	{ "i", 0x69 },
	{ "j", 0x6a },
	{ "k", 0x6b },
	{ "l", 0x6c },
	{ "m", 0x6d },
	{ "n", 0x6e },
	{ "o", 0x6f },
	{ "p", 0x70 },
	{ "q", 0x71 },
	{ "r", 0x72 },
	{ "s", 0x73 },
	{ "t", 0x74 },
	{ "u", 0x75 },
	{ "v", 0x76 },
	{ "w", 0x77 },
	{ "x", 0x78 },
	{ "y", 0x79 },
	{ "z", 0x7a },
	{ "{", 0x7b },
	{ "|", 0x7c },
	{ "}", 0x7d },
	{ "~", 0x7e },
	{ NULL, 0 }
};

static const char *decode_byte(ut8 b) {
	const MutaCharsetMap *m;
	for (m = ascii_table; m->str; m++) {
		if (m->byte == b) {
			return m->str;
		}
	}
	return NULL;
}

static bool encode_utf8(const char *utf8, ut8 *out) {
	const MutaCharsetMap *m;
	for (m = ascii_table; m->str; m++) {
		if (!strcmp (m->str, utf8)) {
			*out = m->byte;
			return true;
		}
	}
	return false;
}

static ut8 *ascii_decode(const ut8 *in, int in_len, int *out_len) {
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

static ut8 *ascii_encode(const ut8 *in, int in_len, int *out_len) {
	const ut8 *end = in + in_len;
	const char *str = (const char *)in;
	ut8 *out = malloc (in_len); // pessimistic allocation
	if (!out) {
		*out_len = 0;
		return NULL;
	}
	int outpos = 0;

	while (str < (const char *)end && *str) {
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

		ut8 b;
		if (encode_utf8 (tok, &b)) {
			out[outpos++] = b;
		} else {
			out[outpos++] = '?';
		}
		str += len;
	}

	*out_len = outpos;
	return out;
}

static bool check(const char *algo) {
	return !strcmp (algo, "ascii");
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = ascii_encode (buf, len, &olen);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		obuf = ascii_decode (buf, len, &olen);
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

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	if (!in || len < 1 || !out || !consumed) {
		return 0;
	}
	ut8 b = *in;
	const char *decoded = decode_byte (b);
	if (decoded) {
		*out = (ut8*)strdup (decoded);
		*consumed = 1;
		return strlen (decoded);
	}
	*consumed = 1;
	*out = NULL;
	return 0;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_charset_ascii = {
	.meta = {
		.name = "ascii",
		.license = "MIT",
		.desc = "ASCII character set encoding/decoding",
	},
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end,
	.decode = decode
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_MUTA,
	.data = &r_muta_plugin_charset_ascii
};
#endif
