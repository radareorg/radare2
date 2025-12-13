 /* radare - MIT - Charset EBCDIC-CP37 */
#include <r_muta.h>
#include <r_util.h>

typedef struct {
	const char *str;
	ut8 byte;
} MutaCharsetMap;

static const MutaCharsetMap map[] = {
	{ "\r", 0x0D }, { "\n", 0x15 },
	{ "!", 0x21 }, { "\"", 0x22 }, { "#", 0x23 }, { "$", 0x24 }, { "%", 0x25 }, { "&", 0x26 },
	{ " ", 0x40 }, { "ç", 0x48 }, { ".", 0x4B }, { "<", 0x4C }, { "(", 0x4D }, { "+", 0x4E }, { "|", 0x4F },
	{ "&", 0x50 }, { "é", 0x51 }, { "!", 0x5A }, { "$", 0x5B }, { "*", 0x5C }, { "*", 0x5D }, { ";", 0x5E },
	{ "-", 0x60 }, { "/", 0x61 }, { "_", 0x6D }, { ">", 0x6E }, { "?", 0x6F }, { ":", 0x7A }, { "#", 0x7B }, { "@", 0x7C },
	{ "'", 0x7D }, { "=", 0x7E }, { "\"", 0x7F },
	{ "a", 0x81 }, { "b", 0x82 }, { "c", 0x83 }, { "d", 0x84 }, { "e", 0x85 }, { "f", 0x86 }, { "g", 0x87 },
	{ "h", 0x88 }, { "i", 0x89 }, { "«", 0x8A }, { "»", 0x8B }, { "j", 0x91 }, { "k", 0x92 }, { "l", 0x93 }, { "m", 0x94 }, { "n", 0x95 },
	{ "o", 0x96 }, { "p", 0x97 }, { "q", 0x98 }, { "r", 0x99 }, { "~", 0xA1 }, { "s", 0xA2 }, { "t", 0xA3 }, { "u", 0xA4 }, { "v", 0xA5 },
	{ "w", 0xA6 }, { "x", 0xA7 }, { "y", 0xA8 }, { "z", 0xA9 }, { "®", 0xAF }, { "©", 0xB4 },
	{ "{", 0xC0 }, { "A", 0xC1 }, { "B", 0xC2 }, { "C", 0xC3 }, { "D", 0xC4 }, { "E", 0xC5 }, { "F", 0xC6 },
	{ "G", 0xC7 }, { "H", 0xC8 }, { "I", 0xC9 }, { "}", 0xD0 }, { "J", 0xD1 }, { "K", 0xD2 }, { "L", 0xD3 }, { "M", 0xD4 }, { "N", 0xD5 },
	{ "O", 0xD6 }, { "P", 0xD7 }, { "Q", 0xD8 }, { "R", 0xD9 }, { "\\", 0xE0 }, { "S", 0xE2 }, { "T", 0xE3 }, { "U", 0xE4 }, { "V", 0xE5 },
	{ "W", 0xE6 }, { "X", 0xE7 }, { "Y", 0xE8 }, { "Z", 0xE9 }, { "0", 0xF0 }, { "1", 0xF1 }, { "2", 0xF2 }, { "3", 0xF3 },
	{ "4", 0xF4 }, { "5", 0xF5 }, { "6", 0xF6 }, { "7", 0xF7 }, { "8", 0xF8 }, { "9", 0xF9 },
	{ NULL, 0 }
};

static const char *decode_byte(ut8 b) {
	const MutaCharsetMap *m;
	for (m = map; m->str; m++) {
		if (m->byte == b) {
			return m->str;
		}
	}
	return NULL;
}
static bool encode_utf8(const char *s, ut8 *out) {
	const MutaCharsetMap *m;
	for (m = map; m->str; m++) {
		if (!strcmp (m->str, s)) {
			*out = m->byte;
			return true;
		}
	}
	return false;
}

static int utf8_len(const char *s, int max) {
	if (!s || max < 1) {
		return 0;
	}
	if ((s[0] & 0x80) == 0) {
		return 1;
	}
	if ((s[0] & 0xe0) == 0xc0 && max >= 2) {
		return 2;
	}
	if ((s[0] & 0xf0) == 0xe0 && max >= 3) {
		return 3;
	}
	if ((s[0] & 0xf8) == 0xf0 && max >= 4) {
		return 4;
	}
	return 1;
}

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	R_RETURN_VAL_IF_FAIL (cj && in && out && consumed, 0);
	if (len < 1) {
		return 0;
	}
	const char *s = decode_byte (in[0]);
	if (!s) {
		s = "?";
	}
	int slen = (int)strlen (s);
	char *cpy = strdup (s);
	if (!cpy) {
		return 0;
	}
	*out = (ut8*)cpy;
	*consumed = 1;
	return slen;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (!cj || !buf || len < 0) {
		return false;
	}
	int i;
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		for (i = 0; i < len; i++) {
			const char *s = decode_byte (buf[i]);
			if (!s) {
				s = "?";
			}
			r_muta_session_append (cj, (const ut8 *)s, (int)strlen (s));
		}
	} else {
		const char *str = (const char *)buf;
		i = 0;
		while (i < len) {
			int ulen = utf8_len (str + i, len - i);
			if (ulen < 1) {
				break;
			}
			char *ch = r_str_ndup (str + i, ulen);
			ut8 b;
			if (ch && encode_utf8 (ch, &b)) {
				r_muta_session_append (cj, &b, 1);
			} else {
				b = 0x6F; /* '?' analog */
				r_muta_session_append (cj, &b, 1);
			}
			free (ch);
			i += ulen;
		}
	}
	return true;
}
static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}
static bool check(const char *algo) {
	return !strcmp (algo, "ebcdic37");
}

RMutaPlugin r_muta_plugin_charset_ebcdic37 = {
	.meta = { .name = "ebcdic37", .license = "MIT", .desc = "EBCDIC CP37 charset" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.decode = decode,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ebcdic37 };
#endif
