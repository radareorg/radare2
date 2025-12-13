/* radare - MIT - Charset ISO 646 (IRV, close to ASCII) */
#include <r_muta.h>

typedef struct {
	const char *str;
	ut8 byte;
} MutaCharsetMap;

/* Base ASCII printable set, ISO/IEC 646 IRV basic.
 * This mirrors legacy r_charset iso646 mapping for printable bytes. */
static const MutaCharsetMap map[] = {
	{ "\n", 0x0A }, { "\t", 0x09 },
	{ " ", 0x20 }, { "!", 0x21 }, { "\"", 0x22 }, { "#", 0x23 }, { "$", 0x24 }, { "%", 0x25 }, { "&", 0x26 }, { "'", 0x27 }, { "(", 0x28 }, { ")", 0x29 }, { "*", 0x2A }, { "+", 0x2B }, { ",", 0x2C }, { "-", 0x2D }, { ".", 0x2E }, { "/", 0x2F },
	{ "0", 0x30 }, { "1", 0x31 }, { "2", 0x32 }, { "3", 0x33 }, { "4", 0x34 }, { "5", 0x35 }, { "6", 0x36 }, { "7", 0x37 }, { "8", 0x38 }, { "9", 0x39 }, { ":", 0x3A }, { ";", 0x3B }, { "<", 0x3C }, { "=", 0x3D }, { ">", 0x3E }, { "?", 0x3F },
	{ "@", 0x40 }, { "A", 0x41 }, { "B", 0x42 }, { "C", 0x43 }, { "D", 0x44 }, { "E", 0x45 }, { "F", 0x46 }, { "G", 0x47 }, { "H", 0x48 }, { "I", 0x49 }, { "J", 0x4A }, { "K", 0x4B }, { "L", 0x4C }, { "M", 0x4D }, { "N", 0x4E }, { "O", 0x4F },
	{ "P", 0x50 }, { "Q", 0x51 }, { "R", 0x52 }, { "S", 0x53 }, { "T", 0x54 }, { "U", 0x55 }, { "V", 0x56 }, { "W", 0x57 }, { "X", 0x58 }, { "Y", 0x59 }, { "Z", 0x5A }, { "[", 0x5B }, { "\\", 0x5C }, { "]", 0x5D }, { "^", 0x5E }, { "_", 0x5F },
	{ "`", 0x60 }, { "a", 0x61 }, { "b", 0x62 }, { "c", 0x63 }, { "d", 0x64 }, { "e", 0x65 }, { "f", 0x66 }, { "g", 0x67 }, { "h", 0x68 }, { "i", 0x69 }, { "j", 0x6A }, { "k", 0x6B }, { "l", 0x6C }, { "m", 0x6D }, { "n", 0x6E }, { "o", 0x6F },
	{ "p", 0x70 }, { "q", 0x71 }, { "r", 0x72 }, { "s", 0x73 }, { "t", 0x74 }, { "u", 0x75 }, { "v", 0x76 }, { "w", 0x77 }, { "x", 0x78 }, { "y", 0x79 }, { "z", 0x7A }, { "{", 0x7B }, { "|", 0x7C }, { "}", 0x7D }, { "~", 0x7E },
	{ NULL, 0 }
};

static const char *decode_byte(ut8 b) {
	for (const MutaCharsetMap *m = map; m->str; m++) {
		if (m->byte == b) {
			return m->str;
		}
	}
	return NULL;
}
static bool encode_utf8(const char *s, ut8 *out) {
	for (const MutaCharsetMap *m = map; m->str; m++) {
		if (!strcmp (m->str, s)) {
			*out = m->byte;
			return true;
		}
	}
	return false;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (!cj || !buf || len < 0) {
		return false;
	}
	RStrBuf *sb = r_strbuf_new ("");
	int i;
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		for (i = 0; i < len; i++) {
			const char *s = decode_byte (buf[i]);
			if (!s) {
				r_strbuf_append (sb, ".");
			} else {
				r_strbuf_append (sb, s);
			}
		}
		const char *out = r_strbuf_get (sb);
		r_muta_session_append (cj, (const ut8 *)out, (int)strlen (out));
	} else {
		for (i = 0; i < len; i++) {
			ut8 b;
			char ch[2] = { (char)buf[i], 0 };
			if (!encode_utf8 (ch, &b)) {
				b = '?';
			}
			r_muta_session_append (cj, &b, 1);
		}
	}
	r_strbuf_free (sb);
	return true;
}
static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}
static bool check(const char *algo) {
	return !strcmp (algo, "iso_646");
}

RMutaPlugin r_muta_plugin_charset_iso_646 = {
	.meta = { .name = "iso_646", .license = "MIT", .desc = "ISO 646 (IRV)" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_iso_646 };
#endif
