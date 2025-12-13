/* radare - MIT - Charset Windows-1251 (Cyrillic) partial */
#include <r_muta.h>

typedef struct {
	const char *u;
	ut8 b;
} Map;
static const Map m[] = {
	/* ASCII */
	{ "\n", 0x0A }, { "\t", 0x09 },
	{ " ", 0x20 }, { "!", 0x21 }, { "\"", 0x22 }, { "#", 0x23 }, { "$", 0x24 }, { "%", 0x25 }, { "&", 0x26 }, { "'", 0x27 }, { "(", 0x28 }, { ")", 0x29 }, { "*", 0x2A }, { "+", 0x2B }, { ",", 0x2C }, { "-", 0x2D }, { ".", 0x2E }, { "/", 0x2F },
	{ "0", 0x30 }, { "1", 0x31 }, { "2", 0x32 }, { "3", 0x33 }, { "4", 0x34 }, { "5", 0x35 }, { "6", 0x36 }, { "7", 0x37 }, { "8", 0x38 }, { "9", 0x39 }, { ":", 0x3A }, { ";", 0x3B }, { "<", 0x3C }, { "=", 0x3D }, { ">", 0x3E }, { "?", 0x3F },
	{ "@", 0x40 }, { "A", 0x41 }, { "B", 0x42 }, { "C", 0x43 }, { "D", 0x44 }, { "E", 0x45 }, { "F", 0x46 }, { "G", 0x47 }, { "H", 0x48 }, { "I", 0x49 }, { "J", 0x4A }, { "K", 0x4B }, { "L", 0x4C }, { "M", 0x4D }, { "N", 0x4E }, { "O", 0x4F },
	{ "P", 0x50 }, { "Q", 0x51 }, { "R", 0x52 }, { "S", 0x53 }, { "T", 0x54 }, { "U", 0x55 }, { "V", 0x56 }, { "W", 0x57 }, { "X", 0x58 }, { "Y", 0x59 }, { "Z", 0x5A }, { "[", 0x5B }, { "\\", 0x5C }, { "]", 0x5D }, { "^", 0x5E }, { "_", 0x5F },
	{ "`", 0x60 }, { "a", 0x61 }, { "b", 0x62 }, { "c", 0x63 }, { "d", 0x64 }, { "e", 0x65 }, { "f", 0x66 }, { "g", 0x67 }, { "h", 0x68 }, { "i", 0x69 }, { "j", 0x6A }, { "k", 0x6B }, { "l", 0x6C }, { "m", 0x6D }, { "n", 0x6E }, { "o", 0x6F },
	{ "p", 0x70 }, { "q", 0x71 }, { "r", 0x72 }, { "s", 0x73 }, { "t", 0x74 }, { "u", 0x75 }, { "v", 0x76 }, { "w", 0x77 }, { "x", 0x78 }, { "y", 0x79 }, { "z", 0x7A }, { "{", 0x7B }, { "|", 0x7C }, { "}", 0x7D }, { "~", 0x7E },
	/* Cyrillic capitals subset */
	{ "А", 0xC0 }, { "Б", 0xC1 }, { "В", 0xC2 }, { "Г", 0xC3 }, { "Д", 0xC4 }, { "Е", 0xC5 }, { "Ж", 0xC6 }, { "З", 0xC7 }, { "И", 0xC8 }, { "Й", 0xC9 },
	{ "К", 0xCA }, { "Л", 0xCB }, { "М", 0xCC }, { "Н", 0xCD }, { "О", 0xCE }, { "П", 0xCF }, { "Р", 0xD0 }, { "С", 0xD1 }, { "Т", 0xD2 }, { "У", 0xD3 },
	{ "Ф", 0xD4 }, { "Х", 0xD5 }, { "Ц", 0xD6 }, { "Ч", 0xD7 }, { "Ш", 0xD8 }, { "Щ", 0xD9 }, { "Ъ", 0xDA }, { "Ы", 0xDB }, { "Ь", 0xDC }, { "Э", 0xDD }, { "Ю", 0xDE }, { "Я", 0xDF },
	/* Cyrillic lowercase subset */
	{ "а", 0xE0 }, { "б", 0xE1 }, { "в", 0xE2 }, { "г", 0xE3 }, { "д", 0xE4 }, { "е", 0xE5 }, { "ж", 0xE6 }, { "з", 0xE7 }, { "и", 0xE8 }, { "й", 0xE9 },
	{ "к", 0xEA }, { "л", 0xEB }, { "м", 0xEC }, { "н", 0xED }, { "о", 0xEE }, { "п", 0xEF }, { "р", 0xF0 }, { "с", 0xF1 }, { "т", 0xF2 }, { "у", 0xF3 },
	{ "ф", 0xF4 }, { "х", 0xF5 }, { "ц", 0xF6 }, { "ч", 0xF7 }, { "ш", 0xF8 }, { "щ", 0xF9 }, { "ъ", 0xFA }, { "ы", 0xFB }, { "ь", 0xFC }, { "э", 0xFD }, { "ю", 0xFE }, { "я", 0xFF },
	{ NULL, 0 }
};

static const char *dec(ut8 b) {
	for (const Map *mm = m; mm->u; mm++) {
		if (mm->b == b) {
			return mm->u;
		}
	}
	return NULL;
}
static bool enc(const char *s, ut8 *out) {
	for (const Map *mm = m; mm->u; mm++) {
		if (!strcmp (mm->u, s)) {
			*out = mm->b;
			return true;
		}
	}
	return false;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	if (!cj || !buf || len < 0) {
		return false;
	}
	int i;
	RStrBuf *sb = r_strbuf_new ("");
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		for (i = 0; i < len; i++) {
			const char *s = dec (buf[i]);
			r_strbuf_append (sb, s? s: ".");
		}
		const char *out = r_strbuf_get (sb);
		r_muta_session_append (cj, (const ut8 *)out, (int)strlen (out));
	} else {
		for (i = 0; i < len; i++) {
			ut8 b;
			char ch[2] = { (char)buf[i], 0 };
			if (!enc (ch, &b)) {
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
	return !strcmp (algo, "cyrillic_windows");
}

RMutaPlugin r_muta_plugin_charset_cyrillic_windows = {
	.meta = { .name = "cyrillic_windows", .license = "MIT", .desc = "Windows-1251 (partial)" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_cyrillic_windows };
#endif
