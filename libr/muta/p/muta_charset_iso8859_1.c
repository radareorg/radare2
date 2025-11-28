/* radare - MIT - Charset ISO-8859-1 */
#include <r_muta.h>

typedef struct {
	const char *str;
	ut8 byte;
} MutaCharsetMap;

static const MutaCharsetMap map[] = {
	{ "[nul]", 0x00 }, { "[stx]", 0x01 }, { "[sot]", 0x02 }, { "[etx]", 0x03 }, { "[eot]", 0x04 }, { "[enq]", 0x05 }, { "[ack]", 0x06 }, { "[bel]", 0x07 },
	{ "[bs]", 0x08 }, { "[ht]", 0x09 }, { "[lf]", 0x0A }, { "[vt]", 0x0B }, { "[ff]", 0x0C }, { "[cr]", 0x0D }, { "[so]", 0x0E }, { "[si]", 0x0F },
	{ "[dle]", 0x10 }, { "[dc1]", 0x11 }, { "[dc2]", 0x12 }, { "[dc3]", 0x13 }, { "[dc4]", 0x14 }, { "[nak]", 0x15 }, { "[syn]", 0x16 }, { "[etb]", 0x17 },
	{ "[can]", 0x18 }, { "[em]", 0x19 }, { "[sub]", 0x1A }, { "[esc]", 0x1B }, { "[fs]", 0x1C }, { "[gs]", 0x1D }, { "[rs]", 0x1E }, { "[us]", 0x1F },
	{ "[sp]", 0x20 }, { "!", 0x21 }, { "\"", 0x22 }, { "#", 0x23 }, { "$", 0x24 }, { "%", 0x25 }, { "&", 0x26 }, { "'", 0x27 }, { "(", 0x28 }, { ")", 0x29 }, { "*", 0x2A }, { "+", 0x2B }, { ",", 0x2C }, { "-", 0x2D }, { ".", 0x2E }, { "/", 0x2F },
	{ "0", 0x30 }, { "1", 0x31 }, { "2", 0x32 }, { "3", 0x33 }, { "4", 0x34 }, { "5", 0x35 }, { "6", 0x36 }, { "7", 0x37 }, { "8", 0x38 }, { "9", 0x39 }, { ":", 0x3A }, { ";", 0x3B }, { "<", 0x3C }, { "=", 0x3D }, { ">", 0x3E }, { "?", 0x3F },
	{ "@", 0x40 }, { "A", 0x41 }, { "B", 0x42 }, { "C", 0x43 }, { "D", 0x44 }, { "E", 0x45 }, { "F", 0x46 }, { "G", 0x47 }, { "H", 0x48 }, { "I", 0x49 }, { "J", 0x4A }, { "K", 0x4B }, { "L", 0x4C }, { "M", 0x4D }, { "N", 0x4E }, { "O", 0x4F },
	{ "P", 0x50 }, { "Q", 0x51 }, { "R", 0x52 }, { "S", 0x53 }, { "T", 0x54 }, { "U", 0x55 }, { "V", 0x56 }, { "W", 0x57 }, { "X", 0x58 }, { "Y", 0x59 }, { "Z", 0x5A }, { "[", 0x5B }, { "\\", 0x5C }, { "]", 0x5D }, { "^", 0x5E }, { "_", 0x5F },
	{ "`", 0x60 }, { "a", 0x61 }, { "b", 0x62 }, { "c", 0x63 }, { "d", 0x64 }, { "e", 0x65 }, { "f", 0x66 }, { "g", 0x67 }, { "h", 0x68 }, { "i", 0x69 }, { "j", 0x6A }, { "k", 0x6B }, { "l", 0x6C }, { "m", 0x6D }, { "n", 0x6E }, { "o", 0x6F },
	{ "p", 0x70 }, { "q", 0x71 }, { "r", 0x72 }, { "s", 0x73 }, { "t", 0x74 }, { "u", 0x75 }, { "v", 0x76 }, { "w", 0x77 }, { "x", 0x78 }, { "y", 0x79 }, { "z", 0x7A }, { "{", 0x7B }, { "|", 0x7C }, { "}", 0x7D }, { "~", 0x7E }, { "[del]", 0x7F },
	{ "[pad]", 0x80 }, { "[hop]", 0x81 }, { "[bhp]", 0x82 }, { "[nbh]", 0x83 }, { "[ind]", 0x84 }, { "[nel]", 0x85 }, { "[ssa]", 0x86 }, { "[esa]", 0x87 },
	{ "[hts]", 0x88 }, { "[htj]", 0x89 }, { "[vts]", 0x8A }, { "[pld]", 0x8B }, { "[plu]", 0x8C }, { "[ri]", 0x8D }, { "[ss2]", 0x8E }, { "[ss3]", 0x8F },
	{ "[dcs]", 0x90 }, { "[pu1]", 0x91 }, { "[pu2]", 0x92 }, { "[sts]", 0x93 }, { "[cch]", 0x94 }, { "[mw]", 0x95 }, { "[spa]", 0x96 }, { "[epa]", 0x97 },
	{ "[sos]", 0x98 }, { "[sgci]", 0x99 }, { "[sci]", 0x9A }, { "[csi]", 0x9B }, { "[st]", 0x9C }, { "[osc]", 0x9D }, { "[pm]", 0x9E }, { "[apc]", 0x9F },
	{ "[nbsp]", 0xA0 }, { "¡", 0xA1 }, { "¢", 0xA2 }, { "£", 0xA3 }, { "¤", 0xA4 }, { "¥", 0xA5 }, { "¦", 0xA6 }, { "§", 0xA7 }, { "¨", 0xA8 }, { "©", 0xA9 }, { "ª", 0xAA }, { "«", 0xAB }, { "¬", 0xAC }, { "shy", 0xAD }, { "®", 0xAE }, { "¯", 0xAF },
	{ "°", 0xB0 }, { "±", 0xB1 }, { "²", 0xB2 }, { "³", 0xB3 }, { "´", 0xB4 }, { "µ", 0xB5 }, { "¶", 0xB6 }, { "·", 0xB7 }, { "¸", 0xB8 }, { "¹", 0xB9 }, { "º", 0xBA }, { "»", 0xBB }, { "¼", 0xBC }, { "½", 0xBD }, { "¾", 0xBE }, { "¿", 0xBF },
	{ "À", 0xC0 }, { "Á", 0xC1 }, { "Â", 0xC2 }, { "Ã", 0xC3 }, { "Ä", 0xC4 }, { "Å", 0xC5 }, { "Æ", 0xC6 }, { "Ç", 0xC7 }, { "È", 0xC8 }, { "É", 0xC9 }, { "Ê", 0xCA }, { "Ë", 0xCB }, { "Ì", 0xCC }, { "Í", 0xCD }, { "Î", 0xCE }, { "Ï", 0xCF },
	{ "Ð", 0xD0 }, { "Ñ", 0xD1 }, { "Ò", 0xD2 }, { "Ó", 0xD3 }, { "Ô", 0xD4 }, { "Õ", 0xD5 }, { "Ö", 0xD6 }, { "×", 0xD7 }, { "Ø", 0xD8 }, { "Ù", 0xD9 }, { "Ú", 0xDA }, { "Û", 0xDB }, { "Ü", 0xDC }, { "Ý", 0xDD }, { "Þ", 0xDE }, { "ß", 0xDF },
	{ "à", 0xE0 }, { "á", 0xE1 }, { "â", 0xE2 }, { "ã", 0xE3 }, { "ä", 0xE4 }, { "å", 0xE5 }, { "æ", 0xE6 }, { "ç", 0xE7 }, { "è", 0xE8 }, { "é", 0xE9 }, { "ê", 0xEA }, { "ë", 0xEB }, { "ì", 0xEC }, { "í", 0xED }, { "î", 0xEE }, { "ï", 0xEF },
	{ "ð", 0xF0 }, { "ñ", 0xF1 }, { "ò", 0xF2 }, { "ó", 0xF3 }, { "ô", 0xF4 }, { "õ", 0xF5 }, { "ö", 0xF6 }, { "÷", 0xF7 }, { "ø", 0xF8 }, { "ù", 0xF9 }, { "ú", 0xFA }, { "û", 0xFB }, { "ü", 0xFC }, { "ý", 0xFD }, { "þ", 0xFE }, { "ÿ", 0xFF },
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
	if (cj->dir == R_CRYPTO_DIR_DECRYPT) {
		for (int i = 0; i < len; i++) {
			const char *s = decode_byte (buf[i]);
			if (!s) {
				char tmp[2] = { '.', 0 };
				r_strbuf_append (sb, tmp);
			} else {
				r_strbuf_append (sb, s);
			}
		}
		const char *out = r_strbuf_get (sb);
		r_muta_session_append (cj, (const ut8 *)out, (int)strlen (out));
	} else {
		for (int i = 0; i < len; i++) {
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
	return !strcmp (algo, "iso8859_1");
}

RMutaPlugin r_muta_plugin_charset_iso8859_1 = {
	.meta = { .name = "iso8859_1", .license = "MIT", .desc = "ISO-8859-1 charset" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_iso8859_1 };
#endif
