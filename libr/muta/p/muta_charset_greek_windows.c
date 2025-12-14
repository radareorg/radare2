/* radare - MIT - Charset Windows-1253 (Greek) partial */
#include <r_muta.h>
#include <r_muta/charset.h>

static const RMutaCharsetMap cp1253_table[] = {
	{ "\n", { 0x0A }, 1 }, { "\t", { 0x09 }, 1 },
	{ " ", { 0x20 }, 1 }, { "!", { 0x21 }, 1 }, { "\"", { 0x22 }, 1 }, { "#", { 0x23 }, 1 }, { "$", { 0x24 }, 1 }, { "%", { 0x25 }, 1 }, { "&", { 0x26 }, 1 }, { "'", { 0x27 }, 1 }, { "(", { 0x28 }, 1 }, { ")", { 0x29 }, 1 }, { "*", { 0x2A }, 1 }, { "+", { 0x2B }, 1 }, { ",", { 0x2C }, 1 }, { "-", { 0x2D }, 1 }, { ".", { 0x2E }, 1 }, { "/", { 0x2F }, 1 },
	{ "0", { 0x30 }, 1 }, { "1", { 0x31 }, 1 }, { "2", { 0x32 }, 1 }, { "3", { 0x33 }, 1 }, { "4", { 0x34 }, 1 }, { "5", { 0x35 }, 1 }, { "6", { 0x36 }, 1 }, { "7", { 0x37 }, 1 }, { "8", { 0x38 }, 1 }, { "9", { 0x39 }, 1 }, { ":", { 0x3A }, 1 }, { ";", { 0x3B }, 1 }, { "<", { 0x3C }, 1 }, { "=", { 0x3D }, 1 }, { ">", { 0x3E }, 1 }, { "?", { 0x3F }, 1 },
	{ "@", { 0x40 }, 1 }, { "A", { 0x41 }, 1 }, { "B", { 0x42 }, 1 }, { "C", { 0x43 }, 1 }, { "D", { 0x44 }, 1 }, { "E", { 0x45 }, 1 }, { "F", { 0x46 }, 1 }, { "G", { 0x47 }, 1 }, { "H", { 0x48 }, 1 }, { "I", { 0x49 }, 1 }, { "J", { 0x4A }, 1 }, { "K", { 0x4B }, 1 }, { "L", { 0x4C }, 1 }, { "M", { 0x4D }, 1 }, { "N", { 0x4E }, 1 }, { "O", { 0x4F }, 1 },
	{ "P", { 0x50 }, 1 }, { "Q", { 0x51 }, 1 }, { "R", { 0x52 }, 1 }, { "S", { 0x53 }, 1 }, { "T", { 0x54 }, 1 }, { "U", { 0x55 }, 1 }, { "V", { 0x56 }, 1 }, { "W", { 0x57 }, 1 }, { "X", { 0x58 }, 1 }, { "Y", { 0x59 }, 1 }, { "Z", { 0x5A }, 1 }, { "[", { 0x5B }, 1 }, { "\\", { 0x5C }, 1 }, { "]", { 0x5D }, 1 }, { "^", { 0x5E }, 1 }, { "_", { 0x5F }, 1 },
	{ "`", { 0x60 }, 1 }, { "a", { 0x61 }, 1 }, { "b", { 0x62 }, 1 }, { "c", { 0x63 }, 1 }, { "d", { 0x64 }, 1 }, { "e", { 0x65 }, 1 }, { "f", { 0x66 }, 1 }, { "g", { 0x67 }, 1 }, { "h", { 0x68 }, 1 }, { "i", { 0x69 }, 1 }, { "j", { 0x6A }, 1 }, { "k", { 0x6B }, 1 }, { "l", { 0x6C }, 1 }, { "m", { 0x6D }, 1 }, { "n", { 0x6E }, 1 }, { "o", { 0x6F }, 1 },
	{ "p", { 0x70 }, 1 }, { "q", { 0x71 }, 1 }, { "r", { 0x72 }, 1 }, { "s", { 0x73 }, 1 }, { "t", { 0x74 }, 1 }, { "u", { 0x75 }, 1 }, { "v", { 0x76 }, 1 }, { "w", { 0x77 }, 1 }, { "x", { 0x78 }, 1 }, { "y", { 0x79 }, 1 }, { "z", { 0x7A }, 1 }, { "{", { 0x7B }, 1 }, { "|", { 0x7C }, 1 }, { "}", { 0x7D }, 1 }, { "~", { 0x7E }, 1 },
	/* Greek capitals subset */
	{ "Ά", { 0xB6 }, 1 }, { "Έ", { 0xB8 }, 1 }, { "Ή", { 0xB9 }, 1 }, { "Ί", { 0xBA }, 1 }, { "Ό", { 0xBC }, 1 }, { "Ύ", { 0xBE }, 1 }, { "Ώ", { 0xBF }, 1 },
	{ "Α", { 0xC1 }, 1 }, { "Β", { 0xC2 }, 1 }, { "Γ", { 0xC3 }, 1 }, { "Δ", { 0xC4 }, 1 }, { "Ε", { 0xC5 }, 1 }, { "Ζ", { 0xC6 }, 1 }, { "Η", { 0xC7 }, 1 }, { "Θ", { 0xC8 }, 1 }, { "Ι", { 0xC9 }, 1 }, { "Κ", { 0xCA }, 1 }, { "Λ", { 0xCB }, 1 }, { "Μ", { 0xCC }, 1 }, { "Ν", { 0xCD }, 1 }, { "Ξ", { 0xCE }, 1 }, { "Ο", { 0xCF }, 1 },
	{ "Π", { 0xD0 }, 1 }, { "Ρ", { 0xD1 }, 1 }, { "Σ", { 0xD3 }, 1 }, { "Τ", { 0xD4 }, 1 }, { "Υ", { 0xD5 }, 1 }, { "Φ", { 0xD6 }, 1 }, { "Χ", { 0xD7 }, 1 }, { "Ψ", { 0xD8 }, 1 }, { "Ω", { 0xD9 }, 1 },
	/* Greek lowercase subset */
	{ "ά", { 0xB1 }, 1 }, { "έ", { 0xB3 }, 1 }, { "ή", { 0xB4 }, 1 }, { "ί", { 0xB5 }, 1 }, { "ό", { 0xB7 }, 1 }, { "ύ", { 0xBA }, 1 }, { "ώ", { 0xBC }, 1 },
	{ "α", { 0xE1 }, 1 }, { "β", { 0xE2 }, 1 }, { "γ", { 0xE3 }, 1 }, { "δ", { 0xE4 }, 1 }, { "ε", { 0xE5 }, 1 }, { "ζ", { 0xE6 }, 1 }, { "η", { 0xE7 }, 1 }, { "θ", { 0xE8 }, 1 }, { "ι", { 0xE9 }, 1 }, { "κ", { 0xEA }, 1 }, { "λ", { 0xEB }, 1 }, { "μ", { 0xEC }, 1 }, { "ν", { 0xED }, 1 }, { "ξ", { 0xEE }, 1 }, { "ο", { 0xEF }, 1 },
	{ "π", { 0xF0 }, 1 }, { "ρ", { 0xF1 }, 1 }, { "ς", { 0xF2 }, 1 }, { "σ", { 0xF3 }, 1 }, { "τ", { 0xF4 }, 1 }, { "υ", { 0xF5 }, 1 }, { "φ", { 0xF6 }, 1 }, { "χ", { 0xF7 }, 1 }, { "ψ", { 0xF8 }, 1 }, { "ω", { 0xF9 }, 1 },
	{ NULL, { 0 }, 0 }
};

static bool check(const char *algo) {
	return !strcmp (algo, "greek_windows");
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (!cj || !buf || len < 0) {
		return false;
	}
	switch (cj->dir) {
	case R_CRYPTO_DIR_DECRYPT:
		obuf = r_muta_charset_decode (buf, len, &olen, cp1253_table, ".");
		break;
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = r_muta_charset_encode (buf, len, &olen, cp1253_table, r_muta_charset_parse_default);
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

static bool end(RMutaSession *cj, const ut8 *b, int l) {
	return update (cj, b, l);
}

RMutaPlugin r_muta_plugin_charset_greek_windows = {
	.meta = { .name = "greek_windows", .license = "MIT", .desc = "Windows-1253 (partial)" },
	.type = R_MUTA_TYPE_CHARSET,
	.check = check,
	.update = update,
	.end = end
};
#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_greek_windows };
#endif

