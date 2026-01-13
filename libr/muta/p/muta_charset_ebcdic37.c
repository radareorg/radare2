/* radare - MIT - Charset EBCDIC-CP37 */
#include <r_muta.h>
#include <r_muta/charset.h>

// clang-format off
static const RMutaCharsetMap ebcdic37_table[] = {
	{ "\r", { 0x0D }, 1 }, { "\n", { 0x15 }, 1 },
	{ "!", { 0x21 }, 1 }, { "\"", { 0x22 }, 1 }, { "#", { 0x23 }, 1 }, { "$", { 0x24 }, 1 }, { "%", { 0x25 }, 1 }, { "&", { 0x26 }, 1 },
	{ " ", { 0x40 }, 1 }, { "ç", { 0x48 }, 1 }, { ".", { 0x4B }, 1 }, { "<", { 0x4C }, 1 }, { "(", { 0x4D }, 1 }, { "+", { 0x4E }, 1 }, { "|", { 0x4F }, 1 },
	{ "&", { 0x50 }, 1 }, { "é", { 0x51 }, 1 }, { "!", { 0x5A }, 1 }, { "$", { 0x5B }, 1 }, { "*", { 0x5C }, 1 }, { "*", { 0x5D }, 1 }, { ";", { 0x5E }, 1 },
	{ "-", { 0x60 }, 1 }, { "/", { 0x61 }, 1 }, { "_", { 0x6D }, 1 }, { ">", { 0x6E }, 1 }, { "?", { 0x6F }, 1 }, { ":", { 0x7A }, 1 }, { "#", { 0x7B }, 1 }, { "@", { 0x7C }, 1 },
	{ "'", { 0x7D }, 1 }, { "=", { 0x7E }, 1 }, { "\"", { 0x7F }, 1 },
	{ "a", { 0x81 }, 1 }, { "b", { 0x82 }, 1 }, { "c", { 0x83 }, 1 }, { "d", { 0x84 }, 1 }, { "e", { 0x85 }, 1 }, { "f", { 0x86 }, 1 }, { "g", { 0x87 }, 1 },
	{ "h", { 0x88 }, 1 }, { "i", { 0x89 }, 1 }, { "«", { 0x8A }, 1 }, { "»", { 0x8B }, 1 }, { "j", { 0x91 }, 1 }, { "k", { 0x92 }, 1 }, { "l", { 0x93 }, 1 }, { "m", { 0x94 }, 1 }, { "n", { 0x95 }, 1 },
	{ "o", { 0x96 }, 1 }, { "p", { 0x97 }, 1 }, { "q", { 0x98 }, 1 }, { "r", { 0x99 }, 1 }, { "~", { 0xA1 }, 1 }, { "s", { 0xA2 }, 1 }, { "t", { 0xA3 }, 1 }, { "u", { 0xA4 }, 1 }, { "v", { 0xA5 }, 1 },
	{ "w", { 0xA6 }, 1 }, { "x", { 0xA7 }, 1 }, { "y", { 0xA8 }, 1 }, { "z", { 0xA9 }, 1 }, { "®", { 0xAF }, 1 }, { "©", { 0xB4 }, 1 },
	{ "{", { 0xC0 }, 1 }, { "A", { 0xC1 }, 1 }, { "B", { 0xC2 }, 1 }, { "C", { 0xC3 }, 1 }, { "D", { 0xC4 }, 1 }, { "E", { 0xC5 }, 1 }, { "F", { 0xC6 }, 1 },
	{ "G", { 0xC7 }, 1 }, { "H", { 0xC8 }, 1 }, { "I", { 0xC9 }, 1 }, { "}", { 0xD0 }, 1 }, { "J", { 0xD1 }, 1 }, { "K", { 0xD2 }, 1 }, { "L", { 0xD3 }, 1 }, { "M", { 0xD4 }, 1 }, { "N", { 0xD5 }, 1 },
	{ "O", { 0xD6 }, 1 }, { "P", { 0xD7 }, 1 }, { "Q", { 0xD8 }, 1 }, { "R", { 0xD9 }, 1 }, { "\\", { 0xE0 }, 1 }, { "S", { 0xE2 }, 1 }, { "T", { 0xE3 }, 1 }, { "U", { 0xE4 }, 1 }, { "V", { 0xE5 }, 1 },
	{ "W", { 0xE6 }, 1 }, { "X", { 0xE7 }, 1 }, { "Y", { 0xE8 }, 1 }, { "Z", { 0xE9 }, 1 }, { "0", { 0xF0 }, 1 }, { "1", { 0xF1 }, 1 }, { "2", { 0xF2 }, 1 }, { "3", { 0xF3 }, 1 },
	{ "4", { 0xF4 }, 1 }, { "5", { 0xF5 }, 1 }, { "6", { 0xF6 }, 1 }, { "7", { 0xF7 }, 1 }, { "8", { 0xF8 }, 1 }, { "9", { 0xF9 }, 1 },
	{ NULL, { 0 }, 0 }
};
// clang-format on

static int decode(RMutaSession *cj, const ut8 *in, int len, ut8 **out, int *consumed) {
	const char *s;
	if (!cj || !in || !out || !consumed || len < 1) {
		return 0;
	}
	s = r_muta_charset_lookup_decode (ebcdic37_table, in, len, consumed);
	if (!s || *consumed < 1) {
		s = "?";
		*consumed = 1;
	}
	*out = (ut8 *)strdup (s);
	return *out? (int)strlen ((const char *)*out): 0;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (!cj || !buf || len < 0) {
		return false;
	}
	switch (cj->dir) {
	case R_CRYPTO_DIR_DECRYPT:
		obuf = r_muta_charset_decode (buf, len, &olen, ebcdic37_table, "?");
		break;
	case R_CRYPTO_DIR_ENCRYPT:
		obuf = r_muta_charset_encode_ex (buf, len, &olen, ebcdic37_table, r_muta_charset_parse_default, 0x6F);
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

RMutaPlugin r_muta_plugin_charset_ebcdic37 = {
	.meta = { .name = "ebcdic37", .license = "MIT", .desc = "EBCDIC CP37 charset" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "ebcdic37",
	.decode = decode,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ebcdic37 };
#endif
