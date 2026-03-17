/* radare - MIT - Copyright 2026 - pancake */

#include <r_muta.h>
#include <r_muta/charset.h>

// clang-format off
static const ut8 ebcdic37_to_ascii[256] = {
	  0,   1,   2,   3, 156,   9, 134, 127, 151, 141, 142,  11,  12,  13,  14,  15,
	 16,  17,  18,  19, 157, 133,   8, 135,  24,  25, 146, 143,  28,  29,  30,  31,
	128, 129, 130, 131, 132,  10,  23,  27, 136, 137, 138, 139, 140,   5,   6,   7,
	144, 145,  22, 147, 148, 149, 150,   4, 152, 153, 154, 155,  20,  21, 158,  26,
	' ', 160, 161, 162, 163, 164, 165, 166, 167, 168, 213, '.', '<', '(', '+', '|',
	'&', 169, 170, 171, 172, 173, 174, 175, 176, 177, '!', '$', '*', ')', ';', '~',
	'-', '/', 178, 179, 180, 181, 182, 183, 184, 185, 203, ',', '%', '_', '>', '?',
	186, 187, 188, 189, 190, 191, 192, 193, 194, '`', ':', '#', '@', '\'', '=', '"',
	195, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 196, 197, 198, 199, 200, 201,
	202, 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', '^', 204, 205, 206, 207, 208,
	209, 229, 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 210, 211, 212, '[', 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, ']', 230, 231,
	'{', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 232, 233, 234, 235, 236, 237,
	'}', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 238, 239, 240, 241, 242, 243,
	'\\', 159, 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 244, 245, 246, 247, 248, 249,
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 250, 251, 252, 253, 254, 255
};

static const ut8 ascii_to_ebcdic37[256] = {
	  0,   1,   2,   3,  55,  45,  46,  47,  22,   5,  37,  11,  12,  13,  14,  15,
	 16,  17,  18,  19,  60,  61,  50,  38,  24,  25,  63,  39,  28,  29,  30,  31,
	 64,  90, 127, 123,  91, 108,  80, 125,  77,  93,  92,  78, 107,  96,  75,  97,
	240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 122,  94,  76, 126, 110, 111,
	124, 193, 194, 195, 196, 197, 198, 199, 200, 201, 209, 210, 211, 212, 213, 214,
	215, 216, 217, 226, 227, 228, 229, 230, 231, 232, 233, 173, 224, 189, 154, 109,
	121, 129, 130, 131, 132, 133, 134, 135, 136, 137, 145, 146, 147, 148, 149, 150,
	151, 152, 153, 162, 163, 164, 165, 166, 167, 168, 169, 192,  79, 208,  95,   7,
	 32,  33,  34,  35,  36,  21,   6,  23,  40,  41,  42,  43,  44,   9,  10,  27,
	 48,  49,  26,  51,  52,  53,  54,   8,  56,  57,  58,  59,   4,  20,  62, 225,
	 65,  66,  67,  68,  69,  70,  71,  72,  73,  81,  82,  83,  84,  85,  86,  87,
	 88,  89,  98,  99, 100, 101, 102, 103, 104, 105, 112, 113, 114, 115, 116, 117,
	118, 119, 120, 128, 138, 139, 140, 141, 142, 143, 144, 106, 155, 156, 157, 158,
	159, 160, 170, 171, 172,  74, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183,
	184, 185, 186, 187, 188, 161, 190, 191, 202, 203, 204, 205, 206, 207, 218, 219,
	220, 221, 222, 223, 234, 235, 236, 237, 238, 239, 250, 251, 252, 253, 254, 255
};
// clang-format on

static bool ascii_to_ebcdic37_update(RMutaSession *ms, const ut8 *buf, int len) {
	const char *ptr = (const char *)buf;
	const char *end = ptr + len;
	char token[32];

	if (!ms || !buf || len < 0) {
		return false;
	}
	while (ptr < end) {
		token[0] = token[1] = 0;
		int consumed = r_muta_charset_parse_default (ptr, end, token, sizeof (token));
		ut8 out = 0x6F;
		if (consumed < 1) {
			consumed = 1;
		}
		if (!token[1]) {
			out = ascii_to_ebcdic37[(ut8)token[0]];
		}
		r_muta_session_append (ms, &out, 1);
		ptr += consumed;
	}
	return true;
}

static int decode(RMutaSession *ms, const ut8 *in, int len, ut8 **out, int *consumed) {
	return r_muta_charset_tr_decode (in, len, out, consumed, ebcdic37_to_ascii);
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (!ms || !buf || len < 0) {
		return false;
	}
	switch (ms->dir) {
	case R_MUTA_OP_DECRYPT:
		return r_muta_charset_tr_update (ms, buf, len, ebcdic37_to_ascii);
	case R_MUTA_OP_ENCRYPT:
		return ascii_to_ebcdic37_update (ms, buf, len);
	}
	return false;
}

RMutaPlugin r_muta_plugin_charset_ebcdic37 = {
	.meta = { .name = "ebcdic37", .license = "MIT", .desc = "EBCDIC CP37 charset" },
	.type = R_MUTA_TYPE_CHARSET,
	.implements = "ebcdic37",
	.decode = decode,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ebcdic37 };
#endif
