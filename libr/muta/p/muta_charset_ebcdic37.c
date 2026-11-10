/* radare - MIT - Copyright 2026 - pancake */

#include <r_muta.h>
#include <r_muta/charset.h>

// clang-format off
static const ut8 ebcdic37_to_ascii[256] = {
	  0,   1,   2,   3, 156,   9, 134, 127, 151, 141, 142,  11,  12,  13,  14,  15,
	 16,  17,  18,  19, 157,  10,   8, 135,  24,  25, 146, 143,  28,  29,  30,  31,
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

// Unicode U+0000..U+00FF to IBM CP37; keep legacy display translation separate.
static const ut8 unicode_to_ebcdic37[256] = {
	0x00, 0x01, 0x02, 0x03, 0x37, 0x2d, 0x2e, 0x2f, 0x16, 0x05, 0x25, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x3c, 0x3d, 0x32, 0x26, 0x18, 0x19, 0x3f, 0x27, 0x1c, 0x1d, 0x1e, 0x1f,
	0x40, 0x5a, 0x7f, 0x7b, 0x5b, 0x6c, 0x50, 0x7d, 0x4d, 0x5d, 0x5c, 0x4e, 0x6b, 0x60, 0x4b, 0x61,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x5e, 0x4c, 0x7e, 0x6e, 0x6f,
	0x7c, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
	0xd7, 0xd8, 0xd9, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xba, 0xe0, 0xbb, 0xb0, 0x6d,
	0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
	0x97, 0x98, 0x99, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xc0, 0x4f, 0xd0, 0xa1, 0x07,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x09, 0x0a, 0x1b,
	0x30, 0x31, 0x1a, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3a, 0x3b, 0x04, 0x14, 0x3e, 0xff,
	0x41, 0xaa, 0x4a, 0xb1, 0x9f, 0xb2, 0x6a, 0xb5, 0xbd, 0xb4, 0x9a, 0x8a, 0x5f, 0xca, 0xaf, 0xbc,
	0x90, 0x8f, 0xea, 0xfa, 0xbe, 0xa0, 0xb6, 0xb3, 0x9d, 0xda, 0x9b, 0x8b, 0xb7, 0xb8, 0xb9, 0xab,
	0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9e, 0x68, 0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,
	0xac, 0x69, 0xed, 0xee, 0xeb, 0xef, 0xec, 0xbf, 0x80, 0xfd, 0xfe, 0xfb, 0xfc, 0xad, 0xae, 0x59,
	0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9c, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
	0x8c, 0x49, 0xcd, 0xce, 0xcb, 0xcf, 0xcc, 0xe1, 0x70, 0xdd, 0xde, 0xdb, 0xdc, 0x8d, 0x8e, 0xdf,
};

static int encode(RMutaSession *ms, const ut8 *in, int len, ut8 **out, int *consumed) {
	R_RETURN_VAL_IF_FAIL (in && len >= 0 && out && consumed, -1);
	*out = NULL;
	*consumed = 0;
	if (!len) {
		return 0;
	}
	ut8 *buf = malloc (len);
	if (!buf) {
		return -1;
	}
	int size = 0;
	while (*consumed < len) {
		RRune rune;
		int n = r_utf8_decode (in + *consumed, len - *consumed, &rune);
		if (!n || rune > UT8_MAX) {
			free (buf);
			return -1;
		}
		buf[size++] = unicode_to_ebcdic37[rune];
		*consumed += n;
	}
	*out = buf;
	return size;
}

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
	.encode = encode,
	.decode = decode,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = { .type = R_LIB_TYPE_MUTA, .data = &r_muta_plugin_charset_ebcdic37 };
#endif
