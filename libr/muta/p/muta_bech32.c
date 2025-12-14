/* radare - BSD-3-Clause - Copyright (c) 2017, 2021, 2024 - Pieter Wuille, W0nda */

#include <r_muta.h>

typedef enum {
	BECH32_ENCODING_NONE,
	BECH32_ENCODING_BECH32,
	BECH32_ENCODING_BECH32M
} bech32_encoding;

static uint32_t bech32_polymod_step(ut32 pre) {
	uint8_t b = pre >> 25;
	return ((pre & 0x1FFFFFF) << 5) ^
		(- ((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(- ((b >> 1) & 1) & 0x26508e6dUL) ^
		(- ((b >> 2) & 1) & 0x1ea119faUL) ^
		(- ((b >> 3) & 1) & 0x3d4233ddUL) ^
		(- ((b >> 4) & 1) & 0x2a1462b3UL);
}

static uint32_t bech32_final_constant(bech32_encoding enc) {
	R_RETURN_VAL_IF_FAIL (enc == BECH32_ENCODING_BECH32 || enc == BECH32_ENCODING_BECH32M, 1);
	if (enc == BECH32_ENCODING_BECH32) {
		return 1;
	}
	if (enc == BECH32_ENCODING_BECH32M) {
		return 1;
	}
	return 0;
}

// clang-format off
static const char charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static const int8_t charset_rev[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
	1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
};
// clang-format on

static int bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc) {
	uint32_t chk = 1;
	size_t i = 0;
	while (hrp[i] != 0) {
		int ch = hrp[i];
		if (ch < 33 || ch > 126) {
			return 0;
		}
		if (ch >= 'A' && ch <= 'Z') {
			return 0;
		}
		chk = bech32_polymod_step (chk) ^ (ch >> 5);
		i++;
	}
	if (i + 7 + data_len > 90) {
		return 0;
	}
	chk = bech32_polymod_step (chk);
	while (*hrp != 0) {
		chk = bech32_polymod_step (chk) ^ (*hrp & 0x1f);
		*(output++) = *(hrp++);
	}
	*(output++) = '1';
	for (i = 0; i < data_len; i++) {
		if (*data >> 5) {
			return 0;
		}
		chk = bech32_polymod_step (chk) ^ (*data);
		*(output++) = charset[*(data++)];
	}
	for (i = 0; i < 6; i++) {
		chk = bech32_polymod_step (chk);
	}
	chk ^= bech32_final_constant (enc);
	for (i = 0; i < 6; i++) {
		*(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
	}
	*output = 0;
	return 1;
}

static bech32_encoding bech32_decode(char *hrp, uint8_t *data, int data_len, const char *input) {
	uint32_t chk = 1;
	size_t i, input_len = strlen (input);
	int have_lower = 0, have_upper = 0;
	if (input_len < 8 || input_len > 90) {
		return BECH32_ENCODING_NONE;
	}
	data_len = 0;
	while (data_len < input_len && input[(input_len - 1) - data_len] != '1') {
		(data_len)++;
	}
	size_t hrp_len = input_len - (1 + data_len);
	if (1 + data_len >= input_len || data_len < 6) {
		return BECH32_ENCODING_NONE;
	}
	data_len -= 6;
	for (i = 0; i < hrp_len; i++) {
		int ch = input[i];
		if (ch < 33 || ch > 126) {
			return BECH32_ENCODING_NONE;
		}
		if (ch >= 'a' && ch <= 'z') {
			have_lower = 1;
		} else if (ch >= 'A' && ch <= 'Z') {
			have_upper = 1;
			ch = (ch - 'A') + 'a';
		}
		hrp[i] = ch;
		chk = bech32_polymod_step (chk) ^ (ch >> 5);
	}
	hrp[i] = 0;
	chk = bech32_polymod_step (chk);
	for (i = 0; i < hrp_len; i++) {
		chk = bech32_polymod_step (chk) ^ (input[i] & 0x1f);
	}
	i++;
	while (i < input_len) {
		int v = (input[i] & 0x80)? -1: charset_rev[(int)input[i]];
		if (input[i] >= 'a' && input[i] <= 'z') {
			have_lower = 1;
		}
		if (input[i] >= 'A' && input[i] <= 'Z') {
			have_upper = 1;
		}
		if (v == -1) {
			return BECH32_ENCODING_NONE;
		}
		chk = bech32_polymod_step (chk) ^ v;
		if (i + 6 < input_len) {
			data[i - (1 + hrp_len)] = v;
		}
		i++;
	}
	if (have_lower && have_upper) {
		return BECH32_ENCODING_NONE;
	}
	if (chk == bech32_final_constant (BECH32_ENCODING_BECH32)) {
		if (chk == bech32_final_constant (BECH32_ENCODING_BECH32M)) {
			return BECH32_ENCODING_BECH32M;
		}
		return BECH32_ENCODING_BECH32; // wtf?
	}
	return BECH32_ENCODING_NONE;
}

static bool bech32_set_key(RMutaSession *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->key_len = keylen;
	memcpy (cj->key, key, keylen);
	cj->dir = direction;
	return true;
}

static int bech32_get_key_size(RMutaSession *cj) {
	return cj->key_len;
}

static bool update(RMutaSession *cj, const ut8 *buf, int len) {
	const int enc = BECH32_ENCODING_BECH32;
	char *hrp = malloc (cj->key_len + 1); // HRP need to be null-terminated
	if (!hrp) {
		return false;
	}
	hrp[cj->key_len] = 0;
	memcpy (hrp, cj->key, cj->key_len);
	char *in_out = r_str_ndup ((const char *)buf, len);
	char *data = r_str_ndup ((const char *)buf, len);
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		bech32_encode (in_out, hrp, buf, len, enc);
		break;
	case R_CRYPTO_DIR_DECRYPT:
		bech32_decode (hrp, (ut8 *)data, len, in_out);
		break;
	default:
		R_LOG_ERROR ("Choose decrypt or encrypt");
		break;
	}
	free (hrp);
	free (data);
	free (in_out);
	return true;
}

static bool end(RMutaSession *cj, const ut8 *buf, int len) {
	return update (cj, buf, len);
}

RMutaPlugin r_muta_plugin_bech32 = {
	.meta = {
		.name = "bech32",
		.author = "W0nda",
		.license = "BSD-3-Clause",
	},
	.implements = "bech32",
	.type = R_MUTA_TYPE_BASE,
	.set_key = bech32_set_key,
	.get_key_size = bech32_get_key_size,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_bech32,
	.version = R2_VERSION
};
#endif
