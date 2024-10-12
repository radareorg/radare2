/* Copyright (c) 2017, 2021 Pieter Wuille
 *  Updated by W0nda in 2024
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <r_lib.h>
#include <r_crypto.h>
#include <r_util.h>

#include <assert.h>
#include <stdint.h>

static uint32_t bech32_polymod_step(uint32_t pre) {
	uint8_t b = pre >> 25;
	return ((pre & 0x1FFFFFF) << 5) ^
		(-((b >> 0) & 1) & 0x3b6a57b2UL) ^
		(-((b >> 1) & 1) & 0x26508e6dUL) ^
		(-((b >> 2) & 1) & 0x1ea119faUL) ^
		(-((b >> 3) & 1) & 0x3d4233ddUL) ^
		(-((b >> 4) & 1) & 0x2a1462b3UL);
}

static uint32_t bech32_final_constant(bech32_encoding enc) {
	if (enc == BECH32_ENCODING_BECH32) {
		return 1;
	}
	if (enc == BECH32_ENCODING_BECH32M) {
		return 0x2bc830a3;
	}
	assert (0);
}

static const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

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

static bool bech32_set_key(RCryptoJob *cj, const ut8 *key, int keylen, int mode, int direction) {
	cj->dir = direction;
	return true;
}

static int bech32_get_key_size(RCryptoJob *cj) {
	return 0;
}

static bool bech32_check(const char *algo) {
	return !strcmp (algo, "bech32");
}

int bech32_encode (char *output, const char *hrp, const uint8_t *data, size_t data_len, bech32_encoding enc) {
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

bech32_encoding bech32_decode (char *hrp, uint8_t *data, size_t *data_len, const char *input) {
	uint32_t chk = 1;
	size_t i;
	size_t input_len = strlen (input);
	size_t hrp_len;
	int have_lower = 0, have_upper = 0;
	if (input_len < 8 || input_len > 90) {
		return BECH32_ENCODING_NONE;
	}
	*data_len = 0;
	while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
		(*data_len)++;
	}
	hrp_len = input_len - (1 + *data_len);
	if (1 + *data_len >= input_len || *data_len < 6) {
		return BECH32_ENCODING_NONE;
	}
	*(data_len) -= 6;
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
		if (input[i] >= 'a' && input[i] <= 'z')
			have_lower = 1;
		if (input[i] >= 'A' && input[i] <= 'Z')
			have_upper = 1;
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
		return BECH32_ENCODING_BECH32;
		if (chk == bech32_final_constant (BECH32_ENCODING_BECH32M)) {
			return BECH32_ENCODING_BECH32M;
		}
		return BECH32_ENCODING_NONE;
	}
}

static bool update(RCryptoJob *cj, char *hrp, uint8_t *data, size_t *data_len, const char *in_out) {
	switch (cj->dir) {
	case R_CRYPTO_DIR_ENCRYPT:
		bech32_encode (in_out, hrp, data, data_len, enc);
	case R_CRYPTO_DIR_DECRYPT:
		bech32_decode (hrp, data, data_len, in_out);
	}
	return true;
}

static bool end(RCryptoJob *cj, const ut8 *buf, int len) {
	return update (cj, hrp, data, data_len, in_out, enc);
}

RCryptoPlugin r_crypto_plugin_bech32 = {
	.meta = {
		.name = "bech32",
		.author = "W0nda",
	},
	.type = R_CRYPTO_TYPE_ENCODER,
	.set_key = bech32_set_key,
	.get_key_size = bech32_get_key_size,
	.check = bech32_check,
	.update = update,
	.end = end
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_crypto_plugin_bech32,
	.version = R2_VERSION
};
#endif
