/* Original code from:
 * dmc - dynamic mail client -- author: pancake
 * See LICENSE file for copyright and license details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_util.h>

#define SZ 1024
static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// This table will handle standard base64 decoding and also url safe decoding with characteres "-" and "_"
static const char cd64[] = "|$|$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$}$XYZ[\\]^_`abcdefghijklmnopq";

static void local_b64_encode(const ut8 in[3], char out[4], int len) {
	if (len < 1) {
		return;
	}
	out[0] = cb64[in[0] >> 2];
	out[1] = cb64[((in[0] & 0x03) << 4) | ((len > 1)? ((in[1] & 0xf0) >> 4): 0)];
	out[2] = (len > 1? cb64[((in[1] & 0x0f) << 2) | (len > 2? ((in[2] & 0xc0) >> 6): 0)]: '=');
	out[3] = (len > 2? cb64[in[2] & 0x3f]: '=');
}

static int local_b64_value(const char c) {
	if (c < 43 || c > 122) {
		return -1;
	}
	const char v = cd64[c - 43];
	return (v == '$')? -1: v - 62;
}

// emit the bytes encoded by an incomplete group of nchars sextets
static int local_b64_flush(const ut8 v[4], int nchars, ut8 *out) {
	switch (nchars) {
	case 4:
		out[2] = (v[2] << 6) | v[3];
		// fallthrough
	case 3:
		out[1] = (v[1] << 4) | (v[2] >> 2);
		// fallthrough
	case 2:
		out[0] = (v[0] << 2) | (v[1] >> 4);
		break;
	default:
		return 0;
	}
	return nchars - 1;
}

static int local_b64_decode_strict(ut8 *bout, const char *bin, int len) {
	if (len % 4) {
		return -1;
	}
	int in, out = 0;
	for (in = 0; in < len; in += 4) {
		ut8 v[4] = {0};
		int nchars = 0;
		int i;
		for (i = 0; i < 4; i++) {
			const char c = bin[in + i];
			if (c == '=') {
				break;
			}
			const int val = local_b64_value (c);
			if (val < 0) {
				return -1;
			}
			v[i] = (ut8)val;
			nchars++;
		}
		if (nchars < 4) {
			// padding is only valid at the tail of the last group
			if (in + 4 != len || nchars < 2) {
				return -1;
			}
			for (i = nchars; i < 4; i++) {
				if (bin[in + i] != '=') {
					return -1;
				}
			}
		}
		out += local_b64_flush (v, nchars, bout + out);
	}
	bout[out] = 0;
	return out;
}

R_API int r_base64_decode(ut8 *bout, const char *bin, int len, bool strict) {
	R_RETURN_VAL_IF_FAIL (bout && bin, -1);
	if (len < 0) {
		len = strlen (bin);
	}
	if (strict) {
		return local_b64_decode_strict (bout, bin, len);
	}
	// tolerant mode: skip invalid bytes (newlines, spaces, junk) instead of
	// truncating, let '=' close the current group and recover trailing
	// groups of unpadded input
	ut8 v[4] = {0};
	int in, out = 0, nchars = 0;
	for (in = 0; in < len; in++) {
		const char c = bin[in];
		if (c == '=') {
			out += local_b64_flush (v, nchars, bout + out);
			nchars = 0;
			continue;
		}
		const int val = local_b64_value (c);
		if (val < 0) {
			continue;
		}
		v[nchars++] = (ut8)val;
		if (nchars == 4) {
			out += local_b64_flush (v, 4, bout + out);
			nchars = 0;
		}
	}
	out += local_b64_flush (v, nchars, bout + out);
	bout[out] = 0;
	return out;
}

R_API ut8 *r_base64_decode_dyn(const char *in, int len, int *olen, bool strict) {
	R_RETURN_VAL_IF_FAIL (in, NULL);
	if (olen) {
		*olen = 0;
	}
	const size_t slen = len < 0? strlen (in): (size_t)len;
	if (slen > ST32_MAX) {
		return NULL;
	}
	ut8 *bout = malloc ((((slen / 4) + 1) * 3) + 1);
	if (!bout) {
		return NULL;
	}
	int res = r_base64_decode (bout, in, (int)slen, strict);
	if (res < 0) {
		free (bout);
		return NULL;
	}
	if (olen) {
		*olen = res;
	}
	return bout;
}

R_API int r_base64_encode(char *bout, const ut8 *bin, int len) {
	int in, out;
	if (len < 0) {
		len = strlen ((const char *)bin);
	}
	for (in = out = 0; in < len; in += 3, out += 4) {
		local_b64_encode (bin + in, (char *)bout + out,
			(len - in) > 3 ? 3 : len - in);
	}
	bout[out] = 0;
	return out;
}

R_API char *r_base64_encode_dyn(const ut8 *str, int len) {
	R_RETURN_VAL_IF_FAIL (str, NULL);
	const size_t slen = len < 0? strlen ((const char *)str): (size_t)len;
	size_t olen;
	if (r_add_overflow (slen, (size_t)2, &olen)
			|| r_mul_overflow (olen / 3, (size_t)4, &olen)
			|| r_add_overflow (olen, (size_t)1, &olen)) {
		return NULL;
	}
	char *bout = (char *)malloc (olen);
	if (!bout) {
		return NULL;
	}
	size_t in, out;
	for (in = out = 0; in < slen; in += 3, out += 4) {
		local_b64_encode (str + in, bout + out,
			(int)R_MIN (slen - in, 3));
	}
	bout[out] = 0;
	return bout;
}
