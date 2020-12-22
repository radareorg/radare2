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
static const char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

static void local_b64_encode(const ut8 in[3], char out[4], int len) {
	if (len < 1) {
		return;
	}
	out[0] = cb64[in[0] >> 2];
	out[1] = cb64[((in[0] & 0x03) << 4) | ((len > 1)? ((in[1] & 0xf0) >> 4): 0)];
	out[2] = (len > 1? cb64[((in[1] & 0x0f) << 2) | (len > 2? ((in[2] & 0xc0) >> 6): 0)]: '=');
	out[3] = (len > 2? cb64[in[2] & 0x3f]: '=');
}

static int local_b64_decode(const char in[4], ut8 out[3]) {
	int len = 3;
	ut8 i, v[4] = { 0 };
	for (i = 0; i < 4; i++) {
		if (in[i] < 43 || in[i] > 122) {
			return -1;
		}
		v[i] = cd64[in[i] - 43];
		if (v[i] == '$') {
			len = i? i - 1: -1;
			break;
		}
		v[i] -= 62;
	}
	out[0] = v[0] << 2 | v[1] >> 4;
	out[1] = v[1] << 4 | v[2] >> 2;
	out[2] = ((v[2] << 6) & 0xc0) | v[3];
	return len;
}

R_API int r_base64_decode(ut8 *bout, const char *bin, int len) {
	int in, out;
	if (len < 0) {
		len = strlen (bin);
	}
	for (in = out = 0; in + 3 < len; in += 4) {
		int ret = local_b64_decode (bin + in, bout + out);
		if (ret < 1) {
			return -1;
		}
		out += ret;
	}
	bout[out] = 0;
	/* XXX this makes no sense, just return out? */
	return (in != out)? out: -1;
}

R_API ut8 *r_base64_decode_dyn(const char *in, int len) {
	ut8 *bout;
	if (!in) {
		return NULL;
	}
	if (len < 0) {
		len = strlen (in) + 1;
	}
	bout = calloc (4, len + 1);
	if (r_base64_decode (bout, in, len) == -1) {
		free (bout);
		return NULL;
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

R_API char *r_base64_encode_dyn(const char *str, int len) {
	char *bout;
	int in, out;
	if (!str) {
		return NULL;
	}
	if (len < 0) {
		len = strlen (str);
	}
	const int olen = (len * 4) + 2;
	if (olen < len) {
		return NULL;
	}
	bout = (char *)malloc (olen);
	if (!bout) {
		return NULL;
	}
	for (in = out = 0; in < len; in += 3, out += 4) {
		local_b64_encode ((const ut8 *)str + in, (char *)bout + out,
			(len - in) > 3 ? 3 : len - in);
	}
	bout[out] = 0;
	return bout;
}
