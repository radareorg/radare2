/* Original code from:
 * dmc - dynamic mail client -- author: pancake
 * See LICENSE file for copyright and license details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <r_util.h>

#define SZ 1024
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

static void b64_encode(const ut8 in[3], char out[4], int len) {
	if (len<1) return;
	out[0] = cb64[ in[0] >> 2 ];
	out[1] = cb64[ ((in[0] & 0x03) << 4) | ((len>1)?((in[1] & 0xf0) >> 4):0) ];
	out[2] = (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | (len > 2 ? ((in[2] & 0xc0) >> 6) : 0) ] : '=');
	out[3] = (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

static int b64_decode(const char in[4], ut8 out[3]) {
	ut8 len = 3, i, v[4] = {0};
	for (i=0; i<4; i++) {
		if (in[i]<43 || in[i]>122)
			return -1;
		v[i] = cd64[in[i]-43];
		if (v[i]=='$') {
			len = i-1;
			break;
		} else v[i]-=62;
	}
	out[0] = v[0] << 2 | v[1] >> 4;
	out[1] = v[1] << 4 | v[2] >> 2;
	out[2] = ((v[2] << 6) & 0xc0) | v[3];
	return len;
}

R_API int r_base64_decode(ut8 *bout, const char *bin, int len) {
	int in, out, ret;
	if (len<1)
		len = strlen (bin);
	for (in=out=0; in<len-1;in+=4) {
		ret = b64_decode (bin+in, bout+out);
		if (ret <1)
			break;
		out += ret;
	}
	bout[out] = 0;
	return (in != out)? out: 0;
}

R_API void r_base64_encode(ut8 *bout, const ut8 *bin, int len) {
	int in, out;
	if (len<1)
		len = strlen ((const char*)bin)+1;
	for (in=out=0; in<len; in+=3,out+=4)
		b64_encode (bin+in, (char*)bout+out,
			(len-in)>3?3:len-in);
	bout[out] = 0;
}
