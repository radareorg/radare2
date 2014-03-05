/* base64 enc/dec - LGPLv3 - Copyright 2011-2014 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sdb.h"

#define SZ 1024
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

static void b64_encode(const ut8 in[3], char out[4], int len) {
	out[0] = cb64[ in[0] >> 2 ];
	out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
	out[2] = (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
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
		}
		v[i]-=62;
	}
	out[0] = v[0] << 2 | v[1] >> 4;
	out[1] = v[1] << 4 | v[2] >> 2;
	out[2] = ((v[2] << 6) & 0xc0) | v[3];
	return len;
}

SDB_API void sdb_encode_raw(char *bout, const ut8 *bin, int len) {
	int in, out;
	for (in=out=0; in<len; in+=3,out+=4)
		b64_encode (bin+in, bout+out, len-in>3?3:len-in);
	bout[out] = 0;
}

SDB_API int sdb_decode_raw(ut8 *bout, const char *bin, int len) {
	int in, out, ret;
	for (in=out=0; in<len-1;in+=4) {
		if ((ret = b64_decode (bin+in, bout+out))<1)
			break;
		out += 3;
	}
	bout[out-1] = 0;
	return (in != out);
}

SDB_API char *sdb_encode(const ut8 *bin, int len) {
	char *out;
	if (len<1)
		len = strlen ((const char *)bin)+1;
	if (len==0)
		return strdup ("");
	out = malloc (len*2);
	if (!out)
		return NULL;
	memset (out, 0, len+8);
	sdb_encode_raw (out, bin, len);
	return out;
}

SDB_API ut8 *sdb_decode (const char *in, int *len) {
	ut8 *out;
	int olen, ilen = strlen (in);
	if (ilen<1)
		return NULL;
	out = malloc (ilen*2);
	if (!out)
		return NULL;
	memset (out, 0, ilen+8);
	olen = sdb_decode_raw (out, in, ilen);
	if (!olen) {
		free (out);
		return NULL;
	}
	if (len)
		*len = olen;
	return out;
}
