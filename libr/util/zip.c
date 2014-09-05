/* radare - LGPL - Copyright 2014 - pancake */

#include <r_util.h>
#include <zlib.h>

// TODO: add r_gzip

// avoid gzipbombs
#define MAXRETRIES 10

R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *dstLen) {
	ut8 *dst = NULL, *dst2;
	z_stream strm;
	int tryLen = 1+(srcLen * 4);
	int retries = 0;
	// TODO: optimize this using an incremental method
	retrygunzip:
	free (dst);
	if (++retries>MAXRETRIES)
		return NULL;
	if (tryLen<1)
		return NULL;
	memset (&strm, 0, sizeof (z_stream));
	dst = malloc (tryLen+1);
	if (!dst)
		return NULL;
	strm.total_in  = strm.avail_in  = srcLen;
	strm.total_out = strm.avail_out = tryLen;
	strm.next_in   = (Bytef *) src;
	strm.next_out  = (Bytef *) dst;

	strm.zalloc = Z_NULL;
	strm.zfree  = Z_NULL;
	strm.opaque = Z_NULL;

	int err = -1;
	int ret = -1;

	// + 32 tells zlib not to care whether the stream is a zlib or gzip stream
	err = inflateInit2(&strm, MAX_WBITS + 32);
	if (err == Z_OK) {
		err = inflate(&strm, Z_FINISH);
		if (err == Z_STREAM_END) {
			ret = strm.total_out;
			if (dstLen)
				*dstLen = ret;
			dst[ret] = 0;
			dst2 = realloc (dst, ret+1);
			if (dst2)
				dst = dst2;
			return dst;
		} else {
			inflateEnd(&strm);
			if (err == Z_BUF_ERROR) {
				tryLen *= 2;
				goto retrygunzip;
			}
			return NULL;
		}
	} else {
		inflateEnd(&strm);
		if (err == Z_BUF_ERROR) {
			tryLen *= 2;
			goto retrygunzip;
		}
		return NULL;
	}

	inflateEnd(&strm);
	if (err == Z_BUF_ERROR) {
		tryLen *= 2;
		goto retrygunzip;
	}
	return NULL;
}
