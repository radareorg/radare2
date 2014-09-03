/* radare - LGPL - Copyright 2014 - pancake */

#include <r_util.h>
#include <zlib.h>

// TODO: add r_gzip

// avoid gzipbombs
#define MAXRETRIES 10

R_API ut8 *r_gunzip(const ut8 *src, int srcLen, int *dstLen) {
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

	// ZLIB
	//err = inflateInit2(&strm, (15 + 32)); //15 window bits, and the +32 tells zlib to to detect if using gzip or zlib
	// GZIP
	err = inflateInit2(&strm, 16+MAX_WBITS);
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

R_API int r_zip_decompress (ut8 *buf, int buf_size, ut8 **out, int *out_size) {
	z_stream *stream = R_NEW0(z_stream);
	int wbits, dec_size = buf_size * 2;
	ut8 *dec_buf = malloc(dec_size);
	*out = NULL;
	*out_size = 0;
	if (!stream || !dec_buf)
		goto err_exit;
	/* Check for zlib header */
	if (buf[0] == 0x78 && buf[1] == 0x9C)
		wbits = MAX_WBITS;
	else
		wbits = -MAX_WBITS;
	if (inflateInit2(stream, wbits) != Z_OK)
		goto err_exit;
	stream->next_in = buf;
	stream->avail_in = buf_size;
	stream->next_out = dec_buf;
	stream->avail_out = dec_size;
	int ret, size;
	for (;;) {
		ret = inflate(stream, Z_FINISH);
		switch (ret) {
			case Z_STREAM_END:
				*out = dec_buf;
				*out_size = stream->next_out - dec_buf;
				inflateEnd(stream);
				free(stream);
				return R_TRUE;
			case Z_BUF_ERROR:
				size = stream->next_out - dec_buf;
				dec_size *= 2;
				dec_buf = realloc(dec_buf, dec_size);
				if (!dec_buf)
					goto err_exit;
				stream->next_out = dec_buf + size;
				stream->avail_out = dec_size - size;
				break;
			default:
				eprintf("Unhandled zlib error! (%i)\n", ret);
				goto err_exit;
		}
	}
err_exit:
	inflateEnd(stream);
	free(stream);
	free(dec_buf);
	*out = NULL;
	*out_size = 0;
	return R_FALSE;
}
