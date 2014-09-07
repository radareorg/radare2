/* radare - LGPL - Copyright 2014 - pancake */

#include <r_util.h>
#include <zlib.h>


// set a maximum output buffer of 50MB
#define MAXOUT 50000000

R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *dstLen) {
	int err = 0;
	int out_size = 0;
	ut8 *dst = NULL;
	z_stream stream;

	if( srcLen <= 0 ) {
		return NULL;
	}

	memset (&stream, 0, sizeof (z_stream));
	stream.avail_in  = srcLen;
	stream.next_in   = (Bytef *) src;

	stream.zalloc = Z_NULL;
	stream.zfree  = Z_NULL;
	stream.opaque = Z_NULL;

	// + 32 tells zlib not to care whether the stream is a zlib or gzip stream
	if( inflateInit2(&stream, MAX_WBITS + 32) != Z_OK ) {
		return NULL;
	}

	do {
		if( stream.avail_out == 0 ) {
			if (! (dst = realloc(dst, stream.total_out + srcLen*2)))
				goto err_exit;

			out_size += srcLen*2;

			if (out_size > MAXOUT)
				goto err_exit;

			stream.next_out  = dst + stream.total_out;
			stream.avail_out = srcLen * 2;
		}
		err = inflate(&stream, Z_FINISH);
		switch (err) {
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
			case Z_NEED_DICT:
				goto err_exit;
				break;
		}


	} while ( err != Z_STREAM_END );

	if( dstLen )
		*dstLen = stream.total_out;

	inflateEnd(&stream);
	return dst;

	err_exit:
	inflateEnd(&stream);
	free(dst);
	return NULL;
}
