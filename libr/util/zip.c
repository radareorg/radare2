/* radare - LGPL - Copyright 2014-2015 - pancake */

#include <r_util.h>
#include <zlib.h>


// set a maximum output buffer of 50MB
#define MAXOUT 50000000

static const char *gzerr(int n) {
	const char *errors[] = {
		"",
		"file error",          /* Z_ERRNO         (-1) */
		"stream error",        /* Z_STREAM_ERROR  (-2) */
		"data error",          /* Z_DATA_ERROR    (-3) */
		"insufficient memory", /* Z_MEM_ERROR     (-4) */
		"buffer error",        /* Z_BUF_ERROR     (-5) */
		"incompatible version",/* Z_VERSION_ERROR (-6) */
	};
	if (n<1 || n>6) {
		return "unknown";
	}
	return errors[n];
}

/**
 * \brief inflate zlib compressed or gzipped.
 * \param src source compressed bytes
 * \param srcLen source bytes length
 * \param srcConsumed comsumed source bytes length
 * \param dstLen uncompressed uncompressed bytes length
 * \param controls the size of the history buffer (or “window size”), and what header and trailer format is expected.
 * \return ptr to uncompressed
*/
static ut8 *r_inflatew(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen, int wbits) {
	int err = 0;
	int out_size = 0;
	ut8 *dst = NULL;
	ut8 *tmp_ptr;
	z_stream stream;

	if (srcLen <= 0) {
		return NULL;
	}

	memset (&stream, 0, sizeof (z_stream));
	stream.avail_in  = srcLen;
	stream.next_in   = (Bytef *) src;

	stream.zalloc = Z_NULL;
	stream.zfree  = Z_NULL;
	stream.opaque = Z_NULL;

	if (inflateInit2 (&stream, wbits) != Z_OK) {
		return NULL;
	}

	do {
		if (stream.avail_out == 0) {
			tmp_ptr = realloc (dst, stream.total_out + srcLen * 2);
			if (!tmp_ptr) {
				goto err_exit;
			}
			dst = tmp_ptr;
			out_size += srcLen*2;
			if (out_size > MAXOUT) {
				goto err_exit;
			}
			stream.next_out  = dst + stream.total_out;
			stream.avail_out = srcLen * 2;
		}
		err = inflate (&stream, Z_NO_FLUSH);
		if (err < 0) {
			eprintf ("inflate error: %d %s\n",
				err, gzerr (-err));
			goto err_exit;
		}
	} while (err != Z_STREAM_END);

	if (dstLen) {
		*dstLen = stream.total_out;
	}
	if (srcConsumed) {
		*srcConsumed = (const ut8 *)stream.next_in - (const ut8 *)src;
	}

	inflateEnd (&stream);
	return dst;

	err_exit:
	inflateEnd (&stream);
	free (dst);
	return NULL;
}

/**
 * @brief inflate zlib compressed or gzipped, automatically accepts either the
 * zlib or gzip format, and use MAX_WBITS as the window size logarithm.
 * @see r_inflatew()
*/
R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen) {
	return r_inflatew (src, srcLen, srcConsumed, dstLen, MAX_WBITS + 32);
}

/**
 * @brief inflate zlib compressed or gzipped. The input must be a raw stream
 * with no header or trailer.
 * @see r_inflatew()
*/
R_API ut8 *r_inflate_ignore_header(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen) {
	return r_inflatew (src, srcLen, srcConsumed, dstLen, -MAX_WBITS);
}
