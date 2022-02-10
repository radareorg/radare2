/* radare - LGPL - Copyright 2014-2022 - pancake */

#include <r_util.h>
#include <zlib.h>
#include "../../../shlr/lz4/lz4.h"

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

static ut8 *r_inflatew(const ut8 *src, int srcLen, int *consumed, int *dstLen, int wbits) {
	int err = 0;
	size_t out_size = 0;
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
			eprintf ("inflate error: %d %s\n", err, gzerr (-err));
			goto err_exit;
		}
	} while (err != Z_STREAM_END);

	if (dstLen) {
		*dstLen = stream.total_out;
	}
	if (consumed) {
		*consumed = (const ut8 *)stream.next_in - (const ut8 *)src;
	}

	inflateEnd (&stream);
	return dst;

	err_exit:
	inflateEnd (&stream);
	free (dst);
	return NULL;
}

R_API ut8 *r_inflate_lz4(const ut8 *src, int srcLen, int *consumed, int *dstLen) {
	ut32 osz = srcLen * 5;
	ut8 *obuf = calloc (srcLen, 5);
	if (!obuf) {
		return NULL;
	}
	int res = LZ4_decompress_safe ((const char*)src, (char*)obuf, (uint32_t) srcLen, (uint32_t) osz);
	if (res < 1) {
		int mul = srcLen / -res;
		int nosz = osz * (5 * (mul + 1));
		if (nosz < osz) {
			free (obuf);
			return NULL;
		}
		ut8 *nbuf = realloc (obuf, nosz);
		if (!nbuf) {
			free (obuf);
			return NULL;
		}
		obuf = nbuf;
		osz = nosz;
	}
	res = LZ4_decompress_safe ((const char*)src, (char*)obuf, (uint32_t) srcLen, (uint32_t) osz);
	if (res > 0) {
		*dstLen = res;
		*consumed = srcLen;
		return obuf;
	}
	*dstLen = 0;
	*consumed = 0;
	free (obuf);
	return NULL;
}

R_API ut8 *r_inflate(const ut8 *src, int srcLen, int *consumed, int *dstLen) {
	return r_inflatew (src, srcLen, consumed, dstLen, MAX_WBITS + 32);
}

R_API ut8 *r_inflate_raw(const ut8 *src, int srcLen, int *consumed, int *dstLen) {
	return r_inflatew (src, srcLen, consumed, dstLen, -MAX_WBITS);
}
