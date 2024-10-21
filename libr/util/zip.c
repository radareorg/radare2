/* radare - LGPL - Copyright 2014-2024 - pancake */

#include <r_util.h>
#include <zlib.h>

// set a maximum output buffer of 50MB
#define MAXOUT 50000000

#if USE_SMALLZ4
#include "../../../shlr/smallz4/smallz4cat.h"

struct UserPtr {
	const ut8 * input;
	ut64 inputPos;
	ut8 *output;
	ut64 outputPos;
	ut32 *outputSize;
	int error;
};

static void smallz4Write(const unsigned char* data, unsigned int numBytes, void *userPtr) {
	struct UserPtr* user = (struct UserPtr*)userPtr;
	if (data != NULL && numBytes > 0) {
		if (*(user->outputSize) - user->outputPos < numBytes) {
			user->error = -1;
			return;
		}
		memcpy(user->output + user->outputPos, data, numBytes);
		user->outputPos += numBytes;
	}
}

static ut8 smallz4GetByte(void *userPtr) {
	struct UserPtr* user = (struct UserPtr*)userPtr;
	return *(user->input + (user->inputPos++));
}
#else
#include <lz4.h>
#endif

static const char *gzerr(int n) {
	const char *const errors[] = {
		"",
		"file error",          /* Z_ERRNO         (-1) */
		"stream error",        /* Z_STREAM_ERROR  (-2) */
		"data error",          /* Z_DATA_ERROR    (-3) */
		"insufficient memory", /* Z_MEM_ERROR     (-4) */
		"buffer error",        /* Z_BUF_ERROR     (-5) */
		"incompatible version",/* Z_VERSION_ERROR (-6) */
	};
	if (R_UNLIKELY (n < 1 || n > 6)) {
		return "unknown";
	}
	return errors[n];
}

static ut8 *inflatew(const ut8 *src, int srcLen, int *consumed, int *dstLen, int wbits) {
	int err = 0;
	size_t out_size = 0;
	ut8 *dst = NULL;
	z_stream stream;

	if (srcLen <= 0) {
		return NULL;
	}

	memset (&stream, 0, sizeof (z_stream));
	stream.avail_in = srcLen;
	stream.next_in = (Bytef *) src;

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (inflateInit2 (&stream, wbits) != Z_OK) {
		return NULL;
	}

	do {
		if (stream.avail_out == 0) {
			ut8 *tmp_ptr = realloc (dst, stream.total_out + srcLen * 2);
			if (!tmp_ptr) {
				goto err_exit;
			}
			dst = tmp_ptr;
			out_size += srcLen * 2;
			if (out_size > MAXOUT) {
				goto err_exit;
			}
			stream.next_out  = dst + stream.total_out;
			stream.avail_out = srcLen * 2;
		}
		err = inflate (&stream, Z_NO_FLUSH);
		if (err < 0) {
			R_LOG_ERROR ("inflate failed: %d %s", err, gzerr (-err));
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

R_API ut8 *r_inflate_lz4(const ut8 *src, int srcLen, R_NULLABLE int *consumed, int *dstLen) {
	R_RETURN_VAL_IF_FAIL (src && dstLen, NULL);
	ut32 osz = srcLen * 5;
	ut8 *obuf = calloc (srcLen, 5);
	if (!obuf) {
		return NULL;
	}

#if USE_SMALLZ4
	struct UserPtr user = {
		.input = src,
		.inputPos = 0,
		.output = obuf,
		.outputPos = 0,
		.outputSize = &osz,
		.error = 0
	};
	int res = unlz4Block_userPtr (smallz4GetByte, smallz4Write, &user, srcLen, NULL, NULL);
	if (res < 1 || user.error != 0)
#else
	int res = LZ4_decompress_safe ((const char*)src, (char*)obuf, (uint32_t) srcLen, (uint32_t) osz);
	if (res < 1)
#endif
	{
		const int mul = srcLen / -res;
		const int nosz = osz * (5 * (mul + 1));
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
#if USE_SMALLZ4
		user.output = obuf;
		user.inputPos = 0;
		user.outputPos = 0;
		user.error = 0;
		res = unlz4Block_userPtr (smallz4GetByte, smallz4Write, &user, srcLen, NULL, NULL);
	}
	user.output = NULL;
	user.input = NULL;
#else
	}
	res = LZ4_decompress_safe ((const char*)src, (char*)obuf, (uint32_t) srcLen, (uint32_t) osz);
#endif
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

R_API ut8 *r_inflate(const ut8 *src, int srcLen, R_NULLABLE int *consumed, int *dstLen) {
	R_RETURN_VAL_IF_FAIL (src && dstLen, NULL);
	return inflatew (src, srcLen, consumed, dstLen, MAX_WBITS + 32);
}

R_API ut8 *r_inflate_raw(const ut8 *src, int srcLen, R_NULLABLE int *consumed, int *dstLen) {
	R_RETURN_VAL_IF_FAIL (src && dstLen, NULL);
	return inflatew (src, srcLen, consumed, dstLen, -MAX_WBITS);
}
