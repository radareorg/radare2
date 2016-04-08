/*
 * Copyright (c) 2009, 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * gzip_wrapper.c
 */

#include <stdlib.h>
#include <zlib.h>

#include "squashfs_fs.h"
#include "compressor.h"

static int gzip_init(void **strm, int block_size, int flags)
{
	int res;
	z_stream *stream;

	stream = *strm = malloc(sizeof(z_stream));
	if(stream == NULL)
		goto failed;

	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = 0;

	res = deflateInit(stream, 9);
	if(res != Z_OK)
		goto failed2;

	return 0;

failed2:
	free(stream);
failed:
	return -1;
}


static int gzip_compress(void *strm, void *d, void *s, int size, int block_size,
		int *error)
{
	int res;
	z_stream *stream = strm;

	res = deflateReset(stream);
	if(res != Z_OK)
		goto failed;

	stream->next_in = s;
	stream->avail_in = size;
	stream->next_out = d;
	stream->avail_out = block_size;

	res = deflate(stream, Z_FINISH);
	if(res == Z_STREAM_END)
		/*
		 * Success, return the compressed size.
		 */
		return (int) stream->total_out;
	if(res == Z_OK)
		/*
		 * Output buffer overflow.  Return out of buffer space
		 */
		return 0;
failed:
	/*
	 * All other errors return failure, with the compressor
	 * specific error code in *error
	 */
	*error = res;
	return -1;
}


static int gzip_uncompress(void *d, void *s, int size, int block_size, int *error)
{
	int res;
	unsigned long bytes = block_size;

	res = uncompress(d, &bytes, s, size);

	*error = res;
	return res == Z_OK ? (int) bytes : -1;
}


struct compressor gzip_comp_ops = {
	.init = gzip_init,
	.compress = gzip_compress,
	.uncompress = gzip_uncompress,
	.options = NULL,
	.usage = NULL,
	.id = ZLIB_COMPRESSION,
	.name = "gzip",
	.supported = 1
};

