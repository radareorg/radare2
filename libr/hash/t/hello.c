#include <stdio.h>
#include <stdlib.h>
#include "r_io.h"
#include "r_hash.h"

int main(int argc, char **argv) {
	RIODesc *fd;
	ut8 *buf;
	ut64 size;
	struct r_io_t *io;

	if (argc<2) {
		printf("Usage: %s [file]\n", argv[0]);
		return 1;
	}

	io = r_io_new();

	fd = r_io_open_nomap (io, argv[1], R_IO_READ, 0);
	if (fd == NULL) {
		eprintf ("Cannot open file\n");
		return 1;
	}

	/* get file size */
	size = r_io_size (io);

	/* read bytes */
	buf = (ut8*) malloc (size);
	if (buf == NULL) {
		printf ("Big too file\n");
		r_io_close (io, fd);
		r_io_free (io);
		return 1;
	}

	memset (buf, 0, size);
	r_io_read (io, buf, size);
	printf ("----\n%s\n----\n", buf);

	printf ("file size = %"PFMT64d"\n", size);
	printf ("CRC32: 0x%08x\n", r_hash_crc32(buf, size));

	{
		struct r_hash_t *ctx;
		const ut8 *c;
		int i;
		//r_hash_init(&ctx, R_TRUE, R_HASH_ALL);
		ctx = r_hash_new (R_TRUE, R_HASH_ALL);
		c = r_hash_do_md5 (ctx, buf, size);
		printf ("MD5: ");
		for (i=0;i<R_HASH_SIZE_MD5;i++) { printf("%02x", c[i]); }
		printf ("\n");

		c = r_hash_do_sha1 (ctx, buf, size);
		printf ("SHA1: ");
		for (i=0;i<R_HASH_SIZE_SHA1;i++) { printf("%02x", c[i]); }
		printf ("\n");

		c = r_hash_do_sha256 (ctx, buf, size);
		printf ("SHA256: ");
		for (i=0;i<R_HASH_SIZE_SHA256;i++) { printf("%02x", c[i]); }
		printf ("\n");
		r_hash_free (ctx);
	}

	r_io_close(io, fd);
	r_io_free (io);
	free (buf);
	return 0;
}
