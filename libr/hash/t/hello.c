#include <stdio.h>
#include <stdlib.h>
#include "r_io.h"
#include "r_hash.h"

int main(int argc, char **argv)
{
	int fd;
	u8 *buf;
	u64 size;
	struct r_io_t io;

	if (argc<2) {
		printf("Usage: %s [file]\n", argv[0]);
		return 1;
	}

	r_io_init(&io);

	fd = r_io_open(&io, argv[1], R_IO_READ, 0);
	if (fd == -1) {
		printf("Cannot open file\n");
		return 1;
	}

	/* get file size */
	r_io_lseek(&io, fd, 0, R_IO_SEEK_END);
	size = r_io_lseek(&io, fd, 0, R_IO_SEEK_END);
	r_io_lseek(&io, fd, 0, R_IO_SEEK_SET);

	/* read bytes */
	buf = (u8*) malloc(size);
	if (buf == NULL) {
		printf("Too big file\n");
		return 1;
		r_io_close(&io, fd);
	}

	r_io_read(&io, fd, buf, size);
	printf("----\n%s\n----\n", buf);

	printf("file size = %lld\n", size);
	printf("CRC32: 0x%08x\n", r_hash_crc32(buf, size));

	{
		struct r_hash_t ctx;
		const u8 *c;
		int i;
		r_hash_state_init(&ctx, R_HASH_ALL);
		c = r_hash_state_md5(&ctx, buf, size);
		printf("MD5: ");
		for(i=0;i<R_HASH_SIZE_MD5;i++) { printf("%02x", c[i]); }
		printf("\n");

		c = r_hash_state_sha1(&ctx, buf, size);
		printf("SHA1: ");
		for(i=0;i<R_HASH_SIZE_SHA1;i++) { printf("%02x", c[i]); }
		printf("\n");

		c = r_hash_state_sha256(&ctx, buf, size);
		printf("SHA256: ");
		for(i=0;i<R_HASH_SIZE_SHA256;i++) { printf("%02x", c[i]); }
		printf("\n");
	}

	r_io_close(&io, fd);
	free (buf);
	return 0;
}
