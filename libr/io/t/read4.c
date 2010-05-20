#include <r_io.h>

int main(int argc, char **argv)
{
	struct r_io_t *io;
	char buf[1024], *file;
	int fd, ret;

	io = r_io_new();
	if (io == NULL)
		return 1;
	file = argc>1?argv[1]:"/bin/ls";
	fd = r_io_open(io, file, R_IO_READ, 0);
	if (fd == -1) {
		printf("Cannot open file '%s'\n", file);
		r_io_free (io);
		return 1;
	}
	printf("FD = %d\n", fd);
	r_io_seek(io, 1, R_IO_SEEK_SET);
	memset(buf, '\0', sizeof(buf));
	r_io_read (io, (ut8 *)buf, 4);
	buf[4]='\0';
	printf("%"PFMT64x"\n", r_io_read_i(io, 0LL, 4, 0));
	puts(buf);
	ret =  r_io_close(io, fd);
	r_io_free (io);

	return ret;
}
