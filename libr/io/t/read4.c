#include <r_io.h>

int main(int argc, char **argv)
{
	char buf[1024];
	int fd;
	struct r_io_t io;

	r_io_init(&io);

	fd = r_io_open(&io, argc>1?argv[1]:"/bin/ls", R_IO_READ, 0);
	printf("FD = %d\n", fd);
	r_io_lseek(&io, 1, R_IO_SEEK_SET);
	memset(buf, '\0', sizeof(buf));
	r_io_read(&io, buf, 4);
	buf[4]='\0';
	printf("%llx\n", r_io_read_i(&io, 0LL, 4, 0));

	puts(buf);

	return r_io_close(&io, fd);
}
