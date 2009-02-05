#include <r_io.h>

int main(int argc, char **argv)
{
	char buf[4];
	int fd;
	struct r_io_t io;

	r_io_init(&io);

	fd = r_io_open(&io, argc>1?argv[1]:"/etc/issue", R_IO_READ, 0);
	r_io_lseek(&io, fd, 1, R_IO_SEEK_SET);
	memset(buf, '\0', 4);
	r_io_read(&io, fd, buf, 4);
	buf[4]='\0';

	puts(buf);

	return r_io_close(&io, fd);
}
