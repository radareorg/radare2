/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_io.h>

int main(int argc, char **argv)
{
	char buf[4096];
	int fd;
	struct r_io_t io;

	r_io_init(&io);

	fd = r_io_open(&io, argc>1?argv[1]:"/etc/issue", R_IO_READ, 0);
	memset(buf, '\0', 4096);
//r_io_set_fd(&io, fd);
	r_io_read (&io, (ut8*)buf, sizeof (buf));

	puts(buf);

	return r_io_close(&io, fd);
}
