/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_io.h>

int main(int argc, char **argv) {
	struct r_io_t *io;
	char buf[4096];
	int ret;
	RIODesc *fd;

	io = r_io_new();
	if (io == NULL)
		return 1;
	fd = r_io_open_nomap(io, argc>1?argv[1]:"/etc/issue", R_IO_READ, 0);
	memset(buf, '\0', 4096);
//r_io_set_fd(&io, fd);
	r_io_read (io, (ut8*)buf, sizeof (buf));
	puts(buf);
	ret = r_io_close(io, fd);
	r_io_free (io);
	
	return ret;
}
