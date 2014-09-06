/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <r_io.h>

int main () {
	int ret;
	RIODesc *fd;
	char buf[1024];
	struct r_io_t *io;

	io = r_io_new();

	r_io_plugin_list(io);
	//fd = r_io_open(io, "/bin/ls", R_IO_READ, 0);
	fd = r_io_open_nomap(io, "dbg:///bin/ls", R_IO_READ, 0);
	r_io_set_fd(io, fd);

	//r_io_map_add(io, fd, R_IO_READ, 0, 0xf00000, 0xffff);
	r_io_map_add(io, fd->fd, R_IO_READ, 0x8048000, 0, 0xffff);

	memset(buf, 0, 1024);
	//ret = r_io_read_at(io, 0xf00000, buf, 1024);
//	ret = r_io_seek(io, 0x8048000, R_IO_SEEK_SET);
//	printf("seek = 0x%"PFMT64x"\n", ret);
	ret = r_io_read_at (io, 0, (ut8*)buf, 64);
	//ret = r_io_read_at(io, 0x8048000, buf, 64);
	printf("%d = %02x %02x %02x %02x\n", ret, buf[0], buf[1], buf[2], buf[3]);
	r_io_free(io);

	return 0;
}
