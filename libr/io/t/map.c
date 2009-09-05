#include <r_io.h>

int main () {
	char buf[1024];
	struct r_io_t *io = r_io_new();
	int fd = r_io_open(io, "/bin/ls", R_IO_READ, 0);
	r_io_map_add(io, fd, R_IO_READ, 0, 0xf00000, 0xffff);

	r_io_read_at(&io, 0xf00000, buf, 1024);
	r_io_free(io);
}
