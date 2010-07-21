/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#include "../../debug/p/libgdbwrap/gdbwrapper.c"
#include "../../debug/p/libgdbwrap/interface.c"

// XXX: is str2bin ok? do reads match reality?
// XXX: This is an ugly singleton!!1
static gdbwrap_t *desc = NULL;
static int _fd = -1;


static int __plugin_open(RIO *io, const char *file) {
	if (!memcmp (file, "gdb://", 6))
		return R_TRUE;
	return R_FALSE;
}

static int __open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file)) {
		char *host = strdup (file+6);
		char *port = strchr (host , ':');
		_fd = -1;
		if (port) {
			*port = '\0';
			_fd = r_socket_connect (host, atoi (port+1));
			if (_fd != -1) desc = gdbwrap_init (_fd);
			else eprintf ("Cannot connect to host.\n");
			//return gdbwrapper ...();
		} else eprintf ("Port not specified. Please use gdb://[host]:[port]\n");
		free (host);
		return _fd;
	}
	return -1;
}

static int __init(RIO *io) {
	return R_TRUE;
}

static int __write(RIO *io, int fd, const ut8 *buf, int count) {
	gdbwrap_writemem (desc, io->off, (void *)buf, count);
	return count;
}

static ut64 __lseek(RIO *io, int fildes, ut64 offset, int whence) {
        return offset;
}

static int __read(RIO *io, int fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	if (fd == _fd) {
		char *ptr = gdbwrap_readmem (desc, (la32)io->off, count);
		if (ptr == NULL)
			return -1;
		//eprintf ("READ %llx (%s)\n", (ut64)io->off, ptr);
		return r_hex_str2bin (ptr, buf);
	}
	return -1;
}

static int __close(RIO *io, int fd) {
	return -1;
}

struct r_io_plugin_t r_io_plugin_gdb = {
        //void *plugin;
	.name = "gdb",
        .desc = "Attach to a running 'gdbserver', 'qemu -s' or other, gdb://localhost:1234", 
        .open = __open,
        .close = __close,
	.read = __read,
	.write = __write,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.system = NULL,
	.debug = (void *)1,
	.init = __init,
        //void *widget;
/*
        struct gdb_t *gdb;
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};
