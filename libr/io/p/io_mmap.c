/* radare - LGPL - Copyright 2013 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

static int __plugin_open(RIO *io, const char *file) {
	return (!memcmp (file, "mmap://", 7));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (r_file_mmap_read (file+7, 0, NULL, 0)==0)
		return r_io_desc_new (&r_io_plugin_mmap,
			-1, file+7, rw, mode, NULL);
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
        return r_file_mmap_read (fd->name, io->off, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	if (fd->flags & 2)
        	return r_file_mmap_write (fd->name, io->off, buf, len);
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return r_file_size (fd->name);
	}
	return offset;
}

static int __close(RIODesc *fd) {
	return 0;
}

struct r_io_plugin_t r_io_plugin_mmap = {
	.name = "mmap",
        .desc = "open file using mmap://",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mach
};
#endif
