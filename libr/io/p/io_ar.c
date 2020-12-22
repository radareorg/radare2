/* radare - LGPLv3- Copyright 2017 - xarkes */
#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_cons.h>
#include "ar.h"


static bool r_io_ar_plugin_open(RIO *io, const char *file, bool many) {
	return !strncmp ("ar://", file, 5) || !strncmp ("lib://", file, 6);
}

static RIODesc *r_io_ar_open(RIO *io, const char *file, int rw, int mode) {
	RIODesc *res = NULL;
	char *url = strdup (file);
	char *arname = strstr (url, "://") + 3;
	char *filename = strstr (arname, "//");
	if (filename) {
		*filename = 0;
		filename += 2;
	}

	RBuffer *b = ar_open_file (arname, filename);
	if (b) {
		res = r_io_desc_new (io, &r_io_plugin_ar, filename, rw, mode, b);
	}
	free (url);
	return res;
}

static RList *r_io_ar_open_many(RIO *io, const char *file, int rw, int mode) {
	eprintf ("Not implemented\n");
	return NULL;
}

static ut64 r_io_ar_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RBuffer *b;
	ut64 seek_val = 0;

	if (!fd || !fd->data) {
		return -1;
	}

	b = fd->data;
	seek_val = r_buf_tell (b);

	switch (whence) {
	case SEEK_SET:
		seek_val = (r_buf_size (b) < offset)? r_buf_size (b) : offset;
		io->off = seek_val;
		r_buf_seek (b, seek_val, R_BUF_SET);
		return seek_val;
	case SEEK_CUR:
		seek_val = (r_buf_size (b) < offset)? r_buf_size (b) : offset;
		io->off = seek_val;
		r_buf_seek (b, seek_val, R_BUF_SET);
		return seek_val;
	case SEEK_END:
		seek_val = r_buf_size (b);
		io->off = seek_val;
		r_buf_seek (b, seek_val, R_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static int r_io_ar_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RBuffer *b;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	b = fd->data;
	return ar_read_at (b, io->off, buf, count);
}

static int r_io_ar_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RBuffer *b = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	return ar_write_at (b, io->off, (void *) buf, count);
}

static int r_io_ar_close(RIODesc *fd) {
	RBuffer *b = NULL;
	if (!fd || !fd->data) {
		return -1;
	}
	b = fd->data;
	return ar_close (b);
}

RIOPlugin r_io_plugin_ar = {
	.name = "ar",
	.desc = "Open ar/lib files",
	.license = "LGPL3",
	.uris = "ar://,lib://",
	.open = r_io_ar_open,
	.open_many = r_io_ar_open_many,
	.write = r_io_ar_write,
	.read = r_io_ar_read,
	.close = r_io_ar_close,
	.lseek = r_io_ar_lseek,
	.check = r_io_ar_plugin_open
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ar,
	.version = R2_VERSION
};
#endif
