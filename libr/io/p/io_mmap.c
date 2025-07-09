/* radare - LGPL - Copyright 2013-2024 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char * filename;
	int mode;
	int flags;
	int fd;
	int opened;
	ut8 modified;
	RBuffer *buf;
	RIO * io_backref;
} RIOMMapFileObj;

static ut64 r_io_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
	ut64 seek_val = r_buf_tell (mmo->buf);
	switch (whence) {
	case R_IO_SEEK_SET:
		seek_val = (r_buf_size (mmo->buf) < offset)? r_buf_size (mmo->buf): offset;
		r_buf_seek (mmo->buf, io->off = seek_val, R_BUF_SET);
		return seek_val;
	case R_IO_SEEK_CUR:
		seek_val = (r_buf_size (mmo->buf) < (offset + r_buf_tell (mmo->buf)))? r_buf_size (mmo->buf):
			offset + r_buf_tell (mmo->buf);
		r_buf_seek (mmo->buf, io->off = seek_val, R_BUF_SET);
		return seek_val;
	case R_IO_SEEK_END:
		seek_val = r_buf_size (mmo->buf);
		r_buf_seek (mmo->buf, io->off = seek_val, R_BUF_SET);
		return seek_val;
	}
	return seek_val;
}

static bool r_io_mmap_refresh_buf(RIOMMapFileObj *mmo) {
	RIO* io = mmo->io_backref;
	ut64 cur = mmo->buf? r_buf_tell (mmo->buf): 0;
	if (mmo->buf) {
		r_buf_free (mmo->buf);
		mmo->buf = NULL;
	}
	mmo->buf = r_buf_new_mmap (mmo->filename, mmo->flags);
	if (mmo->buf) {
		r_io_mmap_seek (io, mmo, cur, SEEK_SET);
	}
	return mmo->buf;
}

static void r_io_mmap_free(RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
	memset (mmo, 0, sizeof (RIOMMapFileObj));
	free (mmo);
}

RIOMMapFileObj *r_io_mmap_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	R_RETURN_VAL_IF_FAIL (io && filename, NULL);
	RIOMMapFileObj *mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	mmo->filename = strdup (filename);
	mmo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	if (!r_io_mmap_refresh_buf (mmo)) {
		r_io_mmap_free (mmo);
		mmo = NULL;
	}
	return mmo;
}

static bool r_io_mmap_check(const char *filename) {
	return (filename && r_str_startswith (filename, "mmap://") && filename[7]);
}

static int r_io_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf) {
		return -1;
	}
	mmo = fd->data;
	if (r_buf_size (mmo->buf) < io->off) {
		io->off = r_buf_size (mmo->buf);
	}
	int r = r_buf_read_at (mmo->buf, io->off, buf, count);
	if (r >= 0) {
		r_buf_seek (mmo->buf, r, R_BUF_CUR);
	}
	return r;
}

static int r_io_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOMMapFileObj *mmo;
	int len = count;
	ut64 addr;

	if (!io || !fd || !fd->data || !buf) {
		return -1;
	}
	mmo = fd->data;
	addr = io->off;
	if (!(mmo->flags & R_PERM_W)) {
		return -1;
	}
	if ((count + addr > r_buf_size (mmo->buf)) || r_buf_size (mmo->buf) == 0) {
		ut64 sz = count + addr;
		r_file_truncate (mmo->filename, sz);
	}
	len = r_file_mmap_write (mmo->filename, io->off, buf, len);
	if (!r_io_mmap_refresh_buf (mmo) ) {
		R_LOG_ERROR ("failed to refresh the mmap backed buffer");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *r_io_mmap_open(RIO *io, const char *file, int flags, int mode) {
	if (r_str_startswith (file, "mmap://")) {
		file += strlen ("mmap://");
	}
	RIOMMapFileObj *mmo = r_io_mmap_create_new_file (io, file, mode, flags);
	return mmo? r_io_desc_new (io, &r_io_plugin_mmap, mmo->filename, flags, mode, mmo): NULL;
}

static ut64 r_io_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data) {
		return -1;
	}
	RIOMMapFileObj *mmo = fd->data;
	return r_io_mmap_seek (io, mmo, offset, whence);
}

static bool r_io_mmap_truncate(RIOMMapFileObj *mmo, ut64 size) {
	int res = r_file_truncate (mmo->filename, size);
	if (res && !r_io_mmap_refresh_buf (mmo)) {
		R_LOG_ERROR ("Cannot refresh the mmap'ed file");
		res = false;
	} else if (res) {
		R_LOG_ERROR ("r_io_mmap_truncate: Cannot resize the file");
	}
	return res;
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_io_mmap_check (file);
}

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
	if (!r_io_mmap_check (file)) {
		return NULL;
	}
	return r_io_mmap_open (io, file, flags, mode);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_mmap_read (io, fd, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return r_io_mmap_write (io, fd, buf, len);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return r_io_mmap_lseek (io, fd, offset, whence);
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	r_io_mmap_free ((RIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return true;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	if (!fd || !fd->data) {
		return false;
	}
	return r_io_mmap_truncate ((RIOMMapFileObj*)fd->data, size);
}

RIOPlugin r_io_plugin_mmap = {
	.meta = {
		.name = "mmap",
		.author = "pancake",
		.desc = "Open files using mmap",
		.license = "LGPL-3.0-only",
	},
	.uris = "mmap://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mmap,
	.version = R2_VERSION
};
#endif
