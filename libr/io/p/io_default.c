/* radare - LGPL - Copyright 2008-2014 - pancake */

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
	int rawio;
} RIOMMapFileObj;

static int r_io_def_mmap_refresh_def_mmap_buf(RIOMMapFileObj *mmo);
static void r_io_def_mmap_free (RIOMMapFileObj *mmo);
static int r_io_def_mmap_close(RIODesc *fd);
static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static int r_io_def_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int flags, int mode);
static ut64 r_io_def_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence);
static ut64 r_io_def_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int r_io_def_mmap_truncate(RIOMMapFileObj *mmo, ut64 size);
static int r_io_def_mmap_resize(RIO *io, RIODesc *fd, ut64 size);

static int __plugin_open_default(RIO *io, const char *file, ut8 many);
static RIODesc *__open_default(RIO *io, const char *file, int flags, int mode);
static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len);
static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len);
static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int __close(RIODesc *fd);
static int __resize(RIO *io, RIODesc *fd, ut64 newsize);

static int __io_posix_open (const char *file, int flags, int mode) {
	int fd;
	if (r_file_is_directory (file))
		return -1;
#if __WINDOWS__
	if (flags & R_IO_WRITE) {
		fd = r_sandbox_open (file, O_BINARY | O_RDWR, 0);
		if (fd == -1) {
			r_sandbox_creat (file, 0644);
			fd = r_sandbox_open (file, O_BINARY | O_RDWR, 0);
		}
	} else fd = r_sandbox_open (file, O_BINARY, 0);
#else
	fd = r_sandbox_open (file, (flags&R_IO_WRITE)?
			(O_RDWR|O_CREAT): O_RDONLY, mode);
#endif
	return fd;
}

static int r_io_def_mmap_refresh_def_mmap_buf(RIOMMapFileObj *mmo) {
	RIO* io = mmo->io_backref;
	ut64 cur;
	if (mmo->buf) {
		cur = mmo->buf->cur;
		r_buf_free (mmo->buf);
		mmo->buf = NULL;
	} else {
		cur = 0;
	}
	if (r_file_size (mmo->filename) > ST32_MAX) {
		// Do not use mmap if the file is huge
		mmo->rawio = 1;
	}
	if (mmo->rawio) {
		mmo->fd = __io_posix_open (mmo->filename, mmo->flags, mmo->mode);
		return (mmo->fd != -1);
	}
	mmo->buf = r_buf_mmap (mmo->filename, mmo->flags);
	if (mmo->buf) {
		r_io_def_mmap_seek (io, mmo, cur, SEEK_SET);
		return R_TRUE;
	} else {
		mmo->rawio = 1;
		mmo->fd = __io_posix_open (mmo->filename, mmo->flags, mmo->mode);
		return (mmo->fd != -1);
	}
	return R_FALSE;
}

RIOMMapFileObj *r_io_def_mmap_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	RIOMMapFileObj *mmo = NULL;
	if (!io)
		return NULL;

	mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo)
		return NULL;

	mmo->filename = strdup (filename);
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	if (flags & R_IO_WRITE)
		mmo->fd = r_sandbox_open (filename, O_CREAT|O_RDWR, mode);
	else mmo->fd = r_sandbox_open (filename, O_RDONLY, mode);

	if (mmo->fd == -1)
		return NULL;

	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo)) {
		mmo->rawio = 1;
		if (!r_io_def_mmap_refresh_def_mmap_buf (mmo)) {
			r_io_def_mmap_free (mmo);
			mmo = NULL;
		}
	}
	return mmo;
}

static void r_io_def_mmap_free (RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
	close (mmo->fd);
	memset (mmo, 0, sizeof (RIOMMapFileObj));
	free (mmo);
}

static int r_io_def_mmap_close(RIODesc *fd) {
	if (!fd || !fd->data)
		return -1;
	r_io_def_mmap_free ( (RIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static int r_io_def_mmap_check_default (const char *filename) {
	if (filename) {
		const char * peekaboo = strstr (filename, "://");
		if (!peekaboo || (peekaboo-filename) > 10 )
			return 1;
	}
	return 0;
}

static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf) {
		// in this case we fallback reopening in raw mode
		return -1;
	}
	if (io->off==UT64_MAX) {
		memset (buf, 0xff, count);
		return count;
	}
	mmo = fd->data;
	if (mmo->rawio) {
		return read (mmo->fd, buf, count);
	}
	if (mmo->buf->length < io->off)
		io->off = mmo->buf->length;
	return r_buf_read_at (mmo->buf, io->off, buf, count);
}

static int r_io_def_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOMMapFileObj *mmo;
	int len = -1;
	ut64 addr = io->off;

	if (!fd || !fd->data || !buf) return -1;

	mmo = fd->data;

	if (mmo && mmo->buf) {
		if (!(mmo->flags & R_IO_WRITE)) return -1;
		if ( (count + addr > mmo->buf->length) || mmo->buf->empty) {
			ut64 sz = count + addr;
			r_file_truncate (mmo->filename, sz);
		}
	}

	len = r_file_mmap_write (mmo->filename, io->off, buf, count);
	if (len != count) {
		// aim to hack some corner cases?
		if (lseek (fd->fd, addr, 0) < 0)
			return -1;
		len = write (fd->fd, buf, count);
	}
	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("io_def_mmap: failed to refresh the def_mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int flags, int mode) {
	RIOMMapFileObj *mmo = r_io_def_mmap_create_new_file (
		io, file, mode, flags);
	if (!mmo) return NULL;
	return r_io_desc_new (&r_io_plugin_default, mmo->fd,
				mmo->filename, flags, mode, mmo);
}

static ut64 r_io_def_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
	ut64 seek_val = UT64_MAX;

	if (!mmo) return UT64_MAX;
	if (mmo->rawio)
		return lseek (mmo->fd, offset, whence);
	if (!mmo->buf) return UT64_MAX;

	seek_val = mmo->buf->cur;
	switch (whence) {
		case SEEK_SET:
			seek_val = (mmo->buf->length < offset) ?
				mmo->buf->length : offset;
			break;
		case SEEK_CUR:
			seek_val = (mmo->buf->length < (offset + mmo->buf->cur)) ?
				mmo->buf->length : offset + mmo->buf->cur;
			break;
		case SEEK_END:
			seek_val = mmo->buf->length;
			break;
	}
	mmo->buf->cur = io->off = seek_val;
	return seek_val;
}

static ut64 r_io_def_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	if (!fd || !fd->data)
		return -1;
	return r_io_def_mmap_seek (io, (RIOMMapFileObj *)fd->data, offset, whence);
}

static int r_io_def_mmap_truncate(RIOMMapFileObj *mmo, ut64 size) {
	int res = r_file_truncate (mmo->filename, size);

	if (res && !r_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("r_io_def_mmap_truncate: Error trying to refresh the def_mmap'ed file.");
		res = R_FALSE;
	}
	else if (!res) eprintf ("r_io_def_mmap_truncate: Error trying to resize the file.");
	return res;
}

static int r_io_def_mmap_resize(RIO *io, RIODesc *fd, ut64 size) {
	RIOMMapFileObj *mmo;
	if (!fd || !fd->data)
		return -1;
	mmo = fd->data;
	if (!(mmo->flags & R_IO_WRITE)) return -1;
	return r_io_def_mmap_truncate (mmo, size);
}

static int __plugin_open_default(RIO *io, const char *file, ut8 many) {
	return r_io_def_mmap_check_default (file);
}

// default open should permit opening 
static RIODesc *__open_default(RIO *io, const char *file, int flags, int mode) {
	RIODesc *iod;
	if (!r_io_def_mmap_check_default (file) ) return NULL;
	iod = r_io_def_mmap_open (io, file, flags, mode);
	return iod;
// NTOE: uncomment this line to support loading files in ro as fallback is rw fails
//	return iod? iod: r_io_def_mmap_open (io, file, R_IO_READ, mode);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_def_mmap_read (io, fd, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return r_io_def_mmap_write(io, fd, buf, len);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return r_io_def_mmap_lseek (io, fd, offset, whence);
}

static int __close(RIODesc *fd) {
	return r_io_def_mmap_close (fd);
}

static int __resize(RIO *io, RIODesc *fd, ut64 size) {
	return r_io_def_mmap_resize (io, fd, size);
}

struct r_io_plugin_t r_io_plugin_default = {
	.name = "default",
	.desc = "open local files using def_mmap://",
	.license = "LGPL3",
	.open = __open_default,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open_default,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_default
};
#endif
