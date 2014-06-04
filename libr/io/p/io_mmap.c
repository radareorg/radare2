/* radare - LGPL - Copyright 2013-2014 - pancake */

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

static int r_io_mmap_refresh_buf(RIOMMapFileObj *mmo);
static void r_io_mmap_free (RIOMMapFileObj *mmo);
static int r_io_mmap_close(RIODesc *fd);
static int r_io_mmap_check (const char *filname);
static int r_io_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static int r_io_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
static RIODesc *r_io_mmap_open(RIO *io, const char *file, int flags, int mode);
static ut64 r_io_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence);
static ut64 r_io_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int r_io_mmap_truncate(RIOMMapFileObj *mmo, ut64 size);
static int r_io_mmap_resize(RIO *io, RIODesc *fd, ut64 size);
static int __plugin_open(RIO *io, const char *file, ut8 many);
static RIODesc *__open(RIO *io, const char *file, int flags, int mode);
static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len);
static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len);
static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int __close(RIODesc *fd);
static int __resize(RIO *io, RIODesc *fd, ut64 newsize);


static int r_io_mmap_refresh_buf(RIOMMapFileObj *mmo) {
	RIO* io = mmo->io_backref;
	ut64 cur = mmo->buf ? mmo->buf->cur : 0;
	if (mmo->buf) {
		r_buf_free (mmo->buf);
		mmo->buf = NULL;
	}
	mmo->buf = r_buf_mmap (mmo->filename, mmo->flags);
	if (mmo->buf)
		r_io_mmap_seek (io, mmo, cur, SEEK_SET);
	return (mmo->buf ? R_TRUE : R_FALSE);
}

RIOMMapFileObj *r_io_mmap_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	RIOMMapFileObj *mmo = NULL;
	if (!io)
		return NULL;

	mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo)
		return NULL;

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

static void r_io_mmap_free (RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
	memset (mmo, 0, sizeof (RIOMMapFileObj));
	free (mmo);
}

static int r_io_mmap_close(RIODesc *fd) {
	if (!fd || !fd->data)
		return -1;
	r_io_mmap_free ( (RIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static int r_io_mmap_check (const char *filename) {
	if ( filename &&
		!strncmp (filename, "mmap://", 7) &&
		*(filename+7))
		return 1;
	return 0;
}

static int r_io_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf)
		return -1;
	mmo = fd->data;
	if (mmo->buf->length < io->off)
		io->off = mmo->buf->length;
	return r_buf_read_at (mmo->buf, io->off, buf, count);
}

static int r_io_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOMMapFileObj *mmo;
	int len = count;
	ut64 addr = io->off;

	if (!fd || !fd->data || !buf) return -1;

	mmo = fd->data;

	if ( !(mmo->flags & R_IO_WRITE)) return -1;
	if ( (count + addr > mmo->buf->length) || mmo->buf->empty) {
		ut64 sz = count + addr;
		r_file_truncate (mmo->filename, sz);
	}

	len = r_file_mmap_write (mmo->filename, io->off, buf, len);
	if (!r_io_mmap_refresh_buf (mmo) ) {
		eprintf ("io_mmap: failed to refresh the mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *r_io_mmap_open(RIO *io, const char *file, int flags, int mode) {
	const char* name = NULL;
	RIOMMapFileObj *mmo;

	name = !strncmp (file, "mmap://", 7) ? file+7 : file;
	mmo = r_io_mmap_create_new_file (io, name, mode, flags);

	if (!mmo) return NULL;
	return r_io_desc_new (&r_io_plugin_mmap, mmo->fd,
				mmo->filename, flags, mode, mmo);
}

static ut64 r_io_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
	ut64 seek_val = mmo->buf->cur;
	switch (whence) {
	case SEEK_SET:
		seek_val = (mmo->buf->length < offset) ?
			mmo->buf->length : offset;
		mmo->buf->cur = io->off = seek_val;
		return seek_val;
	case SEEK_CUR:
		seek_val = (mmo->buf->length < (offset + mmo->buf->cur)) ?
			mmo->buf->length : offset + mmo->buf->cur;
		mmo->buf->cur = io->off = seek_val;
		return seek_val;
	case SEEK_END:
		seek_val = mmo->buf->length;
		mmo->buf->cur = io->off = seek_val;
		return seek_val;
	}
	return seek_val;
}

static ut64 r_io_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo;

	if (!fd || !fd->data)
		return -1;

	mmo = fd->data;
	return r_io_mmap_seek(io, mmo, offset, whence);
}

static int r_io_mmap_truncate(RIOMMapFileObj *mmo, ut64 size) {
	int res = r_file_truncate (mmo->filename, size);

	if (res && !r_io_mmap_refresh_buf (mmo) ) {
		eprintf ("r_io_mmap_truncate: Error trying to refresh the mmap'ed file.");
		res = R_FALSE;
	}
	else if (res) eprintf ("r_io_mmap_truncate: Error trying to resize the file.");
	return res;
}

static int r_io_mmap_resize(RIO *io, RIODesc *fd, ut64 size) {
	RIOMMapFileObj *mmo;
	if (!fd || !fd->data)
		return -1;

	mmo = fd->data;
	return r_io_mmap_truncate(mmo, size);
}


static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return r_io_mmap_check (file);
}

static RIODesc *__open(RIO *io, const char *file, int flags, int mode) {
	if (!r_io_mmap_check (file) ) return NULL;
	return r_io_mmap_open (io, file, flags, mode);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_mmap_read (io, fd, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return r_io_mmap_write(io, fd, buf, len);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return r_io_mmap_lseek (io, fd, offset, whence);
}

static int __close(RIODesc *fd) {
	return r_io_mmap_close (fd);
}

static int __resize(RIO *io, RIODesc *fd, ut64 size) {
	return r_io_mmap_resize (io, fd, size);
}

struct r_io_plugin_t r_io_plugin_mmap = {
	.name = "mmap",
	.desc = "open file using mmap://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_mmap
};
#endif
