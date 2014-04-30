#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char * filename;
	int mode;
	int rw;
	int fd;
	int opened;
	ut8 modified;
	RBuffer *buf;
	RIO * io_backref;
} RIOMMapFileObj;

static int r_io_def_mmap_refresh_def_mmap_buf(RIOMMapFileObj *mmo);
static void r_io_def_mmap_free (RIOMMapFileObj *mmo);
static int r_io_def_mmap_close(RIODesc *fd);
static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count);
static int r_io_def_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count);
static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int rw, int mode);
static ut64 r_io_def_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence);
static ut64 r_io_def_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int r_io_def_mmap_truncate(RIOMMapFileObj *mmo, ut64 size);
static int r_io_def_mmap_resize(RIO *io, RIODesc *fd, ut64 size);

static int __plugin_open_default(RIO *io, const char *file, ut8 many);
static RIODesc *__open_default(RIO *io, const char *file, int rw, int mode);
static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len);
static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len);
static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence);
static int __close(RIODesc *fd);
static int __resize(RIO *io, RIODesc *fd, ut64 newsize);


static int r_io_def_mmap_refresh_def_mmap_buf(RIOMMapFileObj *mmo) {
	RIO* io = mmo->io_backref;
	ut64 cur = mmo->buf ? mmo->buf->cur : 0;
	if (mmo->buf) {
		r_buf_free (mmo->buf);
		mmo->buf = NULL;
	}
	mmo->buf = r_buf_mmap (mmo->filename, mmo->rw);
	if (mmo->buf)
		r_io_def_mmap_seek (io, mmo, cur, SEEK_SET);
	return (mmo->buf ? R_TRUE : R_FALSE);
}

RIOMMapFileObj *r_io_def_mmap_create_new_file(RIO  *io, const char *filename, int mode, int rw) {
	RIOMMapFileObj *mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo || !io)
		return NULL;

	mmo->filename = strdup (filename);
	mmo->fd = r_num_rand (0xFFFF); // XXX: Use r_io_fd api
	mmo->mode = mode;
	mmo->rw = rw;
	mmo->io_backref = io;

	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo)) {
		r_io_def_mmap_free (mmo);
		mmo = NULL;
	}
	return mmo;
}

static void r_io_def_mmap_free (RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
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
	char * peekaboo = strstr (filename, "://");
	if ( (filename && !peekaboo) ||
		( (peekaboo-filename) > 10 ) )
		return 1;
	return 0;
}

static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf)
		return -1;
	mmo = fd->data;
	if (mmo->buf->length < io->off)
		io->off = mmo->buf->length;
	return r_buf_read_at (mmo->buf, io->off, buf, count);
}

static int r_io_def_mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOMMapFileObj *mmo;
	int len = -1;
	ut64 addr = io->off;

	if (!(fd->flags & 2) || !fd || !fd->data || !buf) return -1;

	mmo = fd->data;

	if ( (count + addr > mmo->buf->length) || mmo->buf->empty) {
		ut64 sz = count + addr;
		r_file_truncate (mmo->filename, sz);
	}

	len = r_file_mmap_write (mmo->filename, io->off, buf, count);
	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("io_def_mmap: failed to refresh the def_mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int rw, int mode) {
	const char* name = NULL;
	RIOMMapFileObj *mmo;

	name = file;
	mmo = r_io_def_mmap_create_new_file (io, name, mode, rw);

	if (!mmo) return NULL;
	return r_io_desc_new (&r_io_plugin_default, mmo->fd,
				mmo->filename, rw, mode, mmo);
}

static ut64 r_io_def_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
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

static ut64 r_io_def_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOMMapFileObj *mmo;

	if (!fd || !fd->data)
		return -1;

	mmo = fd->data;
	return r_io_def_mmap_seek(io, mmo, offset, whence);
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
	return r_io_def_mmap_truncate(mmo, size);
}

static int __plugin_open_default(RIO *io, const char *file, ut8 many) {
	return r_io_def_mmap_check_default (file);
}

static RIODesc *__open_default(RIO *io, const char *file, int rw, int mode) {
	if (!r_io_def_mmap_check_default (file) ) return NULL;
	return r_io_def_mmap_open (io, file, rw, mode);
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