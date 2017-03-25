/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char * filename;
	int mode;
	int flags;
	int fd;
	int opened;
	bool nocache;
	ut8 modified;
	RBuffer *buf;
	RIO * io_backref;
	int rawio;
} RIOMMapFileObj;

static int __io_posix_open (const char *file, int flags, int mode) {
	int fd;
	if (r_file_is_directory (file)) {
		return -1;
	}
#if __WINDOWS__
	if (flags & R_IO_WRITE) {
		fd = r_sandbox_open (file, O_BINARY | O_RDWR, 0);
		if (fd == -1) {
			r_sandbox_creat (file, 0644);
			fd = r_sandbox_open (file, O_BINARY | O_RDWR, 0);
		}
	} else {
		fd = r_sandbox_open (file, O_BINARY, 0);
	}
#else
	fd = r_sandbox_open (file, (flags & R_IO_WRITE)
		? (O_RDWR|O_CREAT): O_RDONLY, mode);
#endif
	return fd;
}

static ut64 r_io_def_mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
	ut64 seek_val = UT64_MAX;

	if (!mmo) return UT64_MAX;
	if (mmo->rawio) return lseek (mmo->fd, offset, whence);
	if (!mmo->buf) return UT64_MAX;

	seek_val = mmo->buf->cur;
	switch (whence) {
	case SEEK_SET:
		seek_val = R_MIN (mmo->buf->length, offset);
		break;
	case SEEK_CUR:
		seek_val = R_MIN (mmo->buf->length, (offset + mmo->buf->cur));
		break;
	case SEEK_END:
		seek_val = mmo->buf->length;
		break;
	}
	mmo->buf->cur = io->off = seek_val;
	return seek_val;
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
	st64 sz = r_file_size (mmo->filename);
	if (sz == 0 || sz > ST32_MAX) {
		// Do not use mmap if the file is huge
		mmo->rawio = 1;
	}
	if (mmo->rawio) {
		mmo->fd = __io_posix_open (mmo->filename, mmo->flags, mmo->mode);
		if (mmo->nocache) {
#ifdef F_NOCACHE
			fcntl (mmo->fd, F_NOCACHE, 1);
#endif
		}
		return (mmo->fd != -1);
	}
	mmo->buf = r_buf_mmap (mmo->filename, mmo->flags);
	if (mmo->buf) {
		r_io_def_mmap_seek (io, mmo, cur, SEEK_SET);
		return true;
	} else {
		mmo->rawio = 1;
		mmo->fd = __io_posix_open (mmo->filename, mmo->flags, mmo->mode);
		if (mmo->nocache) {
#ifdef F_NOCACHE
			fcntl (mmo->fd, F_NOCACHE, 1);
#endif
		}
		return (mmo->fd != -1);
	}
	return false;
}

static void r_io_def_mmap_free (RIOMMapFileObj *mmo) {
	free (mmo->filename);
	r_buf_free (mmo->buf);
	close (mmo->fd);
	memset (mmo, 0, sizeof (RIOMMapFileObj));
	free (mmo);
}

RIOMMapFileObj *r_io_def_mmap_create_new_file(RIO  *io, const char *filename, int mode, int flags) {
	RIOMMapFileObj *mmo = NULL;
	if (!io)
		return NULL;

	mmo = R_NEW0 (RIOMMapFileObj);
	if (!mmo) {
		return NULL;
	}
	mmo->nocache = !strncmp (filename, "nocache://", 10);
	if (mmo->nocache) {
		filename += 10;
	}
	mmo->filename = strdup (filename);
	mmo->mode = mode;
	mmo->flags = flags;
	mmo->io_backref = io;
	if (flags & R_IO_WRITE)
		mmo->fd = r_sandbox_open (filename, O_CREAT|O_RDWR, mode);
	else mmo->fd = r_sandbox_open (filename, O_RDONLY, mode);

	if (mmo->fd == -1) {
		free (mmo->filename);
		free (mmo);
		return NULL;
	}
	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo)) {
		mmo->rawio = 1;
		if (!r_io_def_mmap_refresh_def_mmap_buf (mmo)) {
			r_io_def_mmap_free (mmo);
			mmo = NULL;
		}
	}
	return mmo;
}

static int r_io_def_mmap_close(RIODesc *fd) {
	if (!fd || !fd->data) return -1;
	r_io_def_mmap_free ((RIOMMapFileObj *) fd->data);
	fd->data = NULL;
	return 0;
}

static bool r_io_def_mmap_check_default (const char *filename) {
	if (filename) {
		const char * peekaboo = (!strncmp (filename, "nocache://", 10))
			? NULL : strstr (filename, "://");
		if (!peekaboo || (peekaboo-filename) > 10) {
			return true;
		}
	}
	return false;
}

static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOMMapFileObj *mmo = NULL;
	if (!fd || !fd->data || !buf) {
		// in this case we fallback reopening in raw mode
		return -1;
	}
	if (io->off == UT64_MAX) {
		memset (buf, 0xff, count);
		return count;
	}
	mmo = fd->data;
	if (!mmo)
		return -1;
	if (mmo->rawio) {
		if (fd->obsz) {
			char *a_buf;
			ssize_t a_count;
			// only do aligned reads in aligned offsets
			const int aligned = fd->obsz; //512; // XXX obey fd->obsz? or it may be too slow? 128K..
			//ut64 a_off = (io->off >> 9 ) << 9; //- (io->off & aligned);
			ut64 a_off = io->off - (io->off % aligned); //(io->off >> 9 ) << 9; //- (io->off & aligned);
			int a_delta = io->off - a_off;
			if (a_delta<0) {
				memset (buf, 0xff, count);
				return -1;
			}
			a_count = count + (aligned-(count%aligned));

			a_buf = malloc (a_count+aligned);
			if (a_buf) {
				int i;
				memset (a_buf, 0xff, a_count+aligned);
				if (lseek (mmo->fd, a_off, SEEK_SET) < 0) {
					free (a_buf);
					return -1;
				}
				for (i=0; i< a_count ; i+= aligned) {
					(void)read (mmo->fd, a_buf+i, aligned);//a_count);
				}
				memcpy (buf, a_buf+a_delta, count);
			} else {
				memset (buf, 0xff, count);
			}
			free (a_buf);
			return count;
		}
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
	if (!mmo)
		return -1;
	if (mmo->rawio) {
		if (fd->obsz) {
			char *a_buf;
			ssize_t a_count;
			// only do aligned reads in aligned offsets
			const int aligned = fd->obsz; //512; // XXX obey fd->obsz? or it may be too slow? 128K..
			//ut64 a_off = (io->off >> 9 ) << 9; //- (io->off & aligned);
			ut64 a_off = io->off - (io->off % aligned); //(io->off >> 9 ) << 9; //- (io->off & aligned);
			int a_delta = io->off - a_off;
			if (a_delta<0) {
				return -1;
			}
			a_count = count + (aligned-(count%aligned));

			a_buf = malloc (a_count+aligned);
			if (a_buf) {
				int i;
				memset (a_buf, 0xff, a_count+aligned);
				for (i=0; i< a_count ; i+= aligned) {
					(void)lseek (mmo->fd, a_off+i, SEEK_SET);
					(void)read (mmo->fd, a_buf+i, aligned);
				}
				memcpy (a_buf+a_delta, buf, count);
				for (i=0; i< a_count ; i+= aligned) {
					(void)lseek (mmo->fd, a_off+i, SEEK_SET);
					(void)write (mmo->fd, a_buf+i, aligned);
				}
			}
			free (a_buf);
			return count;
		}
		if (lseek (fd->fd, addr, 0) < 0)
			return -1;
		len = write (fd->fd, buf, count);
		return len;
	}

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
		if (lseek (fd->fd, addr, 0) < 0) {
			return -1;
		}
		len = write (fd->fd, buf, count);
	}
	if (!r_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("io_def_mmap: failed to refresh the def_mmap backed buffer.\n");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *r_io_def_mmap_open(RIO *io, const char *file, int flags, int mode) {
	RIOMMapFileObj *mmo = r_io_def_mmap_create_new_file (io, file, mode, flags);
	if (!mmo) return NULL;
	return r_io_desc_new (io, &r_io_plugin_default, mmo->filename, flags, mode, mmo);
}


static ut64 r_io_def_mmap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return (fd && fd->data)
		? r_io_def_mmap_seek (io, (RIOMMapFileObj *)fd->data, offset, whence)
		: UT64_MAX;
}

static int r_io_def_mmap_truncate(RIOMMapFileObj *mmo, ut64 size) {
	bool res = r_file_truncate (mmo->filename, size);
	if (res && !r_io_def_mmap_refresh_def_mmap_buf (mmo) ) {
		eprintf ("r_io_def_mmap_truncate: Error trying to refresh the def_mmap'ed file.");
		res = false;
	} else if (!res) {
		eprintf ("r_io_def_mmap_truncate: Error trying to resize the file.");
	}
	return res;
}

static bool __plugin_open_default(RIO *io, const char *file, bool many) {
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

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOMMapFileObj *mmo = fd->data;
	if (!(mmo->flags & R_IO_WRITE)) {
		return false;
	}
	return r_io_def_mmap_truncate (mmo, size);
}

struct r_io_plugin_t r_io_plugin_default = {
	.name = "default",
	.desc = "open local files using def_mmap://",
	.license = "LGPL3",
	.open = __open_default,
	.close = __close,
	.read = __read,
	.check = __plugin_open_default,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_default,
	.version = R2_VERSION
};
#endif
