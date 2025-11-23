/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_io.h>
#include <r_lib.h>

typedef struct r_io_mmo_t {
	char *filename;
	int mode;
	int perm;
	int fd;
	int isblk;
	ut64 addr;
	bool rawio;
	bool nocache;
	RBuffer *buf;
	RIO *io_backref;
} RIOMMapFileObj;

static bool check_for_blockdevice(RIOMMapFileObj *mmo) {
#if R2__UNIX__
	R_RETURN_VAL_IF_FAIL (mmo, false);
	if (mmo->isblk == -1) {
		struct stat buf;
		if (fstat (mmo->fd, &buf) == -1) {
			mmo->isblk = 0;
		} else {
			mmo->isblk = ((buf.st_mode & S_IFBLK) == S_IFBLK)? 1: 0;
		}
	}
	return mmo->isblk == 1;
#endif
	return false;
}

static int open_file(const char *file, int perm, int mode) {
	int fd;
	if (r_str_startswith (file, "file://")) {
		file += strlen ("file://");
	} else if (r_str_startswith (file, "stdio://")) {
		file += strlen ("stdio://");
	}
	if (r_file_is_directory (file)) {
		return -1;
	}
#if R2__WINDOWS__
	// probably unnecessary to have this ifdef nowadays windows is posix enough
	if (perm & R_PERM_W) {
		fd = r_sandbox_open (file, O_RDWR, 0);
		if (fd == -1 && (perm & R_PERM_CREAT)) {
			r_sandbox_creat (file, 0644);
			fd = r_sandbox_open (file, O_RDWR | O_CREAT, 0);
			if (fd != -1) {
				R_LOG_INFO ("New file created: %s", file);
			}
		}
	} else {
		fd = r_sandbox_open (file, O_RDONLY | O_BINARY, 0);
	}
#else
	const size_t posixFlags = (perm & R_PERM_W) ? (perm & R_PERM_CREAT)
			? (O_RDWR | O_CREAT) : O_RDWR : O_RDONLY;
	bool toctou = (posixFlags & O_CREAT) && r_file_exists (file);
	fd = r_sandbox_open (file, posixFlags, mode);
	if ((posixFlags & O_CREAT) && !toctou && fd != -1) {
		R_LOG_INFO ("New file created: %s", file);
	}
#endif
	return fd;
}

static ut64 mmap_seek(RIO *io, RIOMMapFileObj *mmo, ut64 offset, int whence) {
	if (mmo->rawio) {
		if (whence == 2 && mmo->isblk) {
			return UT64_MAX - 1;
		}
		mmo->addr = lseek (mmo->fd, offset, whence);
	} else if (mmo->buf) {
		mmo->addr = r_buf_seek (mmo->buf, offset, whence);
	} else {
		return UT64_MAX - 1;
	}
	return mmo->addr;
}

static bool mmap_refresh(RIOMMapFileObj *mmo) {
	RIO* io = mmo->io_backref;
	ut64 cur = 0;
	if (mmo->buf) {
		cur = r_buf_tell (mmo->buf);
		r_buf_free (mmo->buf);
		mmo->buf = NULL;
	}
	st64 sz = r_file_size (mmo->filename);
	if (sz > ST32_MAX) {
		// Do not use mmap if the file is huge
		mmo->rawio = true;
	}
	if (mmo->rawio) {
		if (mmo->fd == -1) {
			mmo->fd = open_file (mmo->filename, mmo->perm, mmo->mode);
		}
		if (mmo->fd != -1 && cur) {
			mmap_seek (io, mmo, cur, SEEK_SET);
		}
		goto done;
	}
	if (mmo->fd == -1) {
		mmo->fd = open_file (mmo->filename, mmo->perm, mmo->mode);
		if (mmo->fd == -1) {
			return false;
		}
	}
	check_for_blockdevice (mmo);
	mmo->buf = r_buf_new_mmap (mmo->filename, mmo->perm);
	if (mmo->buf) {
		if (io) {
			mmo->buf->Oxff_priv = io->Oxff;
		}
		mmap_seek (io, mmo, cur, SEEK_SET);
		return true;
	}
	mmo->rawio = true;
done:
#ifdef F_NOCACHE
	if (mmo->nocache && mmo->fd != -1) {
		fcntl (mmo->fd, F_NOCACHE, 1);
	}
#endif
	return mmo->fd != -1;
}

static void mmap_free(RIOMMapFileObj * R_NULLABLE mmo) {
	if (mmo) {
		free (mmo->filename);
		r_buf_free (mmo->buf);
		if (mmo->fd >= 0) {
			close (mmo->fd);
		}
		free (mmo);
	}
}

static RIOMMapFileObj *mmap_create(RIO  *io, const char *filename, int perm, int mode) {
	R_RETURN_VAL_IF_FAIL (io && filename, NULL);
	RIOMMapFileObj *mmo = R_NEW0 (RIOMMapFileObj);
	mmo->fd = -1;
	mmo->rawio = false;
	if (r_str_startswith (filename, "file://")) {
		filename += strlen ("file://");
		mmo->rawio = false;
	} else if (r_str_startswith (filename, "stdio://")) {
		filename += strlen ("stdio://");
		mmo->rawio = true;
	} else if (r_str_startswith (filename, "nocache://")) {
		filename += strlen ("nocache://");
		mmo->nocache = true;
		mmo->rawio = true;
	}
	mmo->filename = strdup (filename);
	mmo->perm = perm;
	mmo->isblk = -1;
	mmo->mode = mode;
	mmo->io_backref = io;
	if (!mmap_refresh (mmo)) {
		mmap_free (mmo);
		mmo = NULL;
	}
	return mmo;
}

static bool uricheck(const char *filename) {
	R_RETURN_VAL_IF_FAIL (filename, false);
	const char *peekaboo = strstr (filename, "://");
	if (peekaboo) {
		if (r_str_startswith (filename, "file://")) {
			filename += strlen ("file://");
		} else if (r_str_startswith (filename, "stdio://")) {
			filename += strlen ("stdio://");
		} else if (r_str_startswith (filename, "nocache://")) {
			filename += strlen ("nocache://");
		} else {
			return false;
		}
	}
	return *filename != 0;
}

static int r_io_def_mmap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (fd && fd->data && buf, -1);
	RIOMMapFileObj *mmo = (RIOMMapFileObj*)fd->data;
	if (mmo->addr == UT64_MAX) {
		memset (buf, io->Oxff, count);
		return count;
	}
	if (mmo->rawio) {
		if (lseek (mmo->fd, mmo->addr, SEEK_SET) < 0) {
			return -1;
		}
		return read (mmo->fd, buf, count);
	}
	size_t bs = r_buf_size (mmo->buf);
	if (bs < mmo->addr) {
		mmo->addr = bs;
	}
	int r = r_buf_read_at (mmo->buf, mmo->addr, buf, count);
	if (r < 0) {
		return r;
	}
	r_buf_seek (mmo->buf, r, R_BUF_CUR);
	mmo->addr += r;
	return r;
}

static int mmap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	R_RETURN_VAL_IF_FAIL (io && fd && fd->data && buf, -1);

	RIOMMapFileObj *mmo = fd->data;
	ut64 addr = mmo->addr;
	if (mmo->rawio) {
		if (lseek (mmo->fd, addr, 0) < 0) {
			return -1;
		}
		return write (mmo->fd, buf, count);
	}

	if (mmo->buf) {
		if (!(mmo->perm & R_PERM_W)) {
			return -1;
		}
		if ((count + addr > r_buf_size (mmo->buf)) || r_buf_size (mmo->buf) == 0) {
			ut64 sz = count + addr;
			r_file_truncate (mmo->filename, sz);
		}
	}

	int len = r_file_mmap_write (mmo->filename, addr, buf, count);
	if (len != count) {
		// XXX this is wrong. what about non-fd baked mmos?
		// aim to hack some corner cases?
		if (lseek (fd->fd, addr, 0) < 0) {
			return -1;
		}
		len = write (fd->fd, buf, count);
	}
	if (!mmap_refresh (mmo) ) {
		R_LOG_ERROR ("failed to refresh the def_mmap backed buffer");
		// XXX - not sure what needs to be done here (error handling).
	}
	return len;
}

static RIODesc *mmap_open(RIO *io, const char *file, int perm, int mode) {
	R_RETURN_VAL_IF_FAIL (io && file, NULL);
#if __wasi__
	RIOPlugin *_plugin = r_io_plugin_resolve (io, (const char *)"slurp://", false);
	if (!_plugin || !_plugin->open) {
		return NULL;
	}
	char *uri = r_str_newf ("slurp://%s", file);
	RIODesc *d = _plugin->open (io, uri, perm, mode);
	free (uri);
	return d;
#else
	RIOMMapFileObj *mmo = mmap_create (io, file, perm, mode);
	if (!mmo) {
		return NULL;
	}
	RIODesc *d = r_io_desc_new (io, &r_io_plugin_default, mmo->filename, perm, mode, mmo);
	if (!d->name) {
		d->name = strdup (file);
	}
	if (r_str_startswith (d->name, "file://")) {
		char *oldname = d->name;
		d->name = strdup (oldname + strlen ("file://"));
		free (oldname);
	}
	return d;
#endif
}

static int mmap_truncate(RIODesc *fd, RIOMMapFileObj *mmo, ut64 size) {
	bool res = r_file_truncate (mmo->filename, size);
	if (res && !mmap_refresh (mmo)) {
		R_LOG_ERROR ("Can't refresh the def_mmap'ed file");
		res = false;
	} else if (!res) {
		R_LOG_ERROR ("Trying to resize the file");
	}
	mmo->addr = size;
	return res;
}

static bool __check(RIO *io, const char *file, bool many) {
	return uricheck (file);
}

// default open should permit opening
static RIODesc *__open(RIO *io, const char *file, int perm, int mode) {
	if (uricheck (file)) {
		return mmap_open (io, file, perm, mode);
	}
	return NULL;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	return r_io_def_mmap_read (io, fd, buf, len);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return mmap_write (io, fd, buf, len);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	R_RETURN_VAL_IF_FAIL (fd && fd->data, UT64_MAX);
	return mmap_seek (io, (RIOMMapFileObj *)fd->data, offset, whence);
}

static bool __close(RIODesc *fd) {
	R_RETURN_VAL_IF_FAIL (fd, false);
	if (fd->data) {
		mmap_free ((RIOMMapFileObj *) fd->data);
		fd->data = NULL;
	}
	return true;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 size) {
	R_RETURN_VAL_IF_FAIL (io && fd && fd->data, false);
	RIOMMapFileObj *mmo = fd->data;
	if (!(mmo->perm & R_PERM_W)) {
		return false;
	}
	return mmap_truncate (fd, mmo, size);
}

static bool __is_blockdevice(RIODesc *desc) {
	R_RETURN_VAL_IF_FAIL (desc && desc->data, false);
	RIOMMapFileObj *mmo = desc->data;
	return mmo? mmo->isblk == 1: false;
}

RIOPlugin r_io_plugin_default = {
	.meta = {
		.name = "default",
		.desc = "Open local files",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.uris = "file://,nocache://,stdio://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
	.resize = __resize,
#if R2__UNIX__
	.is_blockdevice = __is_blockdevice,
#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_default,
	.version = R2_VERSION
};
#endif
