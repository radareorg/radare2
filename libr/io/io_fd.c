/* radare2 - LGPL - Copyright 2017-2024 - condret */

#include <r_io.h>

R_API int r_io_fd_open(RIO *io, const char *uri, int flags, int mode) {
	RIODesc *desc = r_io_desc_open (io, uri, flags, mode);
	return desc? desc->fd: -1;
}

R_API bool r_io_fd_close(RIO *io, int fd) {
	return r_io_desc_close (r_io_desc_get (io, fd));
}

//returns length of read bytes
R_API int r_io_fd_read(RIO *io, int fd, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (io && buf, -1);
	if (len < 0) {
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_read (desc, buf, len): -1;
}

//returns length of written bytes
R_API int r_io_fd_write(RIO *io, int fd, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (io && buf, -1);
	if (len < 0) {
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_write (desc, buf, len): -1;
}

R_API ut64 r_io_fd_seek(RIO *io, int fd, ut64 addr, int whence) {
	R_RETURN_VAL_IF_FAIL (io, UT64_MAX);
	return r_io_desc_seek (r_io_desc_get (io, fd), addr, whence);
}

R_API ut64 r_io_fd_size(RIO *io, int fd) {
	return r_io_desc_size (r_io_desc_get (io, fd));
}

R_API bool r_io_fd_resize(RIO *io, int fd, ut64 newsize) {
	return r_io_desc_resize (r_io_desc_get (io, fd), newsize);
}

R_API char *r_io_fd_system(RIO *io, int fd, const char *cmd) {
	return r_io_desc_system (r_io_desc_get (io, fd), cmd);
}

R_API bool r_io_fd_is_blockdevice(RIO *io, int fd) {
	return r_io_desc_is_blockdevice (r_io_desc_get (io, fd));
}

R_API bool r_io_fd_is_chardevice(RIO *io, int fd) {
	return r_io_desc_is_chardevice (r_io_desc_get (io, fd));
}

//returns length of read bytes
R_API int r_io_fd_read_at(RIO *io, int fd, ut64 addr, ut8 *buf, int len) {
	RIODesc *desc;
	if (!io || !buf || (len < 1) || !(desc = r_io_desc_get (io, fd))) {
		return 0;
	}
	return r_io_desc_read_at (desc, addr, buf, len);
}

//returns length of written bytes
R_API int r_io_fd_write_at(RIO *io, int fd, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (io && buf, -1);
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_write_at (desc, addr, buf, len): -1;
}

R_API bool r_io_fd_is_dbg(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_is_dbg (desc): false;
}

R_API int r_io_fd_get_pid(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_get_pid (desc): -2;
}

R_API int r_io_fd_get_tid(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? r_io_desc_get_tid (desc): -2;
}

R_API bool r_io_fd_get_base(RIO *io, int fd, ut64 *base) {
	R_RETURN_VAL_IF_FAIL (io && io->files.data && base, false);
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_get_base (desc, base);
}

R_API const char *r_io_fd_get_name(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io && io->files.data, NULL);
	RIODesc *desc = r_io_desc_get (io, fd);
	return desc? desc->name: NULL;
}

R_API bool r_io_use_fd(RIO* io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, false);
	if (!io->desc) {
		io->desc = r_io_desc_get (io, fd);
		return io->desc;
	}
	if (io->desc->fd != fd) {
		RIODesc* desc = r_io_desc_get (io, fd);
		//update io->desc if fd is not the same
		if (!desc) {
			return false;
		}
		io->desc = desc;
	}
	return true;
}

R_API int r_io_fd_get_current(RIO *io) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	if (io->desc) {
		return io->desc->fd;
	}
	return -1;
}

R_API int r_io_fd_get_next(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	int ret = fd;
	if (!r_id_storage_get_next (&io->files, (ut32 *)&ret)) {
		return -1;
	}
	return ret;
}

R_API int r_io_fd_get_prev(RIO *io, int fd) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	int ret = fd;
	if (!r_id_storage_get_prev (&io->files, (ut32 *)&ret)) {
		return -1;
	}
	return ret;
}

R_API int r_io_fd_get_highest(RIO *io) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	int fd = -1;
	if (!r_id_storage_get_highest (&io->files, (ut32 *)&fd)) {
		return -1;
	}
	return fd;
}

R_API int r_io_fd_get_lowest(RIO *io) {
	R_RETURN_VAL_IF_FAIL (io, -1);
	int fd = -1;
	if (!r_id_storage_get_lowest (&io->files, (ut32 *)&fd)) {
		return -1;
	}
	return fd;
}
