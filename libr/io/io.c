/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

R_API int r_io_init(struct r_io_t *io)
{
	io->write_mask_fd = -1;
	io->last_align = 0;
	io->redirect = NULL;
	io->printf = printf;
	r_io_map_init(io);
	r_io_section_init(io);
	r_io_handle_init(io);
	return 0;
}

R_API struct r_io_t *r_io_new()
{
	struct r_io_t *io = MALLOC_STRUCT(struct r_io_t);
	r_io_init(io);
	return io;
}

R_API struct r_io_t *r_io_free(struct r_io_t *io)
{
	free(io);
	return NULL;
}

R_API int r_io_redirect(struct r_io_t *io, const char *file)
{
	free(io->redirect);
	io->redirect = file?strdup(file):NULL;
	return 0;
}

R_API int r_io_open(struct r_io_t *io, const char *file, int flags, int mode)
{
	const char *uri = strdup(file);
	struct r_io_handle_t *plugin;
	if (io != NULL) {
		do {
			plugin = r_io_handle_resolve(io, uri);
			if (plugin) {
				int fd = plugin->open(io, uri, flags, mode);
				if (io->redirect) {
					printf("REDIRECT FOO => (%s)\n", io->redirect);
					free((void *)uri);
					uri = strdup(io->redirect);
					r_io_redirect(io, NULL);
					continue;
				}
				if (fd != -1)
					r_io_handle_open(io, fd, plugin);
				if (fd != io->fd)
					io->plugin = plugin;
				io->fd = fd;
				return fd;
			}
			break;
		} while(1);
	} else fprintf(stderr, "WARNING: Using uninitialized r_io\n");
	return open(file, flags, mode);
}

R_API int r_io_set_fd(struct r_io_t *io, int fd)
{
	if (fd == -1)
		fd = io->fd;
	else if (fd != io->fd) {
		io->plugin = r_io_handle_resolve_fd(io, fd);
		io->fd = fd;
	}
	return fd;
}

R_API int r_io_read(struct r_io_t *io, int fd, ut8 *buf, int len)
{
	fd = r_io_set_fd(io, fd);
	if (r_io_map_read_at(io, io->seek, buf, len) != 0)
		return len;
	if (io->plugin && io->plugin->read) {
		io->fd = fd;
		if (io->plugin->read != NULL)
			return io->plugin->read(io, fd, buf, len);
		else fprintf(stderr, "IO handler for fd=%d has no read()\n",fd);
	}
	return read(fd, buf, len);
}

R_API ut64 r_io_read_i(struct r_io_t *io, int fd, ut64 addr, int sz, int endian)
{
	ut64 ret = 0LL;
	int err;
	char buf[128], dst[128];
	if (sz > 8) sz = 8;
	if (sz < 0) sz = 1;
	err = r_io_lseek(io, fd, addr, R_IO_SEEK_SET);
	// XXX do something with err
	err = r_io_read(io, fd, buf, sz);
	if (err != sz) {
		perror("Cannot read");
	} else {
		r_mem_copyendian(&ret, buf, sz, endian);
	}
	return ret;
}

R_API int r_io_resize(struct r_io_t *io, int fd, const char *file, int flags, int mode)
{
	fd = r_io_set_fd(io, fd);
#if 0
	/* TODO */
	struct r_io_handle_t *plugin = r_io_handle_resolve(file);
	if (plugin && io->plugin->resize) {
		int fd = plugin->resize(file, flags, mode);
		if (fd != -1)
			r_io_handle_open(fd, plugin);
		return fd;
	}
#endif
	return -1;
}

R_API int r_io_set_write_mask(struct r_io_t *io, int fd, const ut8 *buf, int len)
{
	int ret;
	fd = r_io_set_fd(io, fd);
	if (len) {
		io->write_mask_fd = fd;
		io->write_mask_buf = (ut8 *)malloc(len);
		memcpy(io->write_mask_buf, buf, len);
		io->write_mask_len = len;
		ret = R_TRUE;
	} else {
		io->write_mask_fd = -1;
		ret = R_FALSE;
	}
	return ret;
}

R_API int r_io_write(struct r_io_t *io, int fd, const ut8 *buf, int len)
{
	int i, ret = -1;
	fd = r_io_set_fd(io, fd);

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		ut8 *data = alloca(len);
		r_io_lseek(io, fd, io->seek, R_IO_SEEK_SET);
		r_io_read(io, fd, data, len);
		r_io_lseek(io, fd, io->seek, R_IO_SEEK_SET);
		for(i=0;i<len;i++) {
			data[i] = buf[i] & \
				io->write_mask_buf[i%io->write_mask_len];
		}
		buf = data;
	}

	if (r_io_map_write_at(io, io->seek, buf, len) != 0)
		return len;
	if (io->plugin) {
		io->fd = fd;
		if (io->plugin->write)
			ret = io->plugin->write(io, fd, buf, len);
	} else ret = write(fd, buf, len);
	if (ret == -1)
		fprintf(stderr, "r_io_write: cannot write\n");
	return ret;
}

R_API ut64 r_io_lseek(struct r_io_t *io, int fd, ut64 offset, int whence)
{
	int posix_whence = 0;
	fd = r_io_set_fd(io, fd);

	if (whence == SEEK_SET)
		offset = r_io_section_align(io, offset, 0, 0);

	/* pwn seek value */
	switch(whence) {
	case R_IO_SEEK_SET:
		io->seek = offset;
		posix_whence = SEEK_SET;
		break;
	case R_IO_SEEK_CUR:
		io->seek += offset;
		posix_whence = SEEK_CUR;
		break;
	case R_IO_SEEK_END:
		io->seek = 0xffffffff;
		posix_whence = SEEK_END;
		break;
	}

	if (io->plugin && io->plugin->lseek) {
		io->fd = fd;
		return io->plugin->lseek(io, fd, offset, whence);
	}
	// XXX can be problematic on w32..so no 64 bit offset?
	return lseek(fd, offset, posix_whence);
}

R_API ut64 r_io_size(struct r_io_t *io, int fd)
{
	ut64 size, here;
	fd = r_io_set_fd(io, fd);
	here = r_io_lseek(io, fd, 0, R_IO_SEEK_CUR);
	size = r_io_lseek(io, fd, 0, R_IO_SEEK_END);
	r_io_lseek(io, fd, here, R_IO_SEEK_SET);
	return size;
}

R_API int r_io_system(struct r_io_t *io, int fd, const char *cmd)
{
	fd = r_io_set_fd(io, fd);
	if (io->plugin && io->plugin->system) {
		return io->plugin->system(io, fd, cmd);
	}
	return 0;
}

R_API int r_io_close(struct r_io_t *io, int fd)
{
	fd = r_io_set_fd(io, fd);
	if (io->plugin) {
		io->fd = fd;
		r_io_handle_close(io, fd, io->plugin);
		if (io->plugin->close)
			return io->plugin->close(io, fd);
	}
	return close(fd);
}

#if 0
// define callback for other APIs to use with current io
static int _cb_read(struct r_io_t *io, int pid, ut64 addr, ut8 *buf, int len)
{
}

static int _cb_write(struct r_io_t *io, int pid, ut64 addr, const ut8 *buf, int len)
{
}

R_API int r_io_hook(struct r_io_t *io, CB_IO)
{
	return cb_io(user, _cb_read, _cb_write
}
#endif
