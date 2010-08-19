/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

// TODO: R_API int r_io_fetch(struct r_io_t *io, ut8 *buf, int len)
//  --- check for EXEC perms in section (use cached read to accelerate)

R_API struct r_io_t *r_io_new() {
	RIO *io = R_NEW (struct r_io_t);
	if (io) {
		io->write_mask_fd = -1;
		io->redirect = NULL;
		io->printf = (void*) printf;
		r_io_cache_init (io);
		r_io_map_init (io);
		r_io_section_init (io);
		r_io_plugin_init (io);
		r_io_desc_init (io);
		r_io_undo_init (io);
	}
	return io;
}

R_API RBuffer *r_io_read_buf(struct r_io_t *io, ut64 addr, int len) {
	RBuffer *b = R_NEW (RBuffer);
	b->buf = malloc (len);
	len = r_io_read_at (io, addr, b->buf, len);
	if (len<0) len = 0;
	b->length = len;
	return b;
}

R_API int r_io_write_buf(struct r_io_t *io, struct r_buf_t *b) {
	return r_io_write_at(io, b->base, b->buf, b->length);
}

R_API struct r_io_t *r_io_free(struct r_io_t *io) {
	/* TODO: properly free inner nfo */
	free (io);
	return NULL;
}

/* used by uri handler plugins */
R_API int r_io_redirect(struct r_io_t *io, const char *file) {
	free (io->redirect);
	io->redirect = file?strdup (file):NULL;
	return 0;
}

R_API int r_io_open_as(struct r_io_t *io, const char *urihandler, const char *file, int flags, int mode) {
	int ret;
	char *uri;
	int urilen = strlen (urihandler);
	uri = malloc (strlen (urihandler)+strlen (file)+5);
	if (uri == NULL)
		return -1;
	if (urilen>0)
		sprintf (uri, "%s://", urihandler);
	else *uri = '\0';
	strcpy (uri+urilen, file);
	ret = r_io_open (io, uri, flags, mode);
	free (uri);
	return ret;
}

R_API int r_io_open(struct r_io_t *io, const char *file, int flags, int mode) {
	int fd = -2;
	char *uri = strdup (file);
	struct r_io_plugin_t *plugin;
	if (io != NULL) {
		for (;;) {
			plugin = r_io_plugin_resolve (io, uri);
			if (plugin) {
				fd = plugin->open (io, uri, flags, mode);
				if (io->redirect) {
					free ((void *)uri);
					uri = strdup (io->redirect);
					r_io_redirect (io, NULL);
					continue;
				}
				if (fd != -1)
					r_io_plugin_open (io, fd, plugin);
				if (fd != io->fd)
					io->plugin = plugin;
			}
			break;
		}
	}
	if (fd == -2) {
#if __WINDOWS__
		fd = open (file, 0);
#else
		if (flags & R_IO_WRITE)
			fd = open (file, O_RDWR, mode);
		else fd = open (file, O_RDONLY, mode);
#endif
	}
	if (fd >= 0) {
		r_io_set_fd (io, fd);
		r_io_desc_add (io, fd, file, flags, io->plugin);
	} else fd = -1;

	free ((void *)uri);
	return fd;
}

// TODO: Rename to use_fd ?
R_API int r_io_set_fd(RIO *io, int fd) {
	if (fd != -1 && fd != io->fd) {
		io->plugin = r_io_plugin_resolve_fd (io, fd);
		io->fd = fd;
	}
	return io->fd;
}

R_API int r_io_read(struct r_io_t *io, ut8 *buf, int len) {
	int ret;
	/* check section permissions */
	if (io->enforce_rwx && !(r_io_section_get_rwx (io, io->off) & R_IO_READ))
		return -1;

#if 0
	if (io->cached) {
		ret = r_io_cache_read (io, io->off, buf, len);
		if (ret == len)
			return len;
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
		// partial reads
		if (ret == len)
			return len;
	}
#endif
	ret = r_io_map_read_at (io, io->off, buf, len);

	// partial reads
	if (ret != len) {
		if (ret != -1) {
			len -= ret;
			buf += len;
		}
		if (io->plugin && io->plugin->read) {
			if (io->plugin->read != NULL)
				ret = io->plugin->read(io, io->fd, buf, len);
			else eprintf ("IO plugin for fd=%d has no read()\n", io->fd);
		} else ret = read (io->fd, buf, len);
		if (ret>0 && ret<len)
			memset (buf+ret, 0xff, len-ret);
	}
	r_io_cache_read (io, io->off, buf, len);
	return ret;
}

R_API int r_io_read_at(struct r_io_t *io, ut64 addr, ut8 *buf, int len) {
	if (r_io_seek (io, addr, R_IO_SEEK_SET)==-1)
		return -1;
	return r_io_read (io, buf, len);
}

R_API ut64 r_io_read_i(struct r_io_t *io, ut64 addr, int sz, int endian) {
	ut64 ret = 0LL;
	int err;
	ut8 buf[8];
	if (sz > 8) sz = 8;
	if (sz < 0) sz = 1;
	err = r_io_read_at (io, addr, buf, sz);
	if (err == sz) r_mem_copyendian ((ut8*)&ret, buf, sz, endian);
	else return -1;
	//else perror("Cannot read");
	return ret;
}

R_API int r_io_resize(struct r_io_t *io, const char *file, int flags, int mode) {
	// XXX not implemented
#if 0
	/* TODO */
	struct r_io_plugin_t *plugin = r_io_plugin_resolve(file);
	if (plugin && io->plugin->resize) {
		int fd = plugin->resize(file, flags, mode);
		if (fd != -1)
			r_io_plugin_open(fd, plugin);
		return fd;
	}
#endif
	return -1;
}

R_API int r_io_set_write_mask(struct r_io_t *io, const ut8 *buf, int len) {
	int ret = R_FALSE;
	if (len) {
		io->write_mask_fd = io->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		memcpy (io->write_mask_buf, buf, len);
		io->write_mask_len = len;
		ret = R_TRUE;
	} else io->write_mask_fd = -1;
	return ret;
}

R_API int r_io_write(struct r_io_t *io, const ut8 *buf, int len) {
	int i, ret = -1;
	ut8 *data = NULL;

	/* check section permissions */
	if (io->enforce_rwx && !(r_io_section_get_rwx (io, io->off) & R_IO_WRITE))
		return -1;

	if (io->cached) {
		ret = r_io_cache_write (io, io->off, buf, len);
		if (ret == len)
			return len;
		if (ret > 0) {
			len -= ret;
			buf += ret;
		}
	}

	/* TODO: implement IO cache here. to avoid dupping work on vm for example */

	/* apply write binary mask */
	if (io->write_mask_fd != -1) {
		data = malloc (len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		r_io_read (io, data, len);
		r_io_seek (io, io->off, R_IO_SEEK_SET);
		for (i=0; i<len; i++)
			data[i] = buf[i] & \
				io->write_mask_buf[i%io->write_mask_len];
		buf = data;
	}

	if (!r_io_map_write_at (io, io->off, buf, len)) {
		if (io->plugin) {
			if (io->plugin->write)
				ret = io->plugin->write (io, io->fd, buf, len);
			else eprintf ("r_io_write: io handler with no write callback\n");
		} else ret = write (io->fd, buf, len);
		if (ret == -1)
			eprintf ("r_io_write: cannot write on fd %d\n", io->fd);
	} else ret = len;
	if (data)
		free (data);
	return ret;
}

R_API int r_io_write_at(struct r_io_t *io, ut64 addr, const ut8 *buf, int len) {
	if (r_io_seek (io, addr, R_IO_SEEK_SET)<0)
		return -1;
	return r_io_write (io, buf, len);
}

R_API ut64 r_io_seek(struct r_io_t *io, ut64 offset, int whence) {
	int posix_whence = SEEK_SET;
	ut64 ret = -1;

	switch(whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		break;
	case R_IO_SEEK_CUR:
		offset += io->off;
		posix_whence = SEEK_CUR;
		break;
	case R_IO_SEEK_END:
		//offset = UT64_MAX; // XXX: depending on io bits?
		posix_whence = SEEK_END;
		break;
	}
	// XXX: list_empty trick must be done in r_io_set_va();
	offset = (!io->debug && io->va && !list_empty (&io->sections))? 
		r_io_section_vaddr_to_offset (io, offset) : offset;
	// TODO: implement io->enforce_seek here!
	if (io->plugin && io->plugin->lseek)
		ret = io->plugin->lseek (io, io->fd, offset, whence);
	// XXX can be problematic on w32..so no 64 bit offset?
	else ret = lseek (io->fd, offset, posix_whence);
	if (ret != -1) {
		io->off = ret;
		// XXX this can be tricky.. better not to use this .. must be deprecated 
		// r_io_sundo_push (io);
		ret = (!io->debug && io->va && !list_empty (&io->sections))?
			r_io_section_offset_to_vaddr (io, io->off) : io->off;
	}
	return ret;
}

R_API ut64 r_io_size(RIO *io, int fd) {
	ut64 size, here;
	r_io_set_fd (io, fd);
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
	r_io_seek (io, here, R_IO_SEEK_SET);
	return size;
}

R_API int r_io_system(RIO *io, const char *cmd) {
	int ret = -1;
	if (io->plugin && io->plugin->system)
		ret = io->plugin->system (io, io->fd, cmd);
	return ret;
}

// TODO: remove int fd here???
R_API int r_io_close(struct r_io_t *io, int fd) {
	fd = r_io_set_fd (io, fd);
	if (fd != -1 && io->plugin) {
		r_io_desc_del (io, fd);
		r_io_map_del (io, fd);
		r_io_plugin_close (io, fd, io->plugin);
		if (io->plugin->close)
			return io->plugin->close (io, fd);
	}
	io->fd = -1; // unset current fd
	return close (fd);
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	bnd->io = io;
	bnd->init = R_TRUE;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	//bnd->fd = io->fd;// do we need to store ptr to fd??
	return R_TRUE;
}
