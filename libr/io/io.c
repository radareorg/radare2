/* radare - LGPL - Copyright 2008-2012 - pancake */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

// TODO: R_API int r_io_fetch(struct r_io_t *io, ut8 *buf, int len)
//  --- check for EXEC perms in section (use cached read to accelerate)

R_API struct r_io_t *r_io_new() {
	RIO *io = R_NEW (RIO);
	if (!io) return NULL;
	io->fd = NULL;
	io->write_mask_fd = -1;
	io->redirect = NULL;
	io->printf = (void*) printf;
	io->bits = (sizeof(void*) == 8)? 64: 32;
	io->va = -1;
	io->plugin = NULL;
	io->raised = -1;
	io->off = 0;
	r_io_cache_init (io);
	r_io_map_init (io);
	r_io_section_init (io);
	r_io_plugin_init (io);
	r_io_desc_init (io);
	r_io_undo_init (io);
	return io;
}

R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener)
		return io->plugin->listener (io->fd);
	return R_FALSE;
}

R_API RBuffer *r_io_read_buf(struct r_io_t *io, ut64 addr, int len) {
	RBuffer *b = R_NEW (RBuffer);
	b->buf = malloc (len);
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len<0)?0:len;
	return b;
}

R_API int r_io_write_buf(struct r_io_t *io, struct r_buf_t *b) {
	return r_io_write_at(io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	if (!io) return NULL;
	/* TODO: properly free inner nfo */
	/* TODO: memory leaks */
	r_list_free (io->sections);
	r_list_free (io->maps);
	r_io_desc_fini (io);
	free (io);
	return NULL;
}

/* used by uri handler plugins */
R_API int r_io_redirect(struct r_io_t *io, const char *file) {
	free (io->redirect);
	io->redirect = file? strdup (file): NULL;
	return 0;
}

R_API RIODesc *r_io_open_as(struct r_io_t *io, const char *urihandler, const char *file, int flags, int mode) {
	RIODesc *ret;
	char *uri;
	int urilen, hlen = strlen (urihandler);
	urilen = hlen + strlen (file)+5;
	uri = malloc (urilen);
	if (uri == NULL)
		return NULL;
	if (hlen>0) snprintf (uri, urilen, "%s://%s", urihandler, file);
	else strncpy (uri, file, urilen);
	ret = r_io_open (io, uri, flags, mode);
	free (uri);
	return ret;
}

R_API RIODesc *r_io_open(RIO *io, const char *file, int flags, int mode) {
	struct r_io_plugin_t *plugin = NULL;
	RIODesc *desc = NULL;
	int fd = -2;
	char *uri;
	if (!io) return NULL;
	io->plugin = NULL;
	uri = strdup (file);
	for (;;) {
		plugin = r_io_plugin_resolve (io, uri);
		if (plugin && plugin->open) {
			desc = plugin->open (io, uri, flags, mode);
			if (io->redirect) {
				// TODO: free desc if not null
				free ((void *)uri);
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
			if (desc != NULL) {
				r_io_desc_add (io, desc);
				fd = desc->fd;
				if (fd != -1)
					r_io_plugin_open (io, fd, plugin);
				if (desc != io->fd)
					io->plugin = plugin;
			}
		}
		break;
	}
	if (fd == -2) {
#if __WINDOWS__
		if (flags & R_IO_WRITE) {
			fd = open (uri, O_BINARY | 1);
			if (fd == -1)
				creat (uri, O_BINARY);
			fd = open (uri, O_BINARY | 1);
		} else fd = open (uri, O_BINARY);
#else
		fd = open (uri, (flags&R_IO_WRITE)?O_RDWR:O_RDONLY, mode);
#endif
	}
	if (fd >= 0) {
		if (desc == NULL)
			desc = r_io_desc_new (io->plugin,
				fd, uri, flags, mode, NULL);
		r_io_desc_add (io, desc);
		r_io_set_fd (io, desc);
	}
	free ((void *)uri);
	return desc;
}

R_API int r_io_set_fd(RIO *io, RIODesc *fd) {
	if (fd != NULL) {
		io->fd = fd;
		io->plugin = fd->plugin;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_io_set_fdn(RIO *io, int fd) {
	if (fd != -1 && io->fd != NULL && fd != io->fd->fd) {
		RIODesc *desc = r_io_desc_get (io, fd);
		if (!desc) return R_FALSE;
		io->fd = desc;
		io->plugin = desc->plugin;
		return R_TRUE;
	}
	return R_FALSE;
}

static inline int r_io_read_internal(RIO *io, ut8 *buf, int len) {
	if (io->plugin && io->plugin->read)
		return io->plugin->read (io, io->fd, buf, len);
	return read (io->fd->fd, buf, len);
}

R_API int r_io_read(RIO *io, ut8 *buf, int len) {
	if (io==NULL || io->fd == NULL)
		return -1;
	/* IGNORE check section permissions 
	if (io->enforce_rwx && !(r_io_section_get_rwx (io, io->off) & R_IO_READ))
		return -1;
	 */
	return r_io_read_at (io, io->off, buf, len);
}

// XXX: this is buggy. must use seek+read
R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	int ret, l, olen = len;
	int w = 0;
	int eof = 0;

	r_io_seek (io, addr, R_IO_SEEK_SET);
#if 0
	// HACK?: if io->va == 0 -> call seek+read without checking sections ?
	if (!io->va) {
	//	r_io_seek (io, addr, R_IO_SEEK_SET);
		r_io_map_select (io, addr);
		ret = r_io_read_internal (io, buf, len);
		if (io->cached) {
			r_io_cache_read (io, addr, buf, len);
		}
		return ret;
	}
#endif
// XXX: this is buggy!
	memset (buf, 0xff, len);
#if 0
	ret = r_io_read_internal (io, buf, len);
	return len;
#endif

	while (len>0) {
		int ms;
		ut64 last = r_io_section_next (io, addr);
		l = (len > (last-addr))? (last-addr): len;
		if (l<1) l = len;
		// ignore seek errors
//		eprintf ("0x%llx %llx\n", addr+w, 
		//r_io_seek (io, addr+w, R_IO_SEEK_SET);
		if (r_io_seek (io, addr+w, R_IO_SEEK_SET)==UT64_MAX) {
			memset (buf+w, 0xff, l);
			return -1;
		}
		ms = r_io_map_select (io, addr+w);
		ret = r_io_read_internal (io, buf+w, l);
		if (ret<1) {
			memset (buf+w, 0xff, l); // reading out of file
			ret = 1;
		} else if (ret<l) {
		//	eprintf ("FOUND EOF AT %llx\n", addr+ret);
			eof = 1;
			l = ret;
		} else {
			//eprintf ("L = %d\n", len-w);
			eof = 1;
		}
		if (io->cached) {
			r_io_cache_read (io, addr+w, buf+w, len-w);
		} else
		// hide non-mapped files here
		// do not allow reading on real addresses if mapped != 0
		if (r_list_length (io->maps) >1)
		if (!io->debug && ms>0) {
			//eprintf ("FAIL MS=%d l=%d d=%d\n", ms, l, d);
			/* check if address is vaddred in sections */
			ut64 o = r_io_section_offset_to_vaddr (io, addr);
			if (o == UT64_MAX) {
				ut64 o = r_io_section_vaddr_to_offset (io, addr);
				if (o == UT64_MAX)
					memset (buf+w, 0xff, l);
			}
			break;
		}
		////if (eof) break;
		w += l;
		len -= l;
break;
	}
	return olen;
}

R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz, int endian) {
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

R_API int r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin && io->plugin->resize)
		return io->plugin->resize (io, io->fd, newsize);
	else ftruncate (io->fd->fd, newsize);
	return R_FALSE;
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	int ret = R_FALSE;
	if (len) {
		io->write_mask_fd = io->fd->fd;
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
	
	r_io_map_select (io, io->off);

	if (io->plugin) {
		if (io->plugin->write)
			ret = io->plugin->write (io, io->fd, buf, len);
		else eprintf ("r_io_write: io handler with no write callback\n");
	} else ret = write (io->fd->fd, buf, len);

	if (ret == -1)
		eprintf ("r_io_write: cannot write on fd %d\n", io->fd->fd);
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
	ut64 ret = UT64_MAX;
	switch (whence) {
	case R_IO_SEEK_SET:
		posix_whence = SEEK_SET;
		ret = offset;
		break;
	case R_IO_SEEK_CUR:
//		offset += io->off;
		posix_whence = SEEK_CUR;
		ret = offset+io->off;
		break;
	case R_IO_SEEK_END:
		//offset = UT64_MAX; // XXX: depending on io bits?
		ret = UT64_MAX;
		posix_whence = SEEK_END;
		break;
	}
	if (io == NULL)
		return ret;
	// XXX: list_empty trick must be done in r_io_set_va();
	//eprintf ("-(seek)-> 0x%08llx\n", offset);
	if (!io->debug && io->va && !r_list_empty (io->sections)) {
		ut64 o = r_io_section_vaddr_to_offset (io, offset);
		if (o != UT64_MAX)
			offset = o;
	//	eprintf ("-(vadd)-> 0x%08llx\n", offset);
	}
	// if resolution fails... just return as invalid address
	if (offset==UT64_MAX)
		return UT64_MAX;
	// TODO: implement io->enforce_seek here!
	if (io->fd != NULL) {
		// lseek_internal
		if (io->plugin && io->plugin->lseek)
			ret = io->plugin->lseek (io, io->fd, offset, whence);
		// XXX can be problematic on w32..so no 64 bit offset?
		else ret = (ut64)lseek (io->fd->fd, offset, posix_whence);
		if (ret != UT64_MAX) {
			io->off = ret;
			// XXX this can be tricky.. better not to use this .. must be deprecated
			// r_io_sundo_push (io);
			ret = (!io->debug && io->va && !r_list_empty (io->sections))?
				r_io_section_offset_to_vaddr (io, io->off) : io->off;
		} //else eprintf ("r_io_seek: cannot seek to %"PFMT64x"\n", offset);
	} //else { eprintf ("r_io_seek: null fd\n"); }
	return ret;
}

R_API ut64 r_io_size(RIO *io) {
	int iova;
	ut64 size, here;
	if (!io) return 0LL;
	iova = io->va;
	if (r_io_is_listener (io))
		return UT64_MAX;
// XXX. problematic when io.va = 1
io->va = 0;
	//r_io_set_fdn (io, fd);
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
io->va = iova;
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
R_API int r_io_close(struct r_io_t *io, RIODesc *fd) {
	if (io == NULL || fd == NULL)
		return -1;
	int nfd = fd->fd;
	if (r_io_set_fd (io, fd)) {
		RIODesc *desc = r_io_desc_get (io, fd->fd);
		if (desc) {
			r_io_map_del (io, fd->fd);
			r_io_plugin_close (io, fd->fd, io->plugin);
			if (io->plugin && io->plugin->close)
				return io->plugin->close (desc);
			r_io_desc_del (io, desc->fd);
		}
	}
	io->fd = NULL; // unset current fd
	return close (nfd);
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	bnd->io = io;
	bnd->init = R_TRUE;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	//bnd->fd = io->fd;// do we need to store ptr to fd??
	return R_TRUE;
}

R_API int r_io_accept(RIO *io, int fd) {
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept)
		return io->plugin->accept (io, io->fd, fd);
	return R_FALSE;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end-start) <= shiftsize) return R_FALSE;
	rest = (end-start) - shiftsize;

	if (!(buf = malloc (chunksize))) return R_FALSE;

	if (move>0) src = end-shiftsize;
	else src = start+shiftsize;

	while (rest>0) {
		if (chunksize>rest) chunksize=rest;
		if (move>0) src -= chunksize;

		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src+move, buf, chunksize);

		if (move<0) src += chunksize;
		rest -= chunksize;
	}
	free (buf);
	return R_TRUE;
}

R_API int r_io_create (RIO *io, const char *file, int mode, int type) {
	if (io->plugin && io->plugin->create)
		return io->plugin->create (io, file, mode, type);
	if (type == 'd'|| type == 1)
		return r_sys_mkdir (file);
	return creat (file, mode)? R_FALSE: R_TRUE;
}
