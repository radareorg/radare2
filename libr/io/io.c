/* radare - LGPL - Copyright 2008-2014 - pancake */

#include "r_io.h"
#include "r_util.h"
#include <stdio.h>

R_LIB_VERSION (r_io);

// XXX: this is buggy. must use seek+read
#define USE_CACHE 1
#define USE_NEW_IO 0
#define DO_THE_IO_DBG 0
#define IO_IFDBG if (DO_THE_IO_DBG == 1)

static ut8 * r_io_desc_read (RIO *io, RIODesc * desc, ut64 *out_sz);
static RIO * r_io_bind_get_io(RIOBind *bnd);

R_API RIO *r_io_new() {
	RIO *io = R_NEW0 (RIO);
	if (!io) return NULL;
	io->buffer = r_cache_new (); // RCache is a list of ranged buffers. maybe rename?
	io->write_mask_fd = -1;
	io->printf = (void*) printf;
	io->bits = (sizeof(void*) == 8)? 64: 32;
	io->ff = 1;
	io->raised = -1;
	io->autofd = R_TRUE;
	r_io_map_init (io);
	r_io_desc_init (io);
	r_io_undo_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_section_init (io);
	return io;
}

R_API void r_io_raise(RIO *io, int fd) {
	io->raised = fd;
}

R_API int r_io_is_listener(RIO *io) {
	if (io && io->plugin && io->plugin->listener)
		return io->plugin->listener (io->desc);
	return R_FALSE;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW0 (RBuffer);
	b->buf = malloc (len);
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len<0)?0:len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API RIO *r_io_free(RIO *io) {
	struct list_head *pos, *n;
	if (!io) return NULL;
	/* TODO: properly free inner nfo */
	/* TODO: memory leaks */
	list_for_each_safe (pos, n, &io->io_list) {
		struct r_io_list_t *il = list_entry (pos, struct r_io_list_t, list);
		R_FREE (il->plugin);
		list_del (pos);
		R_FREE (il);
	}
	r_list_free (io->sections);
	r_list_free (io->maps);
	r_list_free (io->undo.w_list);
	r_cache_free (io->buffer);
	r_list_free (io->cache);
	r_io_desc_fini (io);
	free (io);
	return NULL;
}

/* used by uri handler plugins */
R_API int r_io_redirect(RIO *io, const char *file) {
	free (io->redirect);
	io->redirect = file? strdup (file): NULL;
	return 0;
}

R_API RIODesc *r_io_open_as(RIO *io, const char *urihandler, const char *file, int flags, int mode) {
	RIODesc *ret;
	char *uri;
	int urilen, hlen = strlen (urihandler);
	urilen = hlen + strlen (file)+5;
	uri = malloc (urilen);
	if (uri == NULL)
		return NULL;
	if (hlen>0) snprintf (uri, urilen, "%s://%s", urihandler, file);
	else strncpy (uri, file, urilen);
	ret = r_io_open_nomap (io, uri, flags, mode);
	free (uri);
	return ret;
}

static inline RIODesc *__getioplugin(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin;
	RIODesc *desc = NULL;
	char *uri = strdup (_uri);
	char *redir = NULL;
	for (;;) {
		plugin = r_io_plugin_resolve (io, uri, 0);
		if (plugin && plugin->open) {
			desc = plugin->open (io, uri, flags, mode);
			if (io->redirect) {
				redir = uri;
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
			if (desc) {
				if (desc->fd != -1)
					r_io_plugin_open (io, desc->fd, plugin);
				desc->uri = uri;
				//desc->name = strdup (uri);
				desc->referer = redir;
			}
		}
		break;
	}
	if (!desc) {
		plugin = r_io_plugin_get_default (io, uri, 0);
		desc = (plugin&&plugin->open) ? plugin->open (io, uri, flags, mode) : NULL;
		if (desc) {
			if (desc->fd != -1)
				r_io_plugin_open (io, desc->fd, plugin);
			desc->uri = uri;
		}
	}
	if (!desc) {
		free (uri);
		io->plugin = NULL;
	}
	return desc;
}

static inline RList *__getioplugin_many(RIO *io, const char *_uri, int flags, int mode) {
	RIOPlugin *plugin, *iop = NULL;
	RList *list_fds = NULL;
	RListIter *iter;
	RIODesc *desc;
	char *uri = strdup (_uri);
	for (;;) {
		// resolve
		plugin = r_io_plugin_resolve (io, uri, 1);
		if (plugin && plugin->open_many) {
			// open
			list_fds = plugin->open_many (io, uri, flags, mode);
			if (io->redirect) {
				free (uri);
				uri = strdup (io->redirect);
				r_io_redirect (io, NULL);
				continue;
			}
		}
		break;
	}

	if (!list_fds) {
		free (uri);
		return NULL;
	}

	r_list_foreach (list_fds, iter, desc) {
		if (desc)
			desc->uri = strdup (uri);
	}

	io->plugin = iop;
	free (uri);
	return list_fds;
}

R_API RIODesc *r_io_open_nomap(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	if (io->redirect)
		return NULL;
	desc = __getioplugin (io, file, flags, mode);
	IO_IFDBG {
		if (desc && desc->plugin)
			eprintf ("Opened file: %s with %s\n",
				file, desc->plugin->name);
	}
	if (desc) {
		r_io_desc_add (io, desc);
		if (io->autofd || !io->desc)
			r_io_use_desc (io, desc);
	} else eprintf ("r_io_open_nomap: Unable to open file: %s\n", file);

	return desc;
}

R_API RIODesc *r_io_open_at (RIO *io, const char *file, int flags, int mode, ut64 maddr) {
	RIODesc *desc;
	ut64 size;
	if (io->redirect)
		return NULL;
	desc = __getioplugin (io, file, flags, mode);
	IO_IFDBG {
		if (desc && desc->plugin)
			eprintf ("Opened file: %s with %s\n",
				file, desc->plugin->name);
	}
	if (desc) {
		r_io_desc_add (io, desc);
		size = r_io_desc_size (io, desc);
		if (io->autofd || !io->desc)
			r_io_use_desc (io, desc);
		r_io_map_new (io, desc->fd, mode, 0, maddr, size);
	} else	eprintf ("r_io_open_at: Unable to open file: %s\n", file);
	return desc;
}

R_API RIODesc *r_io_open (RIO *io, const char *file, int flags, int mode) {
	return r_io_open_at (io, file, flags, mode, 0LL);
}

R_API RList *r_io_open_many(RIO *io, const char *file, int flags, int mode) {
	RIODesc *desc;
	RListIter *desc_iter = NULL;
	int fd;
	RList *list_fds;
	if (io->redirect)
		return NULL;
	list_fds = __getioplugin_many (io, file, flags, mode);

	if (!list_fds)
		return NULL;

	r_list_foreach (list_fds, desc_iter, desc) {
		fd = -1;
		if (desc) fd = desc->fd;
		if (fd >= 0) r_io_desc_add (io, desc);
	}
	return list_fds;
}

R_API int r_io_reopen (RIO *io, RIODesc *desc, int flags, int mode) {
	RIODesc *n = NULL;
	RListIter *iter;
	RIOMap *map;
	if (desc && desc->uri && io && io->files && (desc == r_io_desc_get (io, desc->fd))) {
		n = __getioplugin (io, desc->uri, flags, mode);
		if (!n)
			return R_FALSE;
		r_io_section_rm_all (io, desc->fd);
		if (io->maps) {
			r_list_foreach (io->maps, iter, map) {
				if (map->fd == desc->fd) {
					map->fd = n->fd;
					map->flags &= n->flags;
				}
			}
		}
		if (desc->plugin && desc->plugin->close)
			desc->plugin->close (desc);		//free desc->data
		free (desc->name);
		free (desc->uri);
		*desc = *n;
		free (n);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_io_use_desc (RIO *io, RIODesc *d) {
	if (d) {
		io->desc = d;
		io->plugin = d->plugin;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API RIODesc *r_io_use_fd (RIO *io, int fd) {
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc) return NULL;
	io->desc = desc;
	io->plugin = desc->plugin;
	return desc;
}

R_API int r_io_read_internal(RIO *io, ut8 *buf, int len) {
	int bytes_read = 0;
	const char *read_from = NULL;
	if (io->desc && io->desc->plugin && io->desc->plugin->read){
		read_from = io->desc->plugin->name;
		bytes_read = io->desc->plugin->read (io, io->desc, buf, len);
	} else if (!io->desc) {
		if (io->files && r_list_length (io->files) != 0)
			eprintf ("Something really bad has happened, and r2 is going to die soon. sorry! :-(\n");
		read_from = "FAILED";
		bytes_read = 0;
	} else {
		read_from = "File";
		bytes_read = read (io->desc->fd, buf, len);
	}
	IO_IFDBG {
		if (io->desc) eprintf ("Data source: %s\n", io->desc->name);
		eprintf ("Asked for %d bytes, provided %d from %s\n",
			len, bytes_read, read_from);
	}
	return bytes_read;
}

R_API int r_io_read(RIO *io, ut8 *buf, int len) {
	int ret;
	if (io==NULL || io->desc == NULL)
		return -1;
	//if (io->off ==UT64_MAX) asm("int3");
	if (io->off==UT64_MAX)
		return -1;
	/* IGNORE check section permissions */
	if (io->enforce_rwx & R_IO_READ)
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_READ))
			return -1;
	ret = r_io_read_at (io, io->off, buf, len);
	if (ret>0) io->off += ret;
	return ret;
}

int r_io_read_cr (RIO *io, ut64 addr, ut8 *buf, int len) {
	RList *maps;
	RListIter *iter;
	RIOMap *map;
	if (!io)
		return R_FAIL;
	if (io->ff)
		memset (buf, 0xff, len);
	if (io->raw) {
		r_io_seek (io, addr, R_IO_SEEK_SET);
		return r_io_read_internal (io, buf, len);
	}
	if (io->va) {
		r_io_vread (io, addr, buf, len);			//must check return-stat
		if (io->cached)
			r_io_cache_read (io, addr, buf, len);
		return len;
	}
	maps = r_io_map_get_maps_in_range (io, addr, addr+len);
	r_list_foreach (maps, iter, map) {
		r_io_mread (io, map->fd, addr, buf, len);		//must check return-stat
	}
	r_io_mread (io, io->desc->fd, addr, buf, len);			//must check return-stat
	if (io->cached)
		r_io_cache_read (io, addr, buf, len);
	r_list_free(maps);
	return len;
}

R_API int r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
#if USE_NEW_IO
	return r_io_read_cr (io, addr, buf, len);
#else
	ut64 paddr, last, last2;
	int ms, ret, l = 0, olen = len, w = 0;

	if (io->sectonly && !r_list_empty (io->sections)) {
		if (!r_io_section_exists_for_vaddr (io, addr)) {
			// find next sec
			memset (buf, 0xff, len);
			ut64 next = r_io_section_next (io, addr);
			if (next < (addr+len)) {
				int delta = (next-addr);
				addr = next;
				len -= delta;
				buf += delta;
			} else next = 0;
			if (!next)
				return 0;
		}
	}

	if (io->raw) {
		if (r_io_seek (io, addr, R_IO_SEEK_SET)==UT64_MAX)
			memset (buf, 0xff, len);
		return r_io_read_internal (io, buf, len);
	}

	io->off = addr;
	memset (buf, 0xff, len); // probably unnecessary

	if (io->buffer_enabled)
		return r_io_buffer_read (io, addr, buf, len);
	while (len>0) {
		if ((addr+w)< ((addr+w)+len)) {

		// this code assumes that the IO backend knows
		// 1) the size of a loaded file and its offset into the r2 data space
		// 2) the sections with physical (offsets) and virtual addresses in r2 data space
		// Currently debuggers may not support registering these data spaces in r2 and this
		// may prevent "raw" access to locations in the data space for entities like debuggers.
		// Until that issue is resolved this code will be disabled.
		// step one does a section exist for the offset
		int exists = r_io_section_exists_for_paddr (io, addr+w) ||
		r_io_section_exists_for_vaddr (io, addr+w) ||
		r_io_map_exists_for_offset (io, addr+w);

		// XXX this is a break b/c external IO caller do not need to create
		// an IO Map (yet.), so the "checking existence of" only works if r_core_file
		// APIs are used to load files.
		if (!exists && r_io_map_count (io) > 0) {
			// XXX this will break if there is actually data at this location
			// or within UT64_MAX - len
			ut64 next_map_addr = UT64_MAX,
			     next_sec_addr = UT64_MAX;

			RIOMap *next_map = NULL;
			RIOSection * next_sec = NULL;
			// is there a map somewhere within the next range for
			// us to read from
			next_sec = r_io_section_get_first_in_vaddr_range (io, addr+w, addr+len+w);
			next_sec_addr = next_sec ? next_sec->offset : UT64_MAX;

			if (!next_sec) {
				next_map = r_io_map_get_first_map_in_range (io, addr+w, addr+len+w);
				next_map_addr = next_map ? next_map->from : UT64_MAX;
				if (len <= next_map_addr-addr) next_map_addr = UT64_MAX;
				else l = next_map_addr-addr;

			} else if (len <= next_map_addr-addr) {
				next_sec_addr = UT64_MAX;
			} else {
				if (addr > next_sec_addr) {
					/* avoid negative deltas */
					return olen;
				}
				l = next_sec_addr-addr;
			}

			if (!next_sec && !next_map) {
				// done
				return olen;
			}
			// want to capture monotonicity even when maps are 0 in length
			if (l==0) l++;
			w+= l;
			len -= l;
			continue;
		}

		last = r_io_section_next (io, addr+w);
		last2 = r_io_map_next (io, addr+w); // XXX: must use physical address
		if (last == (addr+w)) last = last2;
		//else if (last2<last) last = last2;
		l = (len > (last-addr+w))? (last-addr+w): len;
} else {
	// overflow //
	l = (UT64_MAX-addr)+1;

}
		if (l<1) l = len;
		 {
			if (addr != UT64_MAX)
				paddr = w? r_io_section_vaddr_to_offset (io, addr+w): addr;
			else paddr = 0;
			//if (!paddr || paddr==UT64_MAX)
			if (paddr==UT64_MAX)
				paddr = r_io_map_select (io, addr); // XXX
			if (paddr == UT64_MAX) {
				w +=l;
				len -= l;
				continue;
			}
			r_io_map_select (io, addr); // XXX
			if (len>0 && l>len) l = len;
			addr = paddr-w;
			if (r_io_seek (io, paddr, R_IO_SEEK_SET)==UT64_MAX) {
				memset (buf+w, 0xff, l);
			}
		 }
#if 0
		if (io->zeromap)
			if (!r_io_map_get (io, addr+w)) {
				if (addr==0||r_io_section_getv (io, addr+w)) {
					memset (buf+w, 0xff, l);
					return -1;
				}
			}
#endif
		// XXX is this necessary?
		ms = r_io_map_select (io, addr+w);
		ret = r_io_read_internal (io, buf+w, l);
		if (ret<1) {
			memset (buf+w, 0xff, l); // reading out of file
			ret = l;
		} else if (ret<l) {
			l = ret;
		}
#if USE_CACHE
		if (io->cached) {
			r_io_cache_read (io, addr+w, buf+w, len); //-w);
		} else if (r_list_length (io->maps) >1) {
			if (!io->debug && ms>0) {
				//eprintf ("FAIL MS=%d l=%d d=%d\n", ms, l, d);
				/* check if address is vaddred in sections */
				ut64 o = r_io_section_offset_to_vaddr (io, addr+w);
				if (o == UT64_MAX) {
					ut64 o = r_io_section_vaddr_to_offset (io, addr+w);
					if (o == UT64_MAX)
						memset (buf+w, 0xff, l);
				}
				break;
			}
		}
#endif
		w += l;
		len -= l;
/* Fix famous io/f bug */
#if 0
this is not a real fix, because it just avoids reading again , even if the seek returns error.
bear in mind that we need to fix that loop and honor lseek sections and sio maps fine
#endif
if (len>0) {
	memset (buf+w, 0xff, len);
}
//break;
	}
	return olen;
#endif
}

R_API ut64 r_io_read_i(RIO *io, ut64 addr, int sz, int endian) {
	ut64 ret = 0LL;
	ut8 buf[8];
	sz = R_DIM (sz, 1, 8);
	if (sz != r_io_read_at (io, addr, buf, sz))
		return UT64_MAX;
	r_mem_copyendian ((ut8*)&ret, buf, sz, endian);
	return ret;
}

// TODO. this is a physical resize
R_API int r_io_resize(RIO *io, ut64 newsize) {
	if (io->plugin) {
		if (io->plugin->resize) {
			int res = io->plugin->resize (io, io->desc, newsize);
			if (res)
				r_io_map_truncate_update (io, io->desc->fd, newsize);
			return res;
		}
		return R_FALSE;
	}
	return R_TRUE;
}

R_API int r_io_extend(RIO *io, ut64 size) {
	ut64 curr_off = io->off;
	ut64 cur_size = r_io_size (io), tmp_size = cur_size-size;
	ut8 *buffer = NULL;

	if (!size) return R_FALSE;

	if (io->plugin && io->plugin->extend)
		return io->plugin->extend (io, io->desc, size);

	if (!r_io_resize (io, size+cur_size)) return R_FALSE;

	if (cur_size < size) {
		tmp_size = size - cur_size;
	}

	buffer = malloc (tmp_size);
	// shift the bytes over by size
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_read (io, buffer, tmp_size);
	// move/write the bytes
	r_io_seek (io, curr_off+size, R_IO_SEEK_SET);
	r_io_write (io, buffer, tmp_size);
	// zero out new bytes
	if (cur_size < size) {
		free (buffer);
		buffer = malloc (size);
	}
	memset (buffer, 0, size);
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	r_io_write (io, buffer, size);
	// reset the cursor
	r_io_seek (io, curr_off, R_IO_SEEK_SET);
	free (buffer);
	return R_TRUE;
}

R_API int r_io_extend_at(RIO *io, ut64 addr, ut64 size) {
	if (!size) return R_FALSE;
	r_io_seek (io, addr, R_IO_SEEK_SET);
	return 	r_io_extend (io, size);
}

R_API int r_io_set_write_mask(RIO *io, const ut8 *buf, int len) {
	int ret = R_FALSE;
	if (len>0) {
		io->write_mask_fd = io->desc->fd;
		io->write_mask_buf = (ut8 *)malloc (len);
		memcpy (io->write_mask_buf, buf, len);
		io->write_mask_len = len;
		ret = R_TRUE;
	} else io->write_mask_fd = -1;
	return ret;
}

R_API int r_io_write(RIO *io, const ut8 *buf, int len) {
	int i, ret = -1;
	ut8 *data = NULL;

	/* check section permissions */
	if (io->enforce_rwx & R_IO_WRITE)
		if (!(r_io_section_get_rwx (io, io->off) & R_IO_WRITE))
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
		if (io->plugin->write) {
			ret = io->plugin->write (io, io->desc, buf, len);
		} else { 
			eprintf ("r_io_write: io handler with no write callback\n");
			ret = -1;
		}
	} else {
		ret = write (io->desc->fd, buf, len);
	}
	if (ret == -1) {
		if (io->cached != 2) {
			eprintf ("r_io_write: cannot write on fd %d\n", io->desc->fd);
			r_io_cache_invalidate (io, io->off, io->off+1);
		}
	} else {
		r_io_map_write_update (io, io->desc->fd, io->off, ret);
		io->off += ret;
	}
	free (data);
	return ret;
}

R_API int r_io_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	(void)r_io_seek (io, addr, R_IO_SEEK_SET);
	// errors on seek are checked and ignored here //
	return r_io_write (io, buf, len);
}

R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	// TODO: review the offset/vaddr/paddr/maddr thing here
	// now, io-seek always works with vaddr, because it depends on read/write ops that use it
	int posix_whence = SEEK_SET;
	ut64 ret = UT64_MAX;
	if (io == NULL)
		return ret;
	if (io->buffer_enabled) {
		io->off = offset;
		return offset;
	}
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
	if (io->desc != NULL) {
		if (io->plugin && io->plugin->lseek)
			ret = io->plugin->lseek (io, io->desc, offset, whence);
		// XXX can be problematic on w32..so no 64 bit offset?
		else ret = (ut64)lseek (io->desc->fd, offset, posix_whence);
		if (ret != UT64_MAX) {
			if (whence == R_IO_SEEK_SET)
				io->off = offset; // FIX linux-arm-32-bs at 0x10000
			else io->off = ret;
			// XXX this can be tricky.. better not to use this .. must be deprecated
			// r_io_sundo_push (io);
			ret = (!io->debug && io->va && !r_list_empty (io->sections))?
				r_io_section_offset_to_vaddr (io, io->off) : io->off;
		} //else eprintf ("r_io_seek: cannot seek to %"PFMT64x"\n", offset);
	} //else { eprintf ("r_io_seek: null fd\n"); }
	return ret;
}

R_API ut64 r_io_fd_size(RIO *io, int fd){
	RIODesc *desc = r_io_desc_get (io, fd);
	return r_io_desc_size (io, desc);
}

R_API int r_io_is_blockdevice (RIO *io) {
#if __UNIX__
	if (io && io->desc && io->desc->fd) {
		struct stat buf;
		if (fstat (io->desc->fd , &buf)==-1)
			return 0;
		if (io->plugin == &r_io_plugin_default) {
			// TODO: optimal blocksize = 2048 for disk, 4096 for files
			//eprintf ("OPtimal blocksize : %d\n", buf.st_blksize);
			return ((buf.st_mode & S_IFBLK) == S_IFBLK);
		}
	}
#endif
	return 0;
}

R_API ut64 r_io_size(RIO *io) {
	int oldva;
	ut64 size, here;
	if (!io) return 0LL;
	oldva = io->va;
	if (r_io_is_listener (io))
		return UT64_MAX;
	io->va = R_FALSE;
	here = r_io_seek (io, 0, R_IO_SEEK_CUR);
	size = r_io_seek (io, 0, R_IO_SEEK_END);
	if (r_io_seek (io, here, R_IO_SEEK_SET) != here) {
		eprintf("Failed to reset the file position\n");
	}
	io->va = oldva;
	if (size == 0 && r_io_is_blockdevice (io)) {
		io->va = 0;
		size = UT64_MAX;
	}
	return size;
}

R_API int r_io_system(RIO *io, const char *cmd) {
	int ret = -1;
	if (io->plugin && io->plugin->system)
		ret = io->plugin->system (io, io->desc, cmd);
	return ret;
}

R_API int r_io_close(RIO *io, RIODesc *d) {
	RIODesc *cur = NULL;
	if (io == NULL || d == NULL)
		return -1;
	if (d != io->desc)
		cur = io->desc;
	if (r_io_use_desc (io, d)) {
		int nfd = d->fd;
		RIODesc *desc = r_io_desc_get (io, nfd);
		if (desc) {
			r_io_map_del_all (io, nfd);
			r_io_section_rm_all (io, nfd);
			r_io_plugin_close (io, nfd, io->plugin);
			if (io->plugin && io->plugin->close)
				return io->plugin->close (desc);
			r_io_desc_del (io, desc->fd);
		}
	}
	io->desc = cur;
	return R_FALSE;
}

R_API int r_io_bind(RIO *io, RIOBind *bnd) {
	bnd->io = io;
	bnd->init = R_TRUE;
	bnd->get_io = r_io_bind_get_io;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->size = r_io_size;
	bnd->seek = r_io_seek;
	bnd->is_valid_offset = r_io_is_valid_offset;

	bnd->desc_open = r_io_open_nomap;
	bnd->desc_close = r_io_close;
	bnd->desc_read = r_io_desc_read;
	bnd->desc_size = r_io_desc_size;
	bnd->desc_seek = r_io_desc_seek;
	bnd->desc_get_by_fd = r_io_desc_get;

	bnd->section_add = r_io_section_add;

	bnd->section_set_arch = r_io_section_set_archbits;
	bnd->section_set_arch_bin_id = r_io_section_set_archbits_bin_id;

	return R_TRUE;
}

R_API int r_io_accept(RIO *io, int fd) {
	if (r_io_is_listener (io) && io->plugin && io->plugin->accept)
		return io->plugin->accept (io, io->desc, fd);
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
	return r_sandbox_creat (file, mode)? R_FALSE: R_TRUE;
}

R_API void r_io_sort_maps (RIO *io) {
	r_list_sort (io->maps, (RListComparator) r_io_map_sort);
}

// THIS IS pread.. a weird one
static ut8 * r_io_desc_read (RIO *io, RIODesc * desc, ut64 *out_sz) {
	ut8 *buf_bytes = NULL;
	ut64 off = 0;

	if (!io || !desc || !out_sz)
		return NULL;

	if (*out_sz == UT64_MAX)
		*out_sz = r_io_desc_size (io, desc);

	off = io->off;


	if (*out_sz == UT64_MAX) return buf_bytes;

	buf_bytes = malloc (*out_sz);

	if (desc->plugin && desc->plugin->read) {
		if (!buf_bytes || !desc->plugin->read (io, desc, buf_bytes, *out_sz)) {
			free (buf_bytes);
			io->off = off;
			return R_FALSE;
		}
	}
	io->off = off;
	return buf_bytes;
}

static RIO * r_io_bind_get_io(RIOBind *bnd) {
	return bnd ? bnd->io : NULL;
}

R_API void r_io_set_raw(RIO *io, int raw) {
	io->raw = raw?1:0;
}

//checks if reading at offset or writting to offset is reasonable
R_API int r_io_is_valid_offset (RIO *io, ut64 offset) {
	if (!io) {
		eprintf ("r_io_is_valid_offset: io is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	if (!io->files) {
		eprintf ("r_io_is_valid_offset: io->files is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	if (r_list_length (io->files) == 0)
		return R_FALSE;
	if (!io->desc) {
		eprintf ("r_io_is_valid_offset: io->desc is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	switch (io->va) {
		case 0:
			return (offset < r_io_size (io));
#if USE_NEW_IO
		case 1:
			return r_io_map_exists_for_offset (io, offset);
		case 2:
			return (r_io_map_exists_for_offset (io, offset) ||
				r_io_section_exists_for_vaddr (io, offset));
#else
		case 1:
			return (r_io_map_exists_for_offset (io, offset) ||
				r_io_section_exists_for_vaddr (io, offset));
#endif
	}
	eprintf ("r_io_is_valid_offset: io->va is %i\n", io->va);
	r_sys_backtrace ();
	return R_FAIL;
}
