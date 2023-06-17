/* radare2 - LGPL - Copyright 2008-2023 - condret, pancake, alvaro_fe */

#include <r_io.h>
#include <sdb/sdb.h>
#include <config.h>

R_LIB_VERSION (r_io);

R_API RIO* r_io_new(void) {
	RIO *io = R_NEW0 (RIO);
	r_io_init (io);
	return io;
}

R_API void r_io_init(RIO* io) {
	r_return_if_fail (io);
	io->addrbytes = 1;
	io->overlay = true;
	io->cb_printf = printf;
	r_io_desc_init (io);
	r_io_bank_init (io);
	r_io_map_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_undo_init (io);
	io->event = r_event_new (io);
	RIOBank *bank = r_io_bank_new ("default");
	if (bank) {
		io->bank = bank->id;
		r_io_bank_add (io, bank);
	}
}

R_API void r_io_free(RIO *io) {
	if (io) {
		r_io_fini (io);
		free (io);
	}
}

R_API RIODesc *r_io_open_buffer(RIO *io, RBuffer *b, int perm, int mode) {
	r_return_val_if_fail (io && b, NULL);
#if 0
	ut64 bufSize = r_buf_size (b);
	char *uri = r_str_newf ("malloc://%" PFMT64d, bufSize);
	RIODesc *desc = r_io_open_nomap (io, uri, perm, mode);
	if (desc) {
		const ut8 *tmp = r_buf_data (b, &bufSize);
		r_io_desc_write (desc, tmp, bufSize);
	}
	free (uri);
	return desc;
#else
	char *uri = r_str_newf ("rbuf://%p", b);
	RIODesc *desc = r_io_open_nomap (io, uri, perm, mode);
	free (uri);
	return desc;
#endif
}

R_API RIODesc *r_io_open_nomap(RIO *io, const char *uri, int perm, int mode) {
	r_return_val_if_fail (io && uri, NULL);
	RIODesc *desc = r_io_desc_open (io, uri, perm, mode);
	if ((io->autofd || !io->desc) && desc) {
		io->desc = desc;
	}
	//set desc as current if autofd or io->desc==NULL
	return desc;
}

/* opens a file and maps it to 0x0 */
R_API RIODesc* r_io_open(RIO* io, const char* uri, int perm, int mode) {
	r_return_val_if_fail (io, NULL);
	RIODesc* desc = r_io_open_nomap (io, uri, perm, mode);
	if (desc) {
		r_io_map_add (io, desc->fd, desc->perm, 0LL, 0LL, r_io_desc_size (desc));
	}
	return desc;
}

/* opens a file and maps it to an offset specified by the "at"-parameter */
R_API RIODesc* r_io_open_at(RIO* io, const char* uri, int perm, int mode, ut64 at) {
	r_return_val_if_fail (io && uri, NULL);

	RIODesc* desc = r_io_open_nomap (io, uri, perm, mode);
	if (!desc) {
		return NULL;
	}
	ut64 size = r_io_desc_size (desc);
#if 0
	// second map
	if (size && ((UT64_MAX - size + 1) < at)) {
		// split map into 2 maps if only 1 big map results into interger overflow
		r_io_map_add (io, desc->fd, desc->perm, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);
		// someone pls take a look at this confusing stuff
		size = UT64_MAX - at + 1;
	}
#endif
	r_io_map_add (io, desc->fd, desc->perm, 0LL, at, size);
	return desc;
}

/* opens many files, without mapping them. This should be discussed */
R_API RList* r_io_open_many(RIO* io, const char* uri, int perm, int mode) {
	RList* desc_list;
	RListIter* iter;
	RIODesc* desc;
	r_return_val_if_fail (io && io->files && uri, NULL);
	RIOPlugin* plugin = r_io_plugin_resolve (io, uri, 1);
	if (!plugin || !plugin->open_many || !plugin->close) {
		return NULL;
	}
	if (!(desc_list = plugin->open_many (io, uri, perm, mode))) {
		return NULL;
	}
	r_list_foreach (desc_list, iter, desc) {
		if (desc) {
			if (!desc->plugin) {
				desc->plugin = plugin;
			}
			if (!desc->uri) {
				desc->uri = strdup (uri);
			}
			//should autofd be honored here?
			r_io_desc_add (io, desc);
			if (!io->desc) {
				io->desc = desc;
			}
		}
	}
	// ensure no double free with r_list_close and r_io_free
	desc_list->free = NULL;
	return desc_list;
}

#if R2__WINDOWS__
R_API bool r_io_reopen(RIO* io, int fd, int perm, int mode) {
	RIODesc	*old, *new;
	char *uri;
	if (!(old = r_io_desc_get (io, fd))) {
		return false;
	}
	//does this really work, or do we have to handler debuggers ugly
	uri = old->referer? old->referer: old->uri;
	if (old->plugin->close && !old->plugin->close (old)) {
		return false; // TODO: this is an unrecoverable scenario
	}
	if (!(new = r_io_open_nomap (io, uri, perm, mode))) {
		return false;
	}
	r_io_desc_exchange (io, old->fd, new->fd);
	r_io_desc_del (io, old->fd);
	return true;
}
#else
R_API bool r_io_reopen(RIO* io, int fd, int perm, int mode) {
	RIODesc *od = r_io_desc_get (io, fd);
	if (!od) {
		return false;
	}
	const char *uri = od->referer? od->referer: od->uri;
	RIODesc *nd = r_io_open_nomap (io, uri, perm, mode);
	if (nd) {
		r_io_desc_exchange (io, od->fd, nd->fd);
		r_io_desc_close (od);
		if (nd->perm & R_PERM_W) {
			io->coreb.cmdf (io->coreb.core, "omfg");
		}
		return true;
	}
	R_LOG_ERROR ("Cannot reopen");
	return false;
}
#endif

R_API void r_io_close_all(RIO* io) {
	r_return_if_fail (io);
	r_io_desc_fini (io);
	r_io_map_fini (io);
	ls_free (io->plugins);
	r_io_desc_init (io);
	r_io_map_init (io);
	r_io_cache_reset (io);
	r_io_plugin_init (io);
}

R_API int r_io_pread_at(RIO* io, ut64 paddr, ut8* buf, int len) {
	r_return_val_if_fail (io && buf && len >= 0, -1);
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	return r_io_desc_read_at (io->desc, paddr, buf, len);
}

R_API int r_io_pwrite_at(RIO* io, ut64 paddr, const ut8* buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, -1);
	return r_io_desc_write_at (io->desc, paddr, buf, len);
}

// Returns true iff all reads on mapped regions are successful and complete.
R_API bool r_io_vread_at(RIO *io, ut64 vaddr, ut8* buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, false);
	if ((UT64_MAX - (len - 1)) < vaddr) {
		int _len = UT64_MAX - vaddr + 1;
		len -= _len;
		if (!r_io_vread_at (io, 0ULL, &buf[_len], len)) {
			return false;
		}
		len = _len;
	}
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	return r_io_bank_read_at (io, io->bank, vaddr, buf, len);
}

R_API bool r_io_vwrite_at(RIO *io, ut64 vaddr, const ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, false);
	if ((UT64_MAX - (len - 1)) < vaddr) {
		int _len = UT64_MAX - vaddr + 1;
		len -= _len;
		if (!r_io_vwrite_at (io, 0ULL, &buf[_len], len)) {
			return false;
		}
		len = _len;
	}
	return r_io_bank_write_at (io, io->bank, vaddr, buf, len);
}

R_API bool r_io_vwrite_to_overlay_at(RIO *io, ut64 vaddr, const ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, false);
	if ((UT64_MAX - (len - 1)) < vaddr) {
		int _len = UT64_MAX - vaddr + 1;
		len -= _len;
		if (!r_io_vwrite_to_overlay_at (io, 0ULL, &buf[_len], len)) {
			return false;
		}
		len = _len;
	}
	return r_io_bank_write_to_overlay_at (io, io->bank, vaddr, buf, len);
}

static bool internal_r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	if (len < 1) {
		return false;
	}
	bool ret = (io->va)
		? r_io_vread_at (io, addr, buf, len)
		: r_io_pread_at (io, addr, buf, len) > 0;
	// if (io->cache.mode & R_PERM_X && io->cache.mode & R_PERM_R)
	// read works even when io.cache=false, but io.cache.read=true
	if (io->cache.mode & R_PERM_R) {
		(void)r_io_cache_read_at (io, addr, buf, len);
	}
	return ret;
}

// For virtual mode, returns true if all reads on mapped regions are successful
// and complete.
// For physical mode, the interface is broken because the actual read bytes are
// not available. This requires fixes in all call sites.
R_API bool r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && len >= 0, false);
	if (len == 0) {
		return false;
	}
	if (io->mask) {
		ut64 p = addr;
		size_t q = 0;
		while (q < len) {
			p &= io->mask;
			size_t sz = io->mask - p + 1;
			size_t left = len - q;
			if (sz > left) {
				sz = left;
			}
			if (!internal_r_io_read_at (io, p, buf + q, sz)) {
				return false;
			}
			q += sz;
			p = 0;
		}
		return true;
	}
	return internal_r_io_read_at (io, addr, buf, len);
}

// For both virtual and physical mode, returns the number of bytes of read
// prefix.
// Returns -1 on error.
R_API int r_io_nread_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	int ret;
	r_return_val_if_fail (io && buf && len >= 0, -1);
	if (len == 0) {
		return 0;
	}
	if (io->va) {
		if (io->ff) {
			memset (buf, io->Oxff, len);
		}
		r_io_bank_drain (io, io->bank);
		ret = r_io_bank_read_from_submap_at (io, io->bank, addr, buf, len);
	} else {
		ret = r_io_pread_at (io, addr, buf, len);
	}
	if (ret > 0 && io->cache.mode & R_PERM_R) {
		(void)r_io_cache_read_at (io, addr, buf, len);
	}
	return ret;
}

R_API bool r_io_write_at(RIO* io, ut64 addr, const ut8* buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, false);
	bool ret = false;
	ut8 *mybuf = (ut8*)buf;
	if (io->write_mask) {
		mybuf = r_mem_dup ((void*)buf, len);
		int i;
		for (i = 0; i < len; i++) {
			// this sucks
			mybuf[i] &= io->write_mask[i % io->write_mask_len];
		}
	}
	if ((io->cache.mode & R_PERM_X) == R_PERM_X) {
		if (io->cache.mode & R_PERM_W) {
			ret = r_io_cache_write_at (io, addr, mybuf, len);
		} else {
			R_LOG_ERROR ("enable io.cache.write");
		}
	} else {
		if (io->va) {
			ret = r_io_vwrite_at (io, addr, mybuf, len);
		} else {
			ret = r_io_pwrite_at (io, addr, mybuf, len) > 0; // == len;
		}
	}
	if (buf != mybuf) {
		free (mybuf);
	}
	return ret;
}

R_API bool r_io_read(RIO* io, ut8* buf, int len) {
	if (io && r_io_read_at (io, io->off, buf, len)) {
		io->off += len;
		return true;
	}
	return false;
}

R_API bool r_io_write(RIO* io, ut8* buf, int len) {
	if (io && buf && len > 0 && r_io_write_at (io, io->off, buf, len)) {
		io->off += len;
		return true;
	}
	return false;
}

R_API ut64 r_io_size(RIO* io) {
// TODO: rethink this, maybe not needed
	return io? r_io_desc_size (io->desc): 0LL;
}

R_API bool r_io_is_listener(RIO* io) {
	if (io && io->desc && io->desc->plugin && io->desc->plugin->listener) {
		return io->desc->plugin->listener (io->desc);
	}
	return false;
}

R_API char *r_io_system(RIO* io, const char* cmd) {
	if (io && io->desc) {
		return r_io_desc_system (io->desc, cmd);
	}
	return NULL;
}

R_API bool r_io_resize(RIO* io, ut64 newsize) {
	if (io) {
		RList *maps = r_io_map_get_by_fd (io, io->desc->fd);
		RIOMap *current_map;
		RListIter *iter;
		ut64 fd_size = r_io_fd_size (io, io->desc->fd);
		const bool ret = r_io_desc_resize (io->desc, newsize);
		r_list_foreach (maps, iter, current_map) {
			// we just resize map of the same size of its fd
			if (r_io_map_size (current_map) == fd_size) {
				r_io_map_resize (io, current_map->id, newsize);
			}
		}
		r_list_free (maps);
		return ret;
	}
	return false;
}

R_API bool r_io_close(RIO *io) {
	return io ? r_io_desc_close (io->desc) : false;
}

R_API int r_io_extend_at(RIO* io, ut64 addr, ut64 size) {
	ut64 cur_size, tmp_size;
	ut8* buffer;
	if (!io || !io->desc || !io->desc->plugin || !size) {
		return false;
	}
	if (io->desc->plugin->extend) {
		int ret;
		ut64 cur_off = io->off;
		r_io_seek (io, addr, R_IO_SEEK_SET);
		ret = r_io_desc_extend (io->desc, size);
		//no need to seek here
		io->off = cur_off;
		return ret;
	}
	if ((io->desc->perm & R_PERM_RW) != R_PERM_RW) {
		return false;
	}
	cur_size = r_io_desc_size (io->desc);
	if (addr > cur_size) {
		return false;
	}
	if ((UT64_MAX - size) < cur_size) {
		return false;
	}
	if (!r_io_resize (io, cur_size + size)) {
		return false;
	}
	if ((tmp_size = cur_size - addr) == 0LL) {
		return true;
	}
	if (!(buffer = calloc (1, (size_t) tmp_size + 1))) {
		return false;
	}
	r_io_pread_at (io, addr, buffer, (int) tmp_size);
	/* fill with null bytes */
	ut8 *empty = calloc (1, size);
	if (empty) {
		r_io_pwrite_at (io, addr, empty, size);
		free (empty);
	}
	r_io_pwrite_at (io, addr + size, buffer, (int) tmp_size);
	free (buffer);
	return true;
}

R_API bool r_io_set_write_mask(RIO* io, const ut8* mask, int len) {
	if (!io || len < 1) {
		return false;
	}
	free (io->write_mask);
	if (!mask) {
		io->write_mask = NULL;
		io->write_mask_len = 0;
		return true;
	}
	io->write_mask = (ut8*) malloc (len);
	memcpy (io->write_mask, mask, len);
	io->write_mask_len = len;
	return true;
}

R_API ut64 r_io_p2v(RIO *io, ut64 pa) {
	RIOMap *map = r_io_map_get_paddr (io, pa);
	if (map) {
		return pa - map->delta + r_io_map_begin (map);
	}
	return UT64_MAX;
}

R_API ut64 r_io_v2p(RIO *io, ut64 va) {
	RIOMap *map = r_io_map_get_at (io, va);
	if (map) {
		st64 delta = va - r_io_map_begin (map);
		return r_io_map_begin (map) + map->delta + delta;
	}
	return UT64_MAX;
}

R_API void r_io_bind(RIO *io, RIOBind *bnd) {
	r_return_if_fail (io && bnd);

	bnd->io = io;
	bnd->init = true;
	bnd->desc_use = r_io_use_fd;
	bnd->desc_get = r_io_desc_get;
	bnd->desc_size = r_io_desc_size;
	bnd->p2v = r_io_p2v;
	bnd->v2p = r_io_v2p;
	bnd->open = r_io_open_nomap;
	bnd->open_at = r_io_open_at;
	bnd->close = r_io_fd_close;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->overlay_write_at = r_io_vwrite_to_overlay_at;
	bnd->system = r_io_system;
	bnd->fd_open = r_io_fd_open;
	bnd->fd_close = r_io_fd_close;
	bnd->fd_seek = r_io_fd_seek;
	bnd->fd_size = r_io_fd_size;
	bnd->fd_resize = r_io_fd_resize;
	bnd->fd_read = r_io_fd_read;
	bnd->fd_write = r_io_fd_write;
	bnd->fd_read_at = r_io_fd_read_at;
	bnd->fd_write_at = r_io_fd_write_at;
	bnd->fd_is_dbg = r_io_fd_is_dbg;
	bnd->fd_get_name = r_io_fd_get_name;
	bnd->fd_get_map = r_io_map_get_by_fd;
	bnd->fd_remap = r_io_map_remap_fd;
	bnd->is_valid_offset = r_io_is_valid_offset;
	bnd->bank_get = r_io_bank_get;
	bnd->map_get = r_io_map_get;
	bnd->map_get_at = r_io_map_get_at;
	bnd->map_get_paddr = r_io_map_get_paddr;
	bnd->addr_is_mapped = r_io_addr_is_mapped;
	bnd->map_add = r_io_map_add;
#if HAVE_PTRACE
	bnd->ptrace = r_io_ptrace;
	bnd->ptrace_func = r_io_ptrace_func;
#endif
}

/* moves bytes up (+) or down (-) within the specified range */
R_API bool r_io_shift(RIO* io, ut64 start, ut64 end, st64 move) {
	ut8* buf;
	ut64 chunksize = 0x10000;
	ut64 saved_off = io->off;
	ut64 src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end - start) <= shiftsize) {
		return false;
	}
	ut64 rest = (end - start) - shiftsize;
	if (!(buf = calloc (1, chunksize + 1))) {
		return false;
	}
	if (move > 0) {
		src = end - shiftsize;
	} else {
		src = start + shiftsize;
	}
	while (rest > 0) {
		if (chunksize > rest) {
			chunksize = rest;
		}
		if (move > 0) {
			src -= chunksize;
		}
		r_io_read_at (io, src, buf, chunksize);
		r_io_write_at (io, src + move, buf, chunksize);
		if (move < 0) {
			src += chunksize;
		}
		rest -= chunksize;
	}
	free (buf);
	io->off = r_io_desc_seek (io->desc, saved_off, R_IO_SEEK_SET);
	return true;
}

R_API ut64 r_io_seek(RIO *io, ut64 offset, int whence) {
	if (!io) {
		return 0LL;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
	default:
		io->off = r_io_desc_seek (io->desc, offset, whence);
		break;
	}
	return io->off;
}

static bool drain_cb (void *user, void *data, ut32 id) {
	r_io_map_drain_overlay ((RIOMap *)data);
	return true;
}

R_API void r_io_drain_overlay(RIO *io) {
	r_id_storage_foreach (io->maps, drain_cb, NULL);
}

R_API bool r_io_get_region_at(RIO *io, RIORegion *region, ut64 addr) {
	r_return_val_if_fail (io && region, false);
	if (!io->va) {
		if (io->desc) {
			region->perm = io->desc->perm;
			region->itv.addr = 0ULL;
			region->itv.size = r_io_desc_size (io->desc);
			return addr < region->itv.size;
		}
		return false;
	}
	return r_io_bank_get_region_at (io, io->bank, region, addr);
}

#if HAVE_PTRACE

#if USE_PTRACE_WRAP
#include <ptrace_wrap.h>
#include <errno.h>

static ptrace_wrap_instance *io_ptrace_wrap_instance(RIO *io) {
	if (!io->ptrace_wrap) {
		io->ptrace_wrap = R_NEW (ptrace_wrap_instance);
		if (!io->ptrace_wrap) {
			return NULL;
		}
		if (ptrace_wrap_instance_start (io->ptrace_wrap) < 0) {
			R_FREE (io->ptrace_wrap);
			return NULL;
		}
	}
	return io->ptrace_wrap;
}
#endif

R_API long r_io_ptrace(RIO *io, r_ptrace_request_t request, pid_t pid, void *addr, r_ptrace_data_t data) {
#if USE_PTRACE_WRAP
	if (io->want_ptrace_wrap) {
		ptrace_wrap_instance *wrap = io_ptrace_wrap_instance (io);
		if (!wrap) {
			errno = 0;
			return -1;
		}
		return ptrace_wrap (wrap, request, pid, addr, (void*)(size_t)data);
	}
#endif
	return ptrace (request, pid, addr, (size_t)data);
}

R_API pid_t r_io_ptrace_fork(RIO *io, void(*child_callback)(void *), void *child_callback_user) {
#if USE_PTRACE_WRAP
	if (io->want_ptrace_wrap) {
		ptrace_wrap_instance *wrap = io_ptrace_wrap_instance (io);
		if (!wrap) {
			errno = 0;
			return -1;
		}
		return ptrace_wrap_fork (wrap, child_callback, child_callback_user);
	}
#endif
	pid_t r = r_sys_fork ();
	if (r == 0) {
		child_callback (child_callback_user);
	}
	return r;
}

R_API void *r_io_ptrace_func(RIO *io, void *(*func)(void *), void *user) {
#if USE_PTRACE_WRAP
	ptrace_wrap_instance *wrap = io_ptrace_wrap_instance (io);
	if (wrap) {
		return ptrace_wrap_func (wrap, func, user);
	}
#endif
	return func (user);
}
#endif

R_API void r_io_fini(RIO* io) {
	r_return_if_fail (io);
	r_io_bank_fini (io);
	r_io_map_fini (io);
	r_io_desc_cache_fini_all (io);
	r_io_desc_fini (io);
	ls_free (io->plugins);
	r_io_cache_fini (io);
	r_list_free (io->undo.w_list);
	R_FREE (io->runprofile);
	r_event_free (io->event);
#if R_IO_USE_PTRACE_WRAP
	if (io->ptrace_wrap) {
		ptrace_wrap_instance_stop (io->ptrace_wrap);
		free (io->ptrace_wrap);
	}
#endif
}
