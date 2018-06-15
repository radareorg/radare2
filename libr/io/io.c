/* radare2 - LGPL - Copyright 2008-2018 - condret, pancake, alvaro_fe */

#include <r_io.h>
#include <sdb.h>
#include <config.h>

R_LIB_VERSION (r_io);

static int fd_read_at_wrap (RIO *io, int fd, ut64 addr, ut8 *buf, int len, RIOMap *map, void *user) {
	return r_io_fd_read_at (io, fd, addr, buf, len);
}

static int fd_write_at_wrap (RIO *io, int fd, ut64 addr, ut8 *buf, int len, RIOMap *map, void *user) {
	return r_io_fd_write_at (io, fd, addr, buf, len);
}

static int al_fd_read_at_wrap (RIO *io, int fd, ut64 addr, ut8 *buf, int len, RIOMap *map, void *user) {
	RIOAccessLog *log = (RIOAccessLog *)user;
	RIOAccessLogElement *ale = R_NEW0 (RIOAccessLogElement);
	int rlen = r_io_fd_read_at (io, fd, addr, buf, len);
	if (ale) {
		ale->expect_len = len;
		ale->len = rlen;
		ale->buf_idx = (int)(size_t)(buf - log->buf);
		ale->flags = map->flags;
		ale->fd = fd;
		ale->mapid = map->id;
		ale->paddr = addr;
		ale->vaddr = map->itv.addr + (addr - map->delta);
		r_list_append (log->log, ale);
	} else {
		log->allocation_failed = true;
	}
	return rlen;
}

static int al_fd_write_at_wrap (RIO *io, int fd, ut64 addr, ut8 *buf, int len, RIOMap *map, void *user) {
	RIOAccessLog *log = (RIOAccessLog *)user;
	RIOAccessLogElement *ale = R_NEW0 (RIOAccessLogElement);
	int rlen = r_io_fd_write_at (io, fd, addr, buf, len);
	if (ale) {
		ale->expect_len = len;
		ale->len = rlen;
		ale->buf_idx = (int)(size_t)(buf - log->buf);
		ale->flags = map->flags;
		ale->fd = fd;
		ale->mapid = map->id;
		ale->paddr = addr;
		ale->vaddr = map->itv.addr + (addr - map->delta);
		r_list_append (log->log, ale);
	} else {
		log->allocation_failed = true;
	}
	return rlen;
}

typedef int (*cbOnSubMap)(RIO *io, int fd, ut64 addr, ut8 *buf, int len, RIOMap *map, void *user);

static bool _submap_find_cb(void *vin, void *vincoming, void *user, int *cmp_res) {
	RIOSubMap *sm = (RIOSubMap *)vin;
	ut64 *off = (ut64 *)vincoming;

	if (off[0] < sm->from) {
		cmp_res[0] = 1;
		goto beach;
	}
	if (off[0] > sm->to) {
		cmp_res[0] = -1;
		goto beach;
	}
	cmp_res[0] = 0;
beach:
	return true;
}

static bool operateOnSubMap(RIO *io, ut64 vaddr, ut8 *buf, int len, int match_flg, cbOnSubMap op, void *user) {
	ut8 *ptr;
	ut32 od;
	ut64 vend, paddr;
	RIOMap *map;
	RIOSubMap *sm;
	if ((len < 1) || !io || !io->maps || !io->submaps || !op || !buf) {
		return false;
	}
	vend = vaddr + len - 1;
	io->submaps->cmp = _submap_find_cb;
	od = r_oids_find(io->submaps, &vaddr, NULL);
	while ((sm = r_oids_oget(io->submaps, od)) && sm->from <= vend) {
		map = r_oids_get (io->maps, sm->id);
		if (!map || (((map->flags & match_flg) != match_flg) && !io->p_cache)) {
			od++;
			continue;
		}
		len = R_MIN(sm->to, vend) - R_MAX(sm->from, vaddr) + 1;
		if (sm->from > vaddr) {
			ptr = buf + (sm->from - vaddr);
		} else {
			ptr = buf;
		}
		paddr = map->delta + R_MAX (sm->from, vaddr) - map->itv.addr;
		op (io, map->fd, paddr, ptr, len, map, user);
		od++;
	}
	return true;
}

static bool operateOnSubMap_wrap(RIO *io, ut64 vaddr, ut8 *buf,
		int len, int match_flg, cbOnSubMap op, void *user) {
	if (!len) {
		return true;
	}
	bool ret = true;
	// vaddr + len > 2**64
	if (vaddr > UT64_MAX - len + 1) {
		ret = operateOnSubMap (io, 0, buf - vaddr, len + vaddr, match_flg, op, user);
		len = -vaddr;
	}
	if (ret) {
		ret = operateOnSubMap (io, vaddr, buf, len, match_flg, op, user);
	}
	return ret;
}

R_API RIO* r_io_new() {
	return r_io_init (R_NEW0 (RIO));
}

R_API RIO* r_io_init(RIO* io) {
	if (!io) {
		return NULL;
	}
	io->addrbytes = 1;
	r_io_desc_init (io);
	r_io_map_init (io);
	r_io_section_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_undo_init (io);
	return io;
}

R_API RBuffer *r_io_read_buf(RIO *io, ut64 addr, int len) {
	RBuffer *b = R_NEW0 (RBuffer);
	if (!b) return NULL;
	b->buf = malloc (len);
	if (!b->buf) {
		free (b);
		return NULL;
	}
	len = r_io_read_at (io, addr, b->buf, len);
	b->length = (len < 0)? 0: len;
	return b;
}

R_API int r_io_write_buf(RIO *io, struct r_buf_t *b) {
	return r_io_write_at (io, b->base, b->buf, b->length);
}

R_API void r_io_free(RIO *io) {
	if (!io) {
		return;
	}
	r_io_fini (io);
	r_cache_free (io->buffer);
	free (io);
}

R_API RIODesc *r_io_open_buffer(RIO *io, RBuffer *b, int flags, int mode) {
	const int bufSize = r_buf_size (b);
	char *uri = r_str_newf ("malloc://%d", bufSize);
	RIODesc *desc = r_io_open_nomap (io, uri, flags, mode);
	if (desc) {
		r_io_desc_write (desc, r_buf_get_at(b, 0, NULL), bufSize);
	}
	return desc;
}

R_API RIODesc *r_io_open_nomap(RIO *io, const char *uri, int flags, int mode) {
	RIODesc *desc;
	if (!io) {
		return NULL;
	}
	desc = r_io_desc_open (io, uri, flags, mode);
	if ((io->autofd || !io->desc) && desc) {
		io->desc = desc;
	}
	//set desc as current if autofd or io->desc==NULL
	return desc;
}

/* opens a file and maps it to 0x0 */
R_API RIODesc* r_io_open(RIO* io, const char* uri, int flags, int mode) {
	RIODesc* desc;
	if (!io || !io->maps) {
		return NULL;
	}
	desc = r_io_open_nomap (io, uri, flags, mode);
	if (!desc) {
		return NULL;
	}
	r_io_map_new (io, desc->fd, desc->flags, 0LL, 0LL, r_io_desc_size (desc));
	return desc;
}

/* opens a file and maps it to an offset specified by the "at"-parameter */
R_API RIODesc* r_io_open_at(RIO* io, const char* uri, int flags, int mode, ut64 at) {
	RIODesc* desc;
	ut64 size;
	if (!io || !io->maps) {
		return NULL;
	}
	desc = r_io_open_nomap (io, uri, flags, mode);
	if (!desc) {
		return NULL;
	}
	size = r_io_desc_size (desc);
	// second map
	if (size && ((UT64_MAX - size + 1) < at)) {
		// split map into 2 maps if only 1 big map results into interger overflow
		r_io_map_new (io, desc->fd, desc->flags, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);
		// someone pls take a look at this confusing stuff
		size = UT64_MAX - at + 1;
	}
	r_io_map_new (io, desc->fd, desc->flags, 0LL, at, size);
	return desc;
}

/* opens many files, without mapping them. This should be discussed */
R_API RList* r_io_open_many(RIO* io, const char* uri, int flags, int mode) {
	RList* desc_list;
	RListIter* iter;
	RIODesc* desc;
	if (!io || !io->files || !uri) {
		return NULL;
	}
	RIOPlugin* plugin = r_io_plugin_resolve (io, uri, 1);
	if (!plugin || !plugin->open_many || !plugin->close) {
		return NULL;
	}
	if (!(desc_list = plugin->open_many (io, uri, flags, mode))) {
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
	return desc_list;
}

R_API bool r_io_reopen(RIO* io, int fd, int flags, int mode) {
	RIODesc	*old, *new;
	char *uri;
	if (!(old = r_io_desc_get (io, fd))) {
		return false;
	}
	//does this really work, or do we have to handler debuggers ugly
	uri = old->referer? old->referer: old->uri;
#if __WINDOWS__ //TODO: workaround, see https://github.com/radare/radare2/issues/8840
	if (!r_io_desc_close (old)) {
		return false; // TODO: this is an unrecoverable scenario
	}
	if (!(new = r_io_open_nomap (io, uri, flags, mode))) {
		return false;
	}
	r_io_desc_exchange (io, old->fd, new->fd);
	return true;
#else
	if (!(new = r_io_open_nomap (io, uri, flags, mode))) {
		return false;
	}
	r_io_desc_exchange (io, old->fd, new->fd);
	return r_io_desc_close (old); // magic
#endif // __WINDOWS__
}

R_API int r_io_close_all(RIO* io) { // what about undo?
	if (!io) {
		return false;
	}
	r_io_desc_fini (io);
	r_io_map_fini (io);
	r_io_section_fini (io);
	ls_free (io->plugins);
	r_list_free (io->cache);
	r_io_desc_init (io);
	r_io_map_init (io);
	r_io_section_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	return true;
}

R_API int r_io_pread_at(RIO* io, ut64 paddr, ut8* buf, int len) {
	if (!io || !buf || len < 1) {
		return 0;
	}
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	return r_io_desc_read_at (io->desc, paddr, buf, len);
}

R_API int r_io_pwrite_at(RIO* io, ut64 paddr, const ut8* buf, int len) {
	if (!io) {
		return 0;
	}
	return r_io_desc_write_at (io->desc, paddr, buf, len);
}

// Returns true iff all reads on mapped regions are successful and complete.
R_API bool r_io_vread_at(RIO* io, ut64 vaddr, ut8* buf, int len) {
	if (!io || !buf || (len < 1)) {
		return false;
	}
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	r_io_map_cleanup (io);
	if (!io->maps) {
		return false;
	}
	return operateOnSubMap_wrap (io, vaddr, buf, len, R_IO_READ, fd_read_at_wrap, NULL);
}

R_API bool r_io_vwrite_at(RIO* io, ut64 vaddr, const ut8* buf, int len) {
	if (!io || !buf || (len < 1)) {
		return false;
	}
	r_io_map_cleanup (io);
	if (!io->maps) {
		return false;
	}
	return operateOnSubMap_wrap (io, vaddr, (ut8*)buf, len, R_IO_WRITE, fd_write_at_wrap, NULL);
}

R_API RIOAccessLog *r_io_al_vread_at(RIO* io, ut64 vaddr, ut8* buf, int len) {
	RIOAccessLog *log;
	if (!io || !buf || (len < 1)) {
		return NULL;
	}
	r_io_map_cleanup (io);
	if (!io->maps || !(log = r_io_accesslog_new ())) {
		return NULL;
	}
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	log->buf = buf;
	operateOnSubMap_wrap (io, vaddr, buf, len, R_IO_READ, al_fd_read_at_wrap, log);
	return log;
}

R_API RIOAccessLog *r_io_al_vwrite_at(RIO* io, ut64 vaddr, const ut8* buf, int len) {
	RIOAccessLog *log;
	if (!io || !buf || (len < 1)) {
		return NULL;
	}
	r_io_map_cleanup (io);
	if (!io->maps || !(log = r_io_accesslog_new ())) {
		return NULL;
	}
	log->buf = (ut8*)buf;
	operateOnSubMap_wrap (io, vaddr, (ut8*)buf, len, R_IO_WRITE, al_fd_write_at_wrap, log);
	return log;
}

R_API bool r_io_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	bool ret;
	if (!io || !buf || len < 1) {
		return false;
	}
	if (io->buffer_enabled) {
		return !!r_io_buffer_read(io, addr, buf, len);
	}
	if (io->va) {
		ret = r_io_vread_at(io, addr, buf, len);
	} else {
		ret = r_io_pread_at(io, addr, buf, len) > 0;
	}
	if (io->cached & R_IO_READ) {
		(void)r_io_cache_read(io, addr, buf, len);
	}
	return ret;
}

R_API RIOAccessLog *r_io_al_read_at(RIO* io, ut64 addr, ut8* buf, int len) {
	RIOAccessLog *log;
	RIOAccessLogElement *ale = NULL;
	int rlen;
	if (!io || !buf || (len < 1)) {
		return NULL;
	}
	if (io->va) {
		return r_io_al_vread_at (io, addr, buf, len);
	}
	if (!(log = r_io_accesslog_new ())) {
		return NULL;
	}
	log->buf = buf;
	if (io->ff) {
		memset (buf, io->Oxff, len);
	}
	rlen = r_io_pread_at (io, addr, buf, len);
	if (io->cached & R_IO_READ) {
		(void)r_io_cache_read (io, addr, buf, len);
	}
	if (!(ale = R_NEW0 (RIOAccessLogElement))) {
		log->allocation_failed = true;
	} else {
		ale->paddr = ale->vaddr = addr;
		ale->len = rlen;
		ale->expect_len = len;
		ale->flags = io->desc ? io->desc->flags : 0;
		ale->fd = io->desc ? io->desc->fd : 0;		//xxx
		r_list_append (log->log, ale);
	}
	return log;
}

R_API bool r_io_write_at(RIO* io, ut64 addr, const ut8* buf, int len) {
	int i;
	bool ret = false;
	ut8 *mybuf = (ut8*)buf;
	if (!io || !buf || len < 1) {
		return false;
	}
	if (io->write_mask) {
		mybuf = r_mem_dup ((void*)buf, len);
		for (i = 0; i < len; i++) {
			//this sucks
			mybuf[i] &= io->write_mask[i % io->write_mask_len];
		}
	}
	if (io->cached & R_IO_WRITE) {
		ret = r_io_cache_write (io, addr, mybuf, len);
	} else if (io->va) {
		ret = r_io_vwrite_at (io, addr, mybuf, len);
	} else {
		ret = r_io_pwrite_at (io, addr, mybuf, len) > 0;
	}
	if (buf != mybuf) {
		free (mybuf);
	}
	return ret;
}

R_API bool r_io_read(RIO* io, ut8* buf, int len) {
	if (!io) {
		return false;
	}
	if (r_io_read_at (io, io->off, buf, len)) {
		io->off += len;
		return true;
	}
	return false;
}

R_API bool r_io_write(RIO* io, ut8* buf, int len) {
	if (!io || !buf || len < 1) {
		return false;
	}
	if (r_io_write_at (io, io->off, buf, len)) {
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
	if (io && io->desc && io->desc->plugin && io->desc->plugin->system) {
		return io->desc->plugin->system (io, io->desc, cmd);
	}
	return NULL;
}

R_API bool r_io_resize(RIO* io, ut64 newsize) {
	if (io) {
		RList *maps = r_io_map_get_for_fd (io, io->desc->fd);
		RIOMap *current_map;
		RListIter *iter;
		ut64 fd_size = r_io_fd_size (io, io->desc->fd);
		r_list_foreach (maps, iter, current_map) {
			// we just resize map of the same size of its fd
			if (current_map->itv.size == fd_size) {
				r_io_map_resize (io, current_map->id, newsize);
			}
		}
		r_list_free (maps);
		return r_io_desc_resize (io->desc, newsize);
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
	if ((io->desc->flags & R_IO_RW) != R_IO_RW) {
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

R_API int r_io_bind(RIO* io, RIOBind* bnd) {
	if (!io || !bnd) {
		return false;
	}
	bnd->io = io;
	bnd->init = true;
	bnd->desc_use = r_io_use_fd;
	bnd->desc_get = r_io_desc_get;
	bnd->desc_size = r_io_desc_size;
	bnd->open = r_io_open_nomap;
	bnd->open_at = r_io_open_at;
	bnd->close = r_io_fd_close;
	bnd->read_at = r_io_read_at;
	bnd->al_read_at = r_io_al_read_at;
	bnd->write_at = r_io_write_at;
	bnd->system = r_io_system;
	bnd->fd_open = r_io_fd_open;
	bnd->fd_close = r_io_fd_close;
	bnd->fd_seek = r_io_fd_seek;
	bnd->fd_size = r_io_fd_size;
	bnd->fd_read = r_io_fd_read;
	bnd->fd_write = r_io_fd_write;
	bnd->fd_read_at = r_io_fd_read_at;
	bnd->fd_write_at = r_io_fd_write_at;
	bnd->fd_is_dbg = r_io_fd_is_dbg;
	bnd->fd_get_name = r_io_fd_get_name;
	bnd->fd_get_map = r_io_map_get_for_fd;
	bnd->fd_remap = r_io_map_remap_fd;
	bnd->al_sort = r_io_accesslog_sort;
	bnd->al_free = r_io_accesslog_free;
	bnd->al_buf_byflags = r_io_accesslog_getf_buf_byflags;
	bnd->is_valid_offset = r_io_is_valid_offset;
	bnd->addr_is_mapped = r_io_addr_is_mapped;
	bnd->sections_vget = r_io_sections_vget;
	bnd->section_add = r_io_section_add;
	bnd->sect_vget = r_io_section_vget;
	return true;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift(RIO* io, ut64 start, ut64 end, st64 move) {
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

R_API int r_io_create(RIO* io, const char* file, int mode, int type) {
	if (io && io->desc && io->desc->plugin && io->desc->plugin->create) {
		return io->desc->plugin->create (io, file, mode, type);
	}
	if (type == 'd' || type == 1) {
		return r_sys_mkdir (file);
	}
	return r_sandbox_creat (file, mode);
}

R_API ut64 r_io_seek(RIO* io, ut64 offset, int whence) {
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

//remove all descs and maps
R_API int r_io_fini(RIO* io) {
	if (!io) {
		return false;
	}
	r_io_desc_cache_fini_all (io);
	r_io_desc_fini (io);
	r_io_map_fini (io);
	r_io_section_fini (io);
	ls_free (io->plugins);
	r_list_free (io->cache);
	r_list_free (io->undo.w_list);
	if (io->runprofile) {
		R_FREE (io->runprofile);
	}
	return true;
}
