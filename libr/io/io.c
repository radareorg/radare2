/* radare2 - LGPL - Copyright 2017 - condret */

#include <r_io.h>
#include <sdb.h>
#include "../config.h"

R_LIB_VERSION(r_io);

void operate_on_itermap (SdbListIter *iter, RIO *io, ut64 vaddr, ut8 *buf, int len, int match_flg, int (op (RIO *io, ut64 addr, ut8 *buf, int len)));

R_API RIO *r_io_new ()
{
	RIO *ret = R_NEW0 (RIO);
	return r_io_init (ret);
}

R_API RIO *r_io_init (RIO *io)
{
	if (!io)
		return NULL;
	r_io_desc_init (io);
	r_io_map_init (io);
	r_io_section_init (io);
	r_io_cache_init (io);
	r_io_plugin_init (io);
	r_io_undo_init (io);
	return io;
}

/* opens a file without mapping it */
R_API RIODesc *r_io_open_nomap (RIO *io, const char *uri, int flags, int mode)
{
	RIODesc *desc;
	RIOPlugin *plugin;
	if (!io || !io->files ||!uri)
		return NULL;
	plugin = r_io_plugin_resolve (io, uri, 0);
	if (!plugin || !plugin->open || !plugin->close)
		return NULL;
	desc = plugin->open (io, uri, flags, mode);
	if (!desc)
		return NULL;
	if (!desc->plugin)					//for none static callbacks, those that cannot use r_io_desc_new
		desc->plugin = plugin;
	if (!desc->uri)
		desc->uri = strdup (uri);
	if (!desc->name)
		desc->name = strdup (uri);
	r_io_desc_add (io, desc);
	if (io->autofd || !io->desc)				//set desc as current if autofd or io->desc==NULL
		io->desc = desc;
	return desc;
}

/* opens a file and maps it to 0x0 */
R_API RIODesc *r_io_open (RIO *io, const char *uri, int flags, int mode)
{
	RIODesc *desc;
	if (!io || !io->maps)
		return NULL;
	desc = r_io_open_nomap (io, uri, flags, mode);
	if (!desc)
		return NULL;
	r_io_map_new (io, desc->fd, desc->flags, 0LL, 0LL, r_io_desc_size (desc));
	return desc;
}

/* opens a file and maps it to an offset specified by the "at"-parameter */
R_API RIODesc *r_io_open_at (RIO *io, const char *uri, int flags, int mode, ut64 at)
{
	RIODesc *desc;
	ut64 size;
	if (!io || !io->maps)
		return NULL;
	desc = r_io_open_nomap (io, uri, flags, mode);
	if (!desc)
		 return NULL;
	size = r_io_desc_size (desc);
	if (size && ((UT64_MAX - size + 1) < at)) {		//second map
		r_io_map_new (io, desc->fd, desc->flags, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);			//split map into 2 maps if only 1 big map results into interger overflow
		size = UT64_MAX - at + 1;						//someone pls take a look at this confusing stuff
	}
	r_io_map_new (io, desc->fd, desc->flags, 0LL, at, size);			//first map
	return desc;
}

/* opens many files, without mapping them. This should be discussed */
R_API RList *r_io_open_many (RIO *io, char *uri, int flags, int mode)
{
	RList *desc_list;
	RListIter *iter;
	RIODesc *desc;
	RIOPlugin *plugin;
	if (!io || !io->files || !uri)
		return NULL;
	plugin = r_io_plugin_resolve (io, uri, 1);
	if (!plugin || !plugin->open_many || !plugin->close)
		return NULL;
	if (!(desc_list = plugin->open_many (io, uri, flags, mode)))
		return NULL;
	r_list_foreach (desc_list, iter, desc) {
		if (desc) {
			if (!desc->plugin)
				desc->plugin = plugin;
			if (!desc->uri)
				desc->uri = strdup (uri);
			r_io_desc_add (io, desc);
			if (!io->desc)						//should autofd be honored here?
				io->desc = desc;
		}
	}
	return desc_list;
}

R_API bool r_io_close (RIO *io, int fd)
{
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc || !desc->plugin || !desc->plugin->close)			//check for cb
		return false;
	if (!desc->plugin->close (desc))					//close fd
		return false;
	r_io_desc_del (io, fd);							//remove entry from sdb-instance and free the desc-struct
	r_io_map_cleanup (io);							//remove all dead maps
	r_io_section_cleanup (io);
	return true;
}

R_API bool r_io_reopen (RIO *io, int fd, int flags, int mode)
{
	RIODesc *old, *new;
	char *uri;
	if (!(old = r_io_desc_get (io, fd)))
			return false;
	uri = old->referer ? old->referer : old->uri;	//does this really work, or do we have to handler debuggers ugly
	if (!(new = r_io_open_nomap (io, uri, flags, mode)))
			return false;
	r_io_desc_exchange (io, old->fd, new->fd);
	return r_io_close (io, new->fd);		//magic
}

R_API int r_io_close_all (RIO *io)			//what about undo?
{
	if (!io)
		return false;
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

R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	int ret;
	if (!io || !buf)
		return 0;
	if (io->ff)
		memset (buf, 0xff, len);
	if (!io->desc || !(io->desc->flags & R_IO_READ) || !io->desc->plugin ||
			!io->desc->plugin->read || !len)			//check pointers and permissions
		return 0;
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	ret = io->desc->plugin->read (io, io->desc, buf, len);
	if (io->p_cache)
		r_io_desc_cache_read (io->desc, paddr, buf, len);
	return ret;
}

R_API int r_io_pwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	if (!io || !buf || !io->desc || (!io->p_cache && !(io->desc->flags & R_IO_WRITE)) ||
			!io->desc->plugin || !io->desc->plugin->write || !len)	//check pointers and permissions
		return 0;
	if (io->p_cache)
		return r_io_desc_cache_write (io->desc, paddr, buf, len);
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	return io->desc->plugin->write (io, io->desc, buf, len);
}

R_API int r_io_vread_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return false;
	if (!len)
		return true;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pread_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_READ, r_io_pread_at);
	return true;
}

R_API int r_io_vwrite_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return false;
	if (!len)
		return true;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pwrite_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_WRITE, r_io_pwrite_at);
	return true;
}

R_API int r_io_read_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	int ret;
	if (!io || !buf || !len)
		return 0;
	if (io->buffer_enabled)
		return !!r_io_buffer_read (io, addr, buf, len);
	if (io->va)
		ret = r_io_vread_at (io, addr, buf, len);
	else	ret = r_io_pread_at (io, addr, buf, len);
	if (io->cached_read)
		ret &= !!r_io_cache_read (io, addr, buf, len);
	return ret;
}

R_API int r_io_write_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	int i;
	if (!io || !buf || !len)
		return 0;
	if (io->write_mask)
		for (i = 0; i < len; i++)
			buf[i] &= io->write_mask[i % io->write_mask_len];	//this sucks
	if (io->cached)
		return !!r_io_cache_write (io, addr, buf, len);
	if (io->va)
		return r_io_vwrite_at (io, addr, buf, len);
	return r_io_pwrite_at (io, addr, buf, len);
}

R_API int r_io_read (RIO *io, ut8 *buf, int len)
{
	int ret;
	if (!io)
		return 0;
	ret = r_io_read_at (io, io->off, buf, len);
	io->off += len;					//TODO: check ret before
	return ret;
}

R_API int r_io_write (RIO *io, ut8 *buf, int len)
{
	int ret;
	if (!io)
		return 0;
	ret = r_io_write_at (io, io->off, buf, len);
	io->off += len;
	return ret;
}

R_API ut64 r_io_size (RIO *io)
{
#warning rethink this, maybe not needed
	if (io)
		return r_io_desc_size (io->desc);
	return 0LL;
}

R_API int r_io_is_listener (RIO *io)
{
	if (io && io->desc && io->desc->plugin && io->desc->plugin->listener)
		return io->desc->plugin->listener (io->desc);
	return false;
}

R_API int r_io_system (RIO *io, const char* cmd)
{
	int ret = -1;
	if (io && io->desc && io->desc->plugin && io->desc->plugin->system)
		ret = io->desc->plugin->system (io, io->desc, cmd);
	return ret;
}

R_API bool r_io_resize (RIO *io, ut64 newsize)
{
	bool ret;
	if (io && io->desc && io->desc->plugin && io->desc->plugin->resize) {
		ret = io->desc->plugin->resize (io, io->desc, newsize);
		if (io->p_cache)
			r_io_desc_cache_cleanup (io->desc);
		return ret;
	}
	return false;
}

R_API int r_io_extend_at (RIO *io, ut64 addr, ut64 size)
{
	ut64 cur_size, tmp_size;
	ut8 *buffer;
	if (!io || !io->desc || !io->desc->plugin || !size)
		return false;
	if (io->desc->plugin->extend) {
		ut64 cur_off = io->off;
		int ret;
		r_io_seek (io, addr, R_IO_SEEK_SET);
		ret = io->desc->plugin->extend (io, io->desc, size);
		io->off = cur_off;				//no need to seek here
		return ret;
	}
	if ((io->desc->flags & R_IO_RW) != R_IO_RW)
		return false;
	cur_size = r_io_desc_size (io->desc);
	if (addr > cur_size)
		return false;
	if ((UT64_MAX - size) < cur_size)
		return false;
	if (!r_io_resize (io, cur_size + size))
		return false;
	if ((tmp_size = cur_size - addr) == 0LL)
		return true;
	if (!(buffer = malloc ((size_t)tmp_size)))
		return false;
	r_io_pread_at (io, addr, buffer, (int)tmp_size);
	r_io_pwrite_at (io, addr + size, buffer, (int)tmp_size);
	free (buffer);
	return true;
}

R_API bool r_io_set_write_mask (RIO *io, const ut8 *mask, int len)
{
	if (!io)
		return false;
	free (io->write_mask);
	if (!mask) {
		io->write_mask = NULL;
		io->write_mask_len = 0;
		return true;
	}
	io->write_mask = (ut8 *)malloc (len);
	memcpy (io->write_mask, mask, len);
	io->write_mask_len = len;
	return true;
}

RIO *bind_get_io (RIOBind *iob)
{
	if (!iob)
		return NULL;
	return iob->io;
}

R_API int r_io_is_valid_offset (RIO *io, ut64 offset, int hasperm) {
	RIOMap *map;
	if (!io) {
		eprintf ("r_io_is_valid_offset: io is NULL\n");
		r_sys_backtrace ();
		return R_FAIL;
	}
	if (io->va && (map = r_io_map_get (io, offset)))
		return ((map->flags & hasperm) == hasperm);
	if (!io->desc)
		return false;
	if (r_io_desc_size (io->desc) < offset)
		return false;
	return ((io->desc->flags & hasperm) != hasperm);
}

R_API int r_io_bind (RIO *io, RIOBind *bnd)
{
	if (!io || !bnd)
		return false;
	bnd->io = io;
	bnd->init = true;
	bnd->get_io = bind_get_io;
	bnd->desc_use = r_io_desc_use;
	bnd->desc_get = r_io_desc_get;
	bnd->desc_size = r_io_desc_size;
	bnd->open = r_io_open_nomap;
	bnd->open_at = r_io_open_at;
	bnd->close = r_io_close;
	bnd->read_at = r_io_read_at;
	bnd->write_at = r_io_write_at;
	bnd->system = r_io_system;
	bnd->is_valid_offset = r_io_is_valid_offset;
	bnd->section_vget_secs_at = r_io_section_vget_secs_at;
	bnd->section_add = r_io_section_add;
	return true;
}

/* moves bytes up (+) or down (-) within the specified range */
R_API int r_io_shift (RIO *io, ut64 start, ut64 end, st64 move)
{
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 rest, src, shiftsize = r_num_abs (move);
	if (!shiftsize || (end - start) <= shiftsize) return false;
	rest = (end - start) - shiftsize;

	if (!(buf = malloc (chunksize))) {
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
	return true;
}

R_API int r_io_create (RIO *io, const char *file, int mode, int type)
{
	if (io && io->desc && io->desc->plugin && io->desc->plugin->create)
		return io->desc->plugin->create (io, file, mode, type);
	if (type == 'd' || type == 1)
		return r_sys_mkdir (file);
	return r_sandbox_creat (file, mode);
}

R_API ut64 r_io_seek (RIO *io, ut64 offset, int whence)
{
	if (!io)
		return 0LL;
	switch (whence) {
		case R_IO_SEEK_SET:
			io->off = offset;
			break;
		case R_IO_SEEK_CUR:
			io->off += offset;
			break;
		case R_IO_SEEK_END:
		default:
			io->off = (ut64)(-1);
			break;
	}
	return io->off;
}

//remove all descs and maps
R_API int r_io_fini (RIO *io)
{
	if (!io)
		return false;
	r_io_desc_cache_fini_all (io);
	r_io_desc_fini (io);
	r_io_map_fini (io);
	r_io_section_fini (io);
	ls_free (io->plugins);
	r_list_free (io->cache);
	if (io->runprofile)
		R_FREE (io->runprofile);
	return true;
}

R_API void r_io_free (RIO *io)
{
	if (r_io_fini (io)) {
		free (io->args);
		free (io->write_mask);					//maybe this would be better in r_io_fini
	}
	free (io);
}

//not public api
void operate_on_itermap (SdbListIter *iter, RIO *io, ut64 vaddr, ut8 *buf, int len, int match_flg, int (op (RIO *io, ut64 addr, ut8 *buf, int len)))
{
	RIODesc *temp;
	RIOMap *map;
	ut64 vendaddr;
	if (!io || !len || !buf)
		return;
	if (!iter) {
		op (io, vaddr, buf, len);				//end of list
		return;
	}
	if ((UT64_MAX - len + 1) < vaddr) {				//this block is not that much elegant
		int nlen;						//needed for edge-cases
		vendaddr = UT64_MAX;					//add a test for this block
		nlen = (int)(vendaddr - vaddr + 1);
		operate_on_itermap (iter, io, 0LL, buf + nlen, len - nlen, match_flg, op);
	} else	vendaddr = vaddr + len - 1;
	map = (RIOMap *)iter->data;
	while (!r_io_map_is_in_range (map, vaddr, vendaddr)) {		//search for next map or end of list
		iter = iter->p;
		if (!iter) {						//end of list
			op (io, vaddr, buf, len);			//pread/pwrite
			return;
		}
		map = (RIOMap *)iter->data;
	}
	if (map->from >= vaddr) {
		operate_on_itermap (iter->p, io, vaddr, buf, (int)(map->from - vaddr), match_flg, op);
		buf = buf + (map->from - vaddr);
		vaddr = map->from;
		len = (int)(vendaddr - vaddr + 1);
		if (vendaddr <= map->to) {
			if (((map->flags & match_flg) == match_flg) || io->p_cache) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta, buf, len);
				io->desc = temp;
			}
		} else {
			if (((map->flags & match_flg) == match_flg) || io->p_cache) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta, buf, len - (int)(vendaddr - map->to));
				io->desc = temp;
			}
			vaddr = map->to + 1;
			buf = buf + (len - (int)(vendaddr - map->to));
			len = (int)(vendaddr - map->to);
			operate_on_itermap (iter->p, io, vaddr, buf, len, match_flg, op);
		}
	} else {
		if (vendaddr <= map->to) {
			if (((map->flags & match_flg) == match_flg) || io->p_cache) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta + (vaddr - map->from), buf, len);		//warning: may overflow in rare usecases
				io->desc = temp;
			}
		} else {
			if (((map->flags & match_flg) == match_flg) || io->p_cache) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta + (vaddr - map->from), buf, len - (int)(vendaddr - map->to));
				io->desc = temp;
			}
			vaddr = map->to + 1;
			buf = buf + (len - (int)(vendaddr - map->to));
			len = (int)(vendaddr - map->to);
			operate_on_itermap (iter->p, io, vaddr, buf, len, match_flg, op);
		}
	}
}
