#include <r_io.h>
#include <sdb.h>

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
	r_io_cache_init (io);
	r_io_plugin_init (io);
	return io;
}

R_API RIODesc *r_io_open_nomap (RIO *io, char *uri, int flags, int mode)
{
	RIODesc *desc;
	RIOplugin *plugin;
	if (!io || !io->files ||!uri)
		return NULL;
	plugin = r_io_plugin_resolve (io, uri, 0);
	if (!plugin || !plugin->open || !plugin->close)
		return NULL;
	desc = plugin->open (io, uri, flags, mode);
	if (!desc)
		return NULL;
	if (!desc->plugin)						//for none static callbacks, those that cannot use r_io_desc_new
		desc->plugin = plugin;
	if (!desc->uri)
		desc->uri = strdup (uri);
	r_io_desc_add (io, desc);
	if (io->autofd || !io->desc)				//set desc as current if autofd or io->desc==NULL
		io->desc = desc;
	return desc;
}

R_API RIODesc *r_io_open (RIO *io, char *uri, int flags, int mode)
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

R_API RIODesc *r_io_open_at (RIO *io, char *uri, int flags, int mode, ut64 at)
{
	RIODesc *desc;
	ut64 size;
	if (!io || !io->maps)
		return NULL;
	desc = r_io_open_nomap (io, uri, flags, mode);
	if (!desc)
		 return NULL;
	size = r_io_desc_size (desc);
	if (size && ((UT64_MAX - size + 1) < at)) {										//second map
		r_io_map_new (io, desc->fd, desc->flags, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);			//split map into 2 maps if only 1 big map results into interger overflow
		size = UT64_MAX - at + 1;											//someone pls take a look at this confusing stuff
	}
	r_io_map_new (io, desc->fd, desc->flags, 0LL, at, size);								//first map
	return desc;
}

R_API int r_io_close (RIO *io, int fd)
{
	RIODesc *desc = r_io_desc_get (io, fd);
	if (!desc || !desc->cbs || !desc->cbs->close)										//check for cb
		return R_FALSE;
	if (!desc->cbs->close (desc))												//close fd
		return R_FALSE;
	r_io_desc_del (io, fd);													//remove entry from sdb-instance and free the desc-struct
	r_io_map_cleanup (io);													//remove all dead maps
	return R_TRUE;
}

R_API int r_io_pread_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return 0;
	if (io->ff)
		memset (buf, 0xff, len);
	if (!io->desc || !(io->desc->flags & R_IO_READ) || !io->desc->cbs || !io->desc->cbs->read || !len)			//check pointers and permissions
		return 0;
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	return io->desc->cbs->read (io, io->desc, buf, len);
}

R_API int r_io_pwrite_at (RIO *io, ut64 paddr, ut8 *buf, int len)
{
	if (!io || !buf || !io->desc || !(io->desc->flags & R_IO_WRITE) || !io->desc->cbs || !io->desc->cbs->write || !len)	//check pointers and permissions
		return 0;
	r_io_desc_seek (io->desc, paddr, R_IO_SEEK_SET);
	return io->desc->cbs->write (io, io->desc, buf, len);
}

R_API int r_io_vread_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return R_FALSE;
	if (!len)
		return R_TRUE;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pread_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_READ, r_io_pread_at);
	return R_TRUE;
}

R_API int r_io_vwrite_at (RIO *io, ut64 vaddr, ut8 *buf, int len)
{
	if (!io || !buf)
		return R_FALSE;
	if (!len)
		return R_TRUE;
	r_io_map_cleanup (io);
	if (!io->maps)
		return r_io_pwrite_at (io, vaddr, buf, len);
	operate_on_itermap (io->maps->tail, io, vaddr, buf, len, R_IO_WRITE, r_io_pwrite_at);
	return R_TRUE;
}

R_API int r_io_read_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	int ret;
	if (!io || !buf || !len)
		return 0;
	if (io->va)
		ret = r_io_vread_at (io, addr, buf, len);
	else	ret = r_io_pread_at (io, addr, buf, len);
	if (io->cached_read)
		ret &= !!r_io_cache_read (io, addr, buf, len);
	return ret;
}

R_API int r_io_write_at (RIO *io, ut64 addr, ut8 *buf, int len)
{
	if (!io || !buf || !len)
		return 0;
	if (io->cached)
		return !!r_io_cache_write (io, addr, buf, len);
	if (io->va)
		return r_io_vwrite_at (io, addr, buf, len);
	return r_io_pwrite_at (io, addr, buf, len);
}

//remove all descs and maps
R_API int r_io_fini (RIO *io)
{
	if (!io)
		return R_FALSE;
	r_io_desc_fini (io);
	r_io_map_fini (io);
	ls_free (io->plugins);
	r_list_free (io->cache);
	return R_TRUE;
}

R_API void r_io_free (RIO *io)
{
	r_io_fini (io);
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
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta, buf, len);
				io->desc = temp;
			}
		} else {
			if ((map->flags & match_flg) == match_flg) {
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
			if ((map->flags & match_flg) == match_flg) {
				temp = io->desc;
				r_io_desc_use (io, map->fd);
				op (io, map->delta + (vaddr - map->from), buf, len);		//warning: may overflow in rare usecases
				io->desc = temp;
			}
		} else {
			if ((map->flags & match_flg) == match_flg) {
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
