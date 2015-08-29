/* radare - LGPL - Copyright 2008-2015 - pancake */

// TODO: implement a more inteligent way to store cached memory
// TODO: define limit of max mem to cache

#include "r_io.h"

static void cache_item_free(RIOCache *cache) {
	if (!cache)
		return;
	free (cache->data);
	free (cache->odata);
	free (cache);
}

R_API void r_io_cache_init(RIO *io) {
	io->cache = r_list_newf ((RListFree)cache_item_free);
	io->cached = false; // cache write ops
	io->cached_read = false; // cached read ops
}

R_API void r_io_cache_enable(RIO *io, int read, int write) {
	io->cached = read | write;
	io->cached_read = read;
}

R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to) {
	RListIter *iter;
	RIOCache *c;

	int ioc = io->cached;
	io->cached = 0;
	r_list_foreach (io->cache, iter, c) {
		if (c->from >= from && c->to <= to) {
			if (!r_io_write_at (io, c->from, c->data, c->size))
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", c->from);
			else 
				c->written = true;
			break;
		}
	}
	io->cached = ioc;
}

R_API void r_io_cache_reset(RIO *io, int set) {
	io->cached = set;
	r_list_purge (io->cache);
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	RListIter *iter;
	RIOCache *c;
	int done = false;

	if (from<to) {
		//r_list_foreach_safe (io->cache, iter, iter_tmp, c) {
		r_list_foreach (io->cache, iter, c) {
			if (c->from >= from && c->to <= to) {
				int ioc = io->cached;
				io->cached = 0;
				r_io_write_at (io, c->from, c->odata, c->size);
				io->cached = ioc;
				if (!c->written)
					r_list_delete (io->cache, iter);
				c->written = false;
				done = true;
				break;
			}
		}
	}
	return done;
}

R_API int r_io_cache_list(RIO *io, int rad) {
	int i, j = 0;
	RListIter *iter;
	RIOCache *c;
	if (rad == 2) {
		io->cb_printf ("[");
	}
	r_list_foreach (io->cache, iter, c) {
		if (rad == 1) {
			io->cb_printf ("wx ");
			for (i=0; i<c->size; i++)
				io->cb_printf ("%02x", c->data[i]);
			io->cb_printf (" @ 0x%08"PFMT64x, c->from);
			io->cb_printf (" # replaces: ");
			for (i=0; i<c->size; i++)
				io->cb_printf ("%02x", c->odata[i]);
			io->cb_printf ("\n");
		} else {
			io->cb_printf ("idx=%d addr=0x%08"PFMT64x" size=%d ",
				j, c->from, c->size);
			for (i=0; i<c->size; i++)
				io->cb_printf ("%02x", c->odata[i]);
			}
			io->cb_printf (" -> ");
			for (i=0; i<c->size; i++)
				io->cb_printf ("%02x", c->data[i]);
			io->cb_printf (" %s\n", c->written?"(written)":"(not written)");
		}
		j++;
	}
	if (rad == 2)
		io->cb_printf ("]");
	return false;
}

R_API int r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len) {		//Review this later
	RIOCache *ch;
	ch = R_NEW0 (RIOCache);
	ch->from = addr;
	ch->to = addr + len;
	ch->size = len;
	ch->odata = (ut8*)malloc (len);
	ch->data = (ut8*)malloc (len);
	ch->written = io->cached? 0: 1;
	r_io_read_at (io, addr, ch->odata, len);
	memcpy (ch->data, buf, len);
	r_list_append (io->cache, ch);
	return len;
}

R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	int l, ret, da, db;
	RListIter *iter;
	RIOCache *c;
	if (len < 0) {
		return 0;
	}

	r_list_foreach (io->cache, iter, c) {
		if (r_range_overlap (addr, addr+len-1, c->from, c->to, &ret)) {
			if (ret>0) {
				da = ret;
				db = 0;
				l = c->size;
			} else if (ret<0) {
				da = 0;
				db = -ret;
				l = c->size-db;
			} else {
				da = 0;
				db = 0;
				l = c->size;
			}
			if ((l+da)>len) l = len-da;					//say hello to integer overflow, but this won't happen in realistic scenarios because malloc will fail befor
			if (l<1) l = 1; // XXX: fail
			else memcpy (buf+da, c->data+db, l);
		}
	}
	return len;
}
