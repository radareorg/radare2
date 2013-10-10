/* radare - LGPL - Copyright 2008-2013 - pancake */

// TODO: implement a more inteligent way to store cached memory
// TODO: define limit of max mem to cache

#include "r_io.h"

static void cache_free(RIOCache *cache) {
	if (!cache)
		return;
	if (cache->data)
		free (cache->data);
	free (cache);
}

R_API void r_io_cache_init(RIO *io) {
	io->cache = r_list_new ();
	io->cache->free = (RListFree)cache_free;
	io->cached = R_FALSE; // cache write ops
	io->cached_read = R_FALSE; // cached read ops
}

R_API void r_io_cache_enable(RIO *io, int read, int write) {
	io->cached = read | write;
	io->cached_read = read;
}

R_API void r_io_cache_commit(RIO *io) {
	RListIter *iter;
	RIOCache *c;

	if (io->cached) {
		io->cached = R_FALSE;
		r_list_foreach (io->cache, iter, c) {
			if (!r_io_write_at (io, c->from, c->data, c->size))
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", c->from);
		}
		io->cached = R_TRUE;
		r_io_cache_reset (io, io->cached);
	}
}

R_API void r_io_cache_reset(RIO *io, int set) {
	io->cached = set;
	r_list_purge (io->cache);
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	RListIter *iter, *iter_tmp;
	RIOCache *c;

	if (from>=to) return R_FALSE;

	r_list_foreach_safe (io->cache, iter, iter_tmp, c) {
		if (c->from >= from && c->to <= to) {
			r_list_delete (io->cache, iter);
		}
	}
	return R_FALSE;
}

R_API int r_io_cache_list(RIO *io, int rad) {
	int i, j = 0;
	RListIter *iter;
	RIOCache *c;

	r_list_foreach (io->cache, iter, c) {
		if (rad) {
			io->printf ("wx ");
			for (i=0; i<c->size; i++)
				io->printf ("%02x", c->data[i]);
			io->printf (" @ 0x%08"PFMT64x"\n", c->from);
		} else {
			io->printf ("idx=%d addr=0x%08"PFMT64x" size=%d ",
				j, c->from, c->size);
			for (i=0; i<c->size; i++)
				io->printf ("%02x", c->data[i]);
			io->printf ("\n");
		}
		j++;
	}
	return R_FALSE;
}

R_API int r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len) {
	RIOCache *ch = R_NEW (RIOCache);
	ch->from = addr;
	ch->to = addr + len;
	ch->size = len;
	ch->data = (ut8*)malloc (len);
	memcpy (ch->data, buf, len);
	r_list_append (io->cache, ch);
	return len;
}

R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	int l, ret, da, db;
	RListIter *iter;
	RIOCache *c;

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
			if (l>len)
				l = len;
			if (l<1) {
				l = 1; // XXX: fail
			}
			memcpy (buf+da, c->data+db, l);
		}
	}
	return len;
}
