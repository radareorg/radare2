/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

// XXX This has been stolen from r_vm !!! we must adapt this
// XXX to work with r_io correctly
// r_io_cache_t has not been defined
// TODO: implement a more inteligent way to store cached memory
// TODO: define limit of max mem to cache

#include "r_io.h"

R_API void r_io_cache_init(RIO *io) {
	io->cached = R_FALSE; // cache write ops
	io->cached_read = R_FALSE; // cached read ops
	INIT_LIST_HEAD (&io->cache);
}

R_API void r_io_cache_enable(RIO *io, int read, int write) {
	io->cached = read | write;
	io->cached_read = read;
}

R_API void r_io_cache_commit(RIO *io) {
	struct list_head *pos, *n;
	if (io->cached) {
		io->cached = R_FALSE;
		list_for_each_safe (pos, n, &io->cache) {
			RIOCache *c = list_entry (pos, RIOCache, list);
			if (!r_io_write_at (io, c->from, c->data, c->size))
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", c->from);
		}
		io->cached = R_TRUE;
		r_io_cache_reset (io, io->cached);
	}
}

R_API void r_io_cache_reset(RIO *io, int set) {
	struct list_head *pos, *n;
	io->cached = set;
	list_for_each_safe(pos, n, &io->cache) {
		RIOCache *c = list_entry (pos, RIOCache, list);
		free (c->data);
		free (c);
	}
	// is this necessary at all?
	INIT_LIST_HEAD (&io->cache); 
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	int ret = R_FALSE;
	/* TODO: Implement: invalidate ranged cached read ops between from/to */
	return ret;
}

R_API int r_io_cache_list(RIO *io, int rad) {
	int i;
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &io->cache) {
		RIOCache *c = list_entry (pos, RIOCache, list);
		if (rad) {
			io->printf ("wx ");
			for (i=0; i<c->size; i++)
				io->printf ("%02x", c->data[i]);
			io->printf (" @ 0x%08"PFMT64x"\n", c->from);
		} else io->printf ("addr=0x%08"PFMT64x" size=%d\n", c->from, c->size);
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
	list_add_tail (&(ch->list), &io->cache);
	return len;
}

R_API int r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	int l, ret, da, db;
	struct list_head *pos;

	list_for_each (pos, &io->cache) {
		RIOCache *c = list_entry (pos, RIOCache, list);
		if (r_range_overlap (addr, addr+len, c->from, c->to, &ret)) {
			if (ret>0) {
				da = ret;
				db = 0;
				l = c->size;
			} else
			if (ret<0) {
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
			memcpy (buf+da, c->data+db, l);
		}
	}
	return len;
}
