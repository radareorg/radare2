/* radare - LGPL - Copyright 2008-2018 - pancake */

// TODO: implement a more inteligent way to store cached memory

#include "r_io.h"

#if 0
#define CACHE_CONTAINER(x) container_of ((RBNode*)x, RCache, rb)

static void _fcn_tree_calc_max_addr(RBNode *node) {
	RIOCache *c = CACHE_CONTAINER (node);
}
#endif // 0

static void cache_item_free(RIOCache *cache) {
	if (!cache) {
		return;
	}
	free (cache->data);
	free (cache->odata);
	free (cache);
}

R_API bool r_io_cache_at(RIO *io, ut64 addr) {
	RIOCache *c;
	RListIter *iter;
	r_list_foreach (io->cache, iter, c) {
		if (r_itv_contain (c->itv, addr)) {
			return true;
		}
	}
	return false;
}

R_API void r_io_cache_init(RIO *io) {
	io->cache = r_list_newf ((RListFree)cache_item_free);
	io->cached = 0;
}

R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to) {
	RListIter *iter;
	RIOCache *c;
	RInterval range = (RInterval){from, to - from};
	r_list_foreach (io->cache, iter, c) {
		// if (from <= c->to - 1 && c->from <= to - 1) {
		if (R_ITV_OVERLAP (c, range)) {
			int cached = io->cached;
			io->cached = 0;
			if (r_io_write_at (io, r_itv_begin (c->itv), c->data, r_itv_size (c->itv))) {
				c->written = true;
			} else {
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", R_ITV_BEGIN (c));
			}
			io->cached = cached;
			break; // XXX old behavior, revisit this
		}
	}
}

R_API void r_io_cache_reset(RIO *io, int set) {
	io->cached = set;
	r_list_purge (io->cache);
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	RListIter *iter;
	RIOCache *c;
	int done = false;

	if (from < to) {
		RInterval range = (RInterval){from, to - from};
		r_list_foreach_prev (io->cache, iter, c) {
			if (R_ITV_OVERLAP (c, range)) {
				int cached = io->cached;
				io->cached = 0;
				r_io_write_at (io, R_ITV_BEGIN (c), c->odata, R_ITV_SIZE (c));
				io->cached = cached;
				if (!c->written) {
					r_list_delete (io->cache, iter);
				}
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
		const int dataSize = R_ITV_SIZE (c);
		if (rad == 1) {
			io->cb_printf ("wx ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->data[i] & 0xff));
			}
			io->cb_printf (" @ 0x%08"PFMT64x, R_ITV_BEGIN (c));
			io->cb_printf (" # replaces: ");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->odata[i] & 0xff));
			}
			io->cb_printf ("\n");
		} else if (rad == 2) {
			io->cb_printf ("{\"idx\":%"PFMT64d",\"addr\":%"PFMT64d",\"size\":%d,",
				j, R_ITV_BEGIN (c), dataSize);
			io->cb_printf ("\"before\":\"");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->odata[i]);
			}
			io->cb_printf ("\",\"after\":\"");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->data[i]);
			}
			io->cb_printf ("\",\"written\":%s}%s", c->written
				? "true": "false", iter->n? ",": "");
		} else if (rad == 0) {
			io->cb_printf ("idx=%d addr=0x%08"PFMT64x" size=%d ", j, R_ITV_BEGIN (c), dataSize);
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->odata[i]);
			}
			io->cb_printf (" -> ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->data[i]);
			}
			io->cb_printf (" %s\n", c->written? "(written)": "(not written)");
		}
		j++;
	}
	if (rad == 2) {
		io->cb_printf ("]\n");
	}
	return false;
}

R_API bool r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len) {
	RIOCache *ch;
	ch = R_NEW0 (RIOCache);
	if (!ch) {
		return false;
	}
	ch->itv = (RInterval){addr, len};
	ch->odata = (ut8*)calloc (1, len + 1);
	if (!ch->odata) {
		free (ch);
		return false;
	}
	ch->data = (ut8*)calloc (1, len + 1);
	if (!ch->data) {
		free (ch->odata);
		free (ch);
		return false;
	}
	ch->written = false;
	{
		bool cm = io->cachemode;
		io->cachemode = false;
		r_io_read_at (io, addr, ch->odata, len);
		io->cachemode = cm;
	}
	memcpy (ch->data, buf, len);
	r_list_append (io->cache, ch);
	return true;
}

R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	int l, covered = 0;
	RListIter *iter;
	RIOCache *c;
	RInterval range = (RInterval){ addr, len };
	r_list_foreach (io->cache, iter, c) {
		if (R_ITV_OVERLAP (c, range)) {
			const ut64 begin = R_ITV_BEGIN (c);
			if (addr < begin) {
				l = R_MIN (addr + len - begin, R_ITV_SIZE (c));
				memcpy (buf + begin - addr, c->data, l);
			} else {
				l = R_MIN (R_ITV_END (c) - addr, len);
				memcpy (buf, c->data + addr - begin, l);
			}
			covered += l;
		}
	}
	return (covered == 0) ? false: true;
}

////////////////////////////////////////////////////////////////////
#if 0
R_API bool r_io_cache_ll_read(RIO *io, ut64 addr, ut8 *buf, int len) {
//	UnownedRList *list = r
}

R_API bool r_io_cache_ll_write(RIO *io, ut64 addr, ut8 *buf, int len) {
}

R_API bool r_io_cache_ll_invalidate(RIO *io, ut64 addr, int len) {
}
#endif
