/* radare - LGPL - Copyright 2008-2018 - pancake */

// TODO: implement a more intelligent way to store cached memory

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
	io->buffer = r_cache_new ();
	io->cached = 0;
}

R_API void r_io_cache_fini (RIO *io) {
	r_list_free (io->cache);
	r_cache_free (io->buffer);
	io->cache = NULL;
	io->buffer = NULL;
	io->cached = 0;
}

R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to) {
	RListIter *iter;
	RIOCache *c;
	RInterval range = (RInterval){from, to - from};
	r_list_foreach (io->cache, iter, c) {
		// if (from <= c->to - 1 && c->from <= to - 1) {
		if (r_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			if (r_io_write_at (io, r_itv_begin (c->itv), c->data, r_itv_size (c->itv))) {
				c->written = true;
			} else {
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", r_itv_begin (c->itv));
			}
			io->cached = cached;
			// break; // XXX old behavior, revisit this
		}
	}
}

R_API void r_io_cache_reset(RIO *io, int set) {
	io->cached = set;
	r_list_purge (io->cache);
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	int invalidated = 0;
	RListIter *iter, *tmp;
	RIOCache *c;
	RInterval range = (RInterval){from, to - from};
	r_list_foreach_prev_safe (io->cache, iter, tmp, c) {
		if (r_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			r_io_write_at (io, r_itv_begin (c->itv), c->odata, r_itv_size (c->itv));
			io->cached = cached;
			c->written = false;
			r_list_delete (io->cache, iter);
			invalidated++;
		}
	}
	return invalidated;
}

R_API int r_io_cache_list(RIO *io, int rad) {
	int i, j = 0;
	RListIter *iter;
	RIOCache *c;
	if (rad == 2) {
		io->cb_printf ("[");
	}
	r_list_foreach (io->cache, iter, c) {
		const int dataSize = r_itv_size (c->itv);
		if (rad == 1) {
			io->cb_printf ("wx ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->data[i] & 0xff));
			}
			io->cb_printf (" @ 0x%08"PFMT64x, r_itv_begin (c->itv));
			io->cb_printf (" # replaces: ");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->odata[i] & 0xff));
			}
			io->cb_printf ("\n");
		} else if (rad == 2) {
			io->cb_printf ("{\"idx\":%"PFMT64d",\"addr\":%"PFMT64d",\"size\":%d,",
				j, r_itv_begin (c->itv), dataSize);
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
			io->cb_printf ("idx=%d addr=0x%08"PFMT64x" size=%d ", j, r_itv_begin (c->itv), dataSize);
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
	REventIOWrite iow = { addr, buf, len };
	r_event_send (io->event, R_EVENT_IO_WRITE, &iow);
	return true;
}

R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	bool covered = false;
	RListIter *iter;
	RIOCache *c;
	RInterval range = (RInterval){ addr, len };
	r_list_foreach (io->cache, iter, c) {
		if (r_itv_overlap (c->itv, range)) {
			const ut64 begin = r_itv_begin (c->itv);
			if (addr < begin) {
				int l = R_MIN (addr + len - begin, r_itv_size (c->itv));
				memcpy (buf + begin - addr, c->data, l);
			} else {
				int l = R_MIN (r_itv_end (c->itv) - addr, len);
				memcpy (buf, c->data + addr - begin, l);
			}
			covered = true;
		}
	}
	return covered;
}
