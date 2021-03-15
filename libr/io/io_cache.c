/* radare - LGPL - Copyright 2008-2020 - pancake */

#include <r_io.h>
#include <r_skyline.h>

static void cache_item_free(RIOCache *cache) {
	if (cache) {
		free (cache->data);
		free (cache->odata);
		free (cache);
	}
}

R_API bool r_io_cache_at(RIO *io, ut64 addr) {
	r_return_val_if_fail (io, false);
	return r_skyline_contains (&io->cache_skyline, addr);
}

R_API void r_io_cache_init(RIO *io) {
	r_return_if_fail (io);
	r_pvector_init (&io->cache, (RPVectorFree)cache_item_free);
	r_skyline_init (&io->cache_skyline);
	io->buffer = r_cache_new ();
	io->cached = 0;
}

R_API void r_io_cache_fini(RIO *io) {
	r_return_if_fail (io);
	r_pvector_fini (&io->cache);
	r_skyline_fini (&io->cache_skyline);
	r_cache_free (io->buffer);
	io->buffer = NULL;
	io->cached = 0;
}

R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to) {
	r_return_if_fail (io);
	void **iter;
	RIOCache *c;
	RInterval range = (RInterval){from, to - from};
	r_pvector_foreach (&io->cache, iter) {
		c = *iter;
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
	r_return_if_fail (io);
	io->cached = set;
	r_pvector_clear (&io->cache);
	r_skyline_clear (&io->cache_skyline);
}

R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	r_return_val_if_fail (io, false);
	int invalidated = 0;
	void **iter;
	RIOCache *c;
	RInterval range = (RInterval){from, to - from};
	r_pvector_foreach_prev (&io->cache, iter) {
		c = *iter;
		if (r_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			r_io_write_at (io, r_itv_begin (c->itv), c->odata, r_itv_size (c->itv));
			io->cached = cached;
			c->written = false;
			r_pvector_remove_data (&io->cache, c);
			free (c->data);
			free (c->odata);
			free (c);
			invalidated++;
		}
	}
	r_skyline_clear (&io->cache_skyline);
	r_pvector_foreach (&io->cache, iter) {
		c = *iter;
		r_skyline_add (&io->cache_skyline, c->itv, c);
	}
	return invalidated;
}

R_API bool r_io_cache_list(RIO *io, int rad) {
	r_return_val_if_fail (io, false);
	size_t i, j = 0;
	void **iter;
	RIOCache *c;
	PJ *pj = NULL;
	if (rad == 2) {
		pj = pj_new ();
		pj_a (pj);
	}
	r_pvector_foreach (&io->cache, iter) {
		c = *iter;
		const ut64 dataSize = r_itv_size (c->itv);
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
			pj_o (pj);
			pj_kn (pj, "idx", j);
			pj_kn (pj, "addr", r_itv_begin (c->itv));
			pj_kn (pj, "size", dataSize);
			char *hex = r_hex_bin2strdup (c->odata, dataSize);
			pj_ks (pj, "before", hex);
			free (hex);
			hex = r_hex_bin2strdup (c->data, dataSize);
			pj_ks (pj, "after", hex);
			free (hex);
			pj_kb (pj, "written", c->written);
			pj_end (pj);
		} else if (rad == 0) {
			io->cb_printf ("idx=%"PFMTSZu" addr=0x%08"PFMT64x" size=%"PFMT64u" ", j, r_itv_begin (c->itv), dataSize);
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
		pj_end (pj);
		char *json = pj_drain (pj);
		io->cb_printf ("%s", json);
		free (json);
	}
	return false;
}

R_API bool r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len) {
	r_return_val_if_fail (io && buf, false);
	RIOCache *ch = R_NEW0 (RIOCache);
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
		const bool cm = io->cachemode;
		io->cachemode = false;
		r_io_read_at (io, addr, ch->odata, len);
		io->cachemode = cm;
	}
	memcpy (ch->data, buf, len);
	r_pvector_push (&io->cache, ch);
	r_skyline_add (&io->cache_skyline, ch->itv, ch);
	REventIOWrite iow = { addr, buf, len };
	r_event_send (io->event, R_EVENT_IO_WRITE, &iow);
	return true;
}

R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (io && buf, false);
	RSkyline *skyline = &io->cache_skyline;
	const RSkylineItem *iter = r_skyline_get_item_intersect (skyline, addr, len);
	if (!iter) {
		return false;
	}
	const RSkylineItem *last = (RSkylineItem *)skyline->v.a + skyline->v.len;
	bool covered = false;
	while (iter != last) {
		const ut64 begin = r_itv_begin (iter->itv);
		const st64 addr_offset = begin - addr;
		const ut64 buf_offset = addr_offset > 0 ? addr_offset : 0;
		const ut64 cur_addr = addr + buf_offset;
		const ut64 left = len - buf_offset;
		if (begin > cur_addr + left) {
			break;
		}
		RIOCache *cache = iter->user;
		const ut64 cache_shift = addr_offset < 0 ? -addr_offset : 0;
		const ut64 cache_offset = begin - r_itv_begin (cache->itv) + cache_shift;
		const ut64 read = R_MIN (left, r_itv_size (iter->itv) - cache_shift);
		memcpy (buf + buf_offset, cache->data + cache_offset, read);
		covered = true;
		if (left - read <= 0) {
			break;
		}
		iter++;
	}
	return covered;
}
