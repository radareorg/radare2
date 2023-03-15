/* radare - LGPL - Copyright 2008-2023 - pancake, condret */

#include <r_io.h>
#include <r_skyline.h>

#if !USE_NEW_IO_CACHE_API

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
	io->cached = 0;
}

R_API void r_io_cache_fini(RIO *io) {
	r_return_if_fail (io);
	r_pvector_fini (&io->cache);
	r_skyline_fini (&io->cache_skyline);
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
				R_LOG_ERROR ("writing change at 0x%08"PFMT64x, r_itv_begin (c->itv));
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
	r_return_val_if_fail (io && buf && len > 0, false);
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
		if (io->nodup && !memcmp (ch->odata, buf, len)) {
			free (ch->odata);
			free (ch);
			return false;
		}
	}
	memcpy (ch->data, buf, len);
	r_pvector_push (&io->cache, ch);
	r_skyline_add (&io->cache_skyline, ch->itv, ch);
	REventIOWrite iow = { addr, buf, len };
	r_event_send (io->event, R_EVENT_IO_WRITE, &iow);
	return true;
}

R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && len > 0, false);
	RSkyline *skyline = &io->cache_skyline;
	const RSkylineItem *iter = r_skyline_get_item_intersect (skyline, addr, len);
	if (!iter) {
		return false;
	}
	const RSkylineItem *last = (RSkylineItem *)skyline->v.a + skyline->v.len;
	bool covered = false;
	int count = 0;
	while (iter != last) {
		const ut64 begin = r_itv_begin (iter->itv);
		const ut64 end = r_itv_end (iter->itv);
		count++;
		if (end < addr) {
			iter++;
			continue;
		}
		const st64 addr_offset = begin - addr;
		const ut64 buf_offset = addr_offset > 0 ? addr_offset : 0;
		const ut64 left = len - buf_offset;
		const ut64 cur_addr = addr + buf_offset;
		if (begin > cur_addr + left) {
			iter++;
			continue;
		}
		RIOCache *cache = iter->user;
		const ut64 cache_shift = addr_offset < 0 ? -addr_offset : 0;
		const ut64 cache_begin = r_itv_begin (cache->itv);
		if (end < cache_begin + cache_shift) {
			iter++;
			continue;
		}
		const st64 cache_offset = begin - cache_begin + cache_shift;
		const st64 read = R_MIN (left, r_itv_size (iter->itv) - cache_shift);
		if (cache_offset > r_itv_size (cache->itv)) {
			iter++;
			continue;
		}
		if (read < 0 || cache_offset < 0) {
			iter++;
			continue;
		}
		if (count > 32) {
			break;
		}
		// eprintf ("inrange (%llx %d)\n", begin, (int)(end - begin));
		if (read > 0) {
			memcpy (buf + buf_offset, cache->data + cache_offset, read);
		}
		covered = true;
		iter++;
	}
#if 0
	eprintf ("COUNT %d (0x%llx %d)\n", count, addr, len);
	if (count > 45000) {
		r_sys_breakpoint ();
	}
#endif
	return covered;
}

#else
// USE_NEW_IO_CACHE_API

R_API RIOCacheItem * _io_cache_item_new(RInterval *itv) {
	RIOCacheItem *ci = R_NEW0 (RIOCacheItem);
	if (!ci) {
		return NULL;
	}
	ci->data = R_NEWS (ut8, itv->size);
	if (!ci->data) {
		free (ci);
		return NULL;
	}
	ci->odata = R_NEWS (ut8, itv->size);
	if (!ci->odata) {
		free (ci->data);
		free (ci);
		return NULL;
	}
	ci->tree_itv = R_NEWCOPY (RInterval, itv);
	if (!ci->tree_itv) {
		free (ci->odata);
		free (ci->data);
		free (ci);
		return NULL;
	}
	ci->itv = (*itv);
	return ci;
}

void _io_cache_item_free(void *data) {
	RIOCacheItem *ci = (RIOCacheItem *)data;
	if (ci) {
		free (ci->tree_itv);
		free (ci->data);
		free (ci->odata);
		free (ci);
	}
}

R_API void r_io_cache_init(RIO *io) {
	r_return_if_fail (io);
	io->cache = R_NEW (RIOCache);
	if (io->cache) {
		io->cache->tree = r_crbtree_new (NULL);
		io->cache->vec = r_pvector_new ((RPVectorFree)_io_cache_item_free);
	}
	io->cached = 0;
}

R_API void r_io_cache_fini(RIO *io) {
	r_return_if_fail (io);
	if (io->cache) {
		r_crbtree_free (io->cache->tree);
		r_pvector_free (io->cache->vec);
		R_FREE (io->cache);
	}
	io->cached = 0;
}

R_API void r_io_cache_reset(RIO *io, int set) {
	r_return_if_fail (io);
	io->cached = set;
	r_crbtree_clear (io->cache->tree);
	r_pvector_clear (io->cache->vec);
}

static int _find_lowest_intersection_ci_cb(void *incoming, void *in, void *user) {
	RInterval *itv = (RInterval *)incoming;
	RIOCacheItem *ci = (RIOCacheItem *)in;
	if (r_itv_overlap (itv[0], ci->tree_itv[0])) {
		return 0;
	}
	if (itv->addr < ci->tree_itv->addr) {
		return -1;
	}
	return 1;
}

// returns the node containing the submap with lowest itv.addr, that intersects with sm
static RRBNode *_find_entry_ci_node(RRBTree *caache_tree, RInterval *itv) {
	RRBNode *node = r_crbtree_find_node (caache_tree, itv, _find_lowest_intersection_ci_cb, NULL);
	if (!node) {
		return NULL;
	}
	RRBNode *prev = r_rbnode_prev (node);
	while (prev && r_itv_overlap (itv[0], ((RIOCacheItem *)(prev->data))->tree_itv[0])) {
		node = prev;
		prev = r_rbnode_prev (node);
	}
	return node;
}

static int _ci_start_cmp_cb(void *incoming, void *in, void *user) {
	RIOCacheItem *incoming_ci = (RIOCacheItem *)incoming, *in_ci = (RIOCacheItem *)in;
	if (incoming_ci->tree_itv->addr < in_ci->tree_itv->addr) {
		return -1;
	}
	if (incoming_ci->tree_itv->addr > in_ci->tree_itv->addr) {
		return 1;
	}
	return 0;
}

R_API bool r_io_cache_write(RIO *io, ut64 addr, const ut8 *buf, int len) {
	return r_io_cache_write_at (io, addr, buf, len);
}

R_API bool r_io_cache_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && (len > 0), false);
	RInterval itv = (RInterval){addr, len};
	RIOCacheItem *ci = _io_cache_item_new (&itv);
	if (!ci) {
		return false;
	}
	r_io_read_at (io, addr, ci->odata, len);
	memcpy (ci->data, buf, len);
	RRBNode *node = _find_entry_ci_node (io->cache->tree, &itv);
	if (node) {
		RIOCacheItem *_ci = (RIOCacheItem *)node->data;
		if (itv.addr > _ci->tree_itv->addr) {
			_ci->tree_itv->size = itv.addr - _ci->tree_itv->addr;
			node = r_rbnode_next (node);
			_ci = node? (RIOCacheItem *)node->data: NULL;
		}
		while (_ci && r_itv_include (itv, _ci->tree_itv[0])) {
			node = r_rbnode_next (node);
			r_crbtree_delete (io->cache->tree, _ci, _ci_start_cmp_cb, NULL);
			R_FREE (_ci->tree_itv);
			_ci = node? (RIOCacheItem *)node->data: NULL;
		}
		if (_ci && r_itv_contain (itv, _ci->tree_itv->addr)) {
			_ci->tree_itv->size = r_itv_end (_ci->tree_itv[0]) - r_itv_end (itv);
			_ci->tree_itv->addr = r_itv_end (itv);
		}
	}
	r_crbtree_insert (io->cache->tree, ci, _ci_start_cmp_cb, NULL);
	r_pvector_push (io->cache->vec, ci);
	return true;
}

// R2_590 deprecate and use the _at method directly
R_API bool r_io_cache_read(RIO *io, ut64 addr, ut8 *buf, int len) {
	return r_io_cache_read_at (io, addr, buf, len);
}

R_API bool r_io_cache_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	r_return_val_if_fail (io && buf && (len > 0), false);
	RInterval itv = (RInterval){addr, len};
	RRBNode *node = _find_entry_ci_node (io->cache->tree, &itv);
	RIOCacheItem *ci = node? (RIOCacheItem *)node->data: NULL;
	const bool ret = !!ci;
	while (ci && r_itv_overlap (ci->tree_itv[0], itv)) {
		node = r_rbnode_next (node);
		RInterval its = r_itv_intersect (ci->tree_itv[0], itv);
		int itvlen = R_MIN (r_itv_size (its), r_itv_size (ci->itv));
		if (r_itv_begin (its) > addr) {
			// R_LOG_ERROR ("io-cache missfeature");
			ut64 aa = addr;
			// ut64 as = len;
			ut64 ba = r_itv_begin (its);
			ut64 bs = r_itv_size (its);
			// ut64 ca = r_itv_begin (ci->itv);
			// ut64 cs = r_itv_size (ci->itv);
			// eprintf ("%llx %llx - %llx %llx - %llx %llx\n", aa, as, ba, bs, ca, cs);
			int delta = (ba - aa);
			if (delta + bs > len) {
				itvlen = len - delta;
			}
			memcpy (buf + (ba - aa), ci->data, itvlen);
			// r_sys_breakpoint ();
		} else {
			st64 offa = addr - r_itv_begin (its);
			st64 offb = r_itv_begin (its) - r_itv_begin (ci->itv);
			// eprintf ("OFFA (addr %llx iv %llx) %llx %llx\n", addr, r_itv_begin (its), offa, offb);
			memcpy (buf + offa, ci->data + offb, itvlen);
		}
		ci = node? (RIOCacheItem *)node->data: NULL;
	}
	return ret;
}

R_API bool r_io_cache_at(RIO *io, ut64 addr) {
	r_return_val_if_fail (io, false);
	RInterval itv = (RInterval){addr, 0};
	return !!_find_entry_ci_node (io->cache->tree, &itv);
}

// this uses closed boundary input
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to) {
	r_return_val_if_fail (io && from <= to, 0);
	RInterval itv = (RInterval){from, (to + 1) - from};
	void **iter;
	ut32 invalidated_cache_bytes = 0;
	r_pvector_foreach_prev (io->cache->vec, iter) {
		RIOCacheItem *ci = (RIOCacheItem *)*iter;
		if (!r_itv_overlap (itv, ci->itv)) {
			continue;
		}
		if (r_itv_include (itv, ci->itv)) {
			if (ci->tree_itv) {
				invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
				r_crbtree_delete (io->cache->tree, ci, _ci_start_cmp_cb, NULL);
			}
			r_pvector_remove_data (io->cache->vec, ci);
			continue;
		}
		if (r_itv_include (ci->itv, itv)) {
			RInterval iitv = (RInterval){r_itv_end (itv), r_itv_end (ci->itv) - r_itv_end (itv)};
			RIOCacheItem *_ci = _io_cache_item_new (&iitv);
			memcpy (_ci->data, &ci->data[r_itv_end (itv) - r_itv_begin (ci->itv)], r_itv_size (_ci->itv));
			memcpy (_ci->odata, &ci->odata[r_itv_end (itv) - r_itv_begin (ci->itv)], r_itv_size (_ci->itv));
			ci->itv.size = itv.addr - ci->itv.addr;
			ci->data = realloc (ci->data, (size_t)r_itv_size (ci->itv));
			ci->odata = realloc (ci->odata, (size_t)r_itv_size (ci->itv));
			if (ci->tree_itv) {
				invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
				if (r_itv_overlap (ci->tree_itv[0], _ci->itv)) {
					_ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], _ci->itv);
					invalidated_cache_bytes -= r_itv_size (_ci->tree_itv[0]);
					r_crbtree_insert (io->cache->tree, _ci, _ci_start_cmp_cb, NULL);
				} else {
					R_FREE (_ci->tree_itv);
				}
				if (r_itv_overlap (ci->itv, ci->tree_itv[0])) {
					ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
					invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
				} else {
					r_crbtree_delete (io->cache->tree, ci, _ci_start_cmp_cb, NULL);
					R_FREE (ci->tree_itv);
				}
			} else {
				R_FREE (_ci->tree_itv);
			}
			r_pvector_push (io->cache->vec, _ci);
			continue;
		}
		if (r_itv_begin (ci->itv) < r_itv_begin (itv)) {
			ci->itv.size = itv.addr - ci->itv.addr;
			ci->data = realloc (ci->data, (size_t)r_itv_size (ci->itv));
			ci->odata = realloc (ci->odata, (size_t)r_itv_size (ci->itv));
			if (ci->tree_itv) {
				if (!r_itv_overlap (ci->itv, ci->tree_itv[0])) {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					r_crbtree_delete (io->cache->tree, ci, _ci_start_cmp_cb, NULL);
					R_FREE (ci->tree_itv);
				} else {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
					invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
				}
			}
			continue;
		}
		memmove (ci->data, &ci->data[r_itv_end (itv) - r_itv_begin (ci->itv)],
			r_itv_end (ci->itv) - r_itv_end (itv));
		memmove (ci->odata, &ci->odata[r_itv_end (itv) - r_itv_begin (ci->itv)],
			r_itv_end (ci->itv) - r_itv_end (itv));
		ci->itv.size = r_itv_end (ci->itv) - r_itv_end (itv);
		ci->itv.addr = r_itv_end (itv);	//this feels so wrong
		if (ci->tree_itv) {
			if (!r_itv_overlap (ci->itv, ci->tree_itv[0])) {
				invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
				r_crbtree_delete (io->cache->tree, ci, _ci_start_cmp_cb, NULL);
				R_FREE (ci->tree_itv);
			} else {
				invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
				ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
				invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
			}
		}
	}
	return invalidated_cache_bytes;
}

// this uses closed boundary input
R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to) {
	r_return_if_fail (io && from <= to);
	if (from == 0LL && to == UT64_MAX) {
		RRBNode *node = r_crbtree_first_node (io->cache->tree);
		while (node) {
			RIOCacheItem *ci = (RIOCacheItem *)node->data;
			node = r_rbnode_next (node);
			r_io_bank_write_at (io, io->bank, r_itv_begin (ci->tree_itv[0]),
				&ci->data[r_itv_begin (ci->tree_itv[0]) - r_itv_begin (ci->itv)],
				r_itv_size (ci->tree_itv[0]));
		}
		r_io_cache_reset (io, io->cached);
		return;
	}
	RInterval itv = (RInterval){from, (to + 1) - from};
	RRBNode *node = _find_entry_ci_node (io->cache->tree, &itv);
	if (!node) {
		return;
	}
	RIOCacheItem *ci = (RIOCacheItem *)node->data;
	while (ci && r_itv_overlap (itv, ci->tree_itv[0])) {
		RInterval its = r_itv_intersect (itv, ci->tree_itv[0]);
		r_io_bank_write_at (io, io->bank, r_itv_begin (its),
			&ci->data[r_itv_begin (its) - r_itv_begin (ci->itv)], r_itv_size (its));
		node = r_rbnode_next (node);
		ci = node? (RIOCacheItem *)node->data: NULL;
	}
	r_io_cache_invalidate (io, from, to);
}

R_API bool r_io_cache_list(RIO *io, int rad) {
	r_return_val_if_fail (io, false);
	size_t i, j = 0;
	void **iter;
	RIOCacheItem *ci;
	PJ *pj = NULL;
	if (rad == 2) {
		pj = pj_new ();
		pj_a (pj);
	}
	r_pvector_foreach (io->cache->vec, iter) {
		ci = *iter;
		const ut64 dataSize = r_itv_size (ci->itv);
		if (rad == 1) {
			io->cb_printf ("wx ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(ci->data[i] & 0xff));
			}
			io->cb_printf (" @ 0x%08"PFMT64x, r_itv_begin (ci->itv));
			io->cb_printf (" # replaces: ");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(ci->odata[i] & 0xff));
			}
			io->cb_printf ("\n");
		} else if (rad == 2) {
			pj_o (pj);
			pj_kn (pj, "idx", j);
			pj_kn (pj, "addr", r_itv_begin (ci->itv));
			pj_kn (pj, "size", dataSize);
			char *hex = r_hex_bin2strdup (ci->odata, dataSize);
			pj_ks (pj, "before", hex);
			free (hex);
			hex = r_hex_bin2strdup (ci->data, dataSize);
			pj_ks (pj, "after", hex);
			free (hex);
			pj_kb (pj, "written", false);
			pj_end (pj);
		} else if (rad == 0) {
			io->cb_printf ("idx=%"PFMTSZu" addr=0x%08"PFMT64x" size=%"PFMT64u" ", j,
				r_itv_begin (ci->itv), dataSize);
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", ci->odata[i]);
			}
			io->cb_printf (" -> ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", ci->data[i]);
			}
			io->cb_printf (" %s\n", "(not written)");
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

static RIOCacheItem *_clone_ci(RIOCacheItem *ci) {
	RIOCacheItem *clone = R_NEWCOPY (RIOCacheItem, ci);
	if (clone) {
		clone->data = R_NEWS (ut8, r_itv_size (ci->itv));
		clone->odata = R_NEWS (ut8, r_itv_size (ci->itv));
		memcpy (clone->data, ci->data, (size_t)r_itv_size (ci->itv));
		memcpy (clone->odata, ci->odata, (size_t)r_itv_size (ci->itv));
		if (ci->tree_itv) {
			clone->tree_itv = R_NEWCOPY (RInterval, ci->tree_itv);
		}
	}
	return clone;
}

R_API RIOCache *r_io_cache_clone(RIO *io) {
	r_return_val_if_fail (io, NULL);
	if (!io->cache) {
		return NULL;
	}
	RIOCache *clone = R_NEW (RIOCache);
	clone->tree = r_crbtree_new (NULL);
	clone->vec = r_pvector_new ((RPVectorFree)_io_cache_item_free);
	void **iter;
	r_pvector_foreach_prev (io->cache->vec, iter) {
		RIOCacheItem *ci = _clone_ci ((RIOCacheItem *)*iter);
		r_pvector_push (clone->vec, ci);
		if (ci->tree_itv) {
			r_crbtree_insert (clone->tree, clone, _ci_start_cmp_cb, NULL);
		}
	}
	return clone;
}

R_API void r_io_cache_replace(RIO *io, RIOCache *cache) {
	r_return_if_fail (io && cache);
	const ut32 cached = io->cached;
	r_io_cache_fini (io);
	io->cache = cache;
	io->cached = cached;
}
#endif
