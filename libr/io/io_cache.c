/* radare - LGPL - Copyright 2008-2024 - pancake, condret */

#include <r_io.h>

static int _ci_start_cmp_cb(void *incoming, void *in, void *user) {
	RIOCacheItem *incoming_ci = (RIOCacheItem *)incoming, *in_ci = (RIOCacheItem *)in;
	if (R_UNLIKELY (!in_ci->tree_itv)) {
		R_LOG_ERROR ("io cache tree corrupted");
		r_sys_backtrace ();
	}
	if (incoming_ci->tree_itv->addr < in_ci->tree_itv->addr) {
		return -1;
	}
	if (incoming_ci->tree_itv->addr > in_ci->tree_itv->addr) {
		return 1;
	}
	return 0;
}

static void iocache_layer_free(void *arg) {
	RIOCacheLayer *cl = arg;
	if (cl) {
		r_crbtree_free (cl->tree);
		r_pvector_free (cl->vec);
		// cl->cache.mode = 0;
		free (cl);
	}
}

static RIOCacheItem *iocache_item_new(RIO *io, RInterval *itv) {
	RIOCacheItem *ci = R_NEW0 (RIOCacheItem);
	if (R_LIKELY (ci)) {
		ci->data = R_NEWS (ut8, itv->size);
		ci->odata = R_NEWS (ut8, itv->size);
		ci->tree_itv = R_NEWCOPY (RInterval, itv);
		if (ci->data && ci->odata && ci->tree_itv) {
			ci->itv = (*itv);
			return ci;
		}
	}
	free (ci->odata);
	free (ci->data);
	free (ci);
	return NULL;
}

static void _io_cache_item_free(void *data) {
	RIOCacheItem *ci = (RIOCacheItem *)data;
	if (ci) {
		free (ci->tree_itv);
		free (ci->data);
		free (ci->odata);
		free (ci);
	}
}

R_API void r_io_cache_init(RIO *io) {
	R_RETURN_IF_FAIL (io);
	io->cache.layers = r_list_newf (iocache_layer_free);
	io->cache.mode = R_PERM_R | R_PERM_W;
	r_io_cache_push (io);
}

R_API void r_io_cache_fini(RIO *io) {
	R_RETURN_IF_FAIL (io);
	r_list_free (io->cache.layers);
}

R_API bool r_io_cache_empty(RIO *io) {
	RListIter *liter;
	RIOCacheLayer *layer;
	if (r_list_empty (io->cache.layers)) {
		return true;
	}
	r_list_foreach (io->cache.layers, liter, layer) {
		if (r_pvector_length (layer->vec) > 0) {
			return true;
		}
	}
	return false;
}

R_API void r_io_cache_reset(RIO *io) {
	R_RETURN_IF_FAIL (io);
	ut32 mode = io->cache.mode;
	r_io_cache_fini (io);
	r_io_cache_init (io);
	io->cache.mode = mode;
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
static RRBNode *_find_entry_ci_node(RRBTree *cache_tree, RInterval *itv) {
	RRBNode *node = r_crbtree_find_node (cache_tree, itv, _find_lowest_intersection_ci_cb, NULL);
	if (node) {
		RRBNode *prev = r_rbnode_prev (node);
		while (prev && r_itv_overlap (itv[0], ((RIOCacheItem *)(prev->data))->tree_itv[0])) {
			node = prev;
			prev = r_rbnode_prev (node);
		}
	}
	return node;
}

// write happens only in the last layer
R_API bool r_io_cache_write_at(RIO *io, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (io && buf && (len > 0), false);
	if (r_list_empty (io->cache.layers)) {
		return false;
	}
	if ((UT64_MAX - len + 1) < addr) {
		const int olen = len;
		len = UT64_MAX - addr + 1;
		if (!r_io_cache_write_at (io, 0ULL, &buf[len], olen - len)) {
			return false;
		}
	}
	RInterval itv = (RInterval){addr, len};
	RIOCacheItem *ci = iocache_item_new (io, &itv);
	if (!ci) {
		return false;
	}
	(void)r_io_read_at (io, addr, ci->odata, len); // ignore failed reads?
	memcpy (ci->data, buf, len);
	RIOCacheLayer *layer = r_list_last (io->cache.layers);
	RRBNode *node = _find_entry_ci_node (layer->tree, &itv);
	if (node) {
		RIOCacheItem *_ci = (RIOCacheItem *)node->data;
		if (itv.addr > _ci->tree_itv->addr) {
			_ci->tree_itv->size = itv.addr - _ci->tree_itv->addr;
			node = r_rbnode_next (node);
			_ci = node? (RIOCacheItem *)node->data: NULL;
		}
		while (_ci && r_itv_include (itv, _ci->tree_itv[0])) {
			node = r_rbnode_next (node);
			RIOCacheItem *tci = (RIOCacheItem *)r_crbtree_take (layer->tree, _ci, _ci_start_cmp_cb, NULL);
			if (R_UNLIKELY (_ci != tci)) {
				R_LOG_ERROR ("missmatch: %p != %p", _ci, tci);
				R_LOG_ERROR ("_ci @ %p: [0x%"PFMT64x" - 0x%"PFMT64x"]",
					_ci, _ci->tree_itv[0].addr, r_itv_end (_ci->tree_itv[0]) - 1);
				R_LOG_ERROR ("tci @ %p: [0x%"PFMT64x" - 0x%"PFMT64x"]",
					tci, tci->tree_itv[0].addr, r_itv_end (tci->tree_itv[0]) - 1);
			}
			R_FREE (_ci->tree_itv);
			_ci = node? (RIOCacheItem *)node->data: NULL;
		}
		if (_ci && r_itv_contain (itv, _ci->tree_itv->addr)) {
			_ci->tree_itv->size = r_itv_end (_ci->tree_itv[0]) - r_itv_end (itv);
			_ci->tree_itv->addr = r_itv_end (itv);
		}
	}
	r_crbtree_insert (layer->tree, ci, _ci_start_cmp_cb, NULL);
	r_pvector_push (layer->vec, ci);
	return true;
}

// read happens by iterating over all the layers
R_API bool r_io_cache_read_at(RIO *io, ut64 addr, ut8 *buf, int len) {
	R_RETURN_VAL_IF_FAIL (io && buf && (len > 0), false);
#if 0
	// X perm is the io.cache.. this is disabled by bin.cache.. so many tests fail because of this
	if (!(io->cache.mode & R_PERM_X)) {
		return false;
	}
#endif
	if ((UT64_MAX - len + 1) < addr) {
		const int olen = len;
		len = UT64_MAX - addr + 1;
		if (!r_io_cache_read_at (io, 0ULL, &buf[len], olen - len)) {
			return false;
		}
	}
	RIOCacheLayer *layer;
	RListIter *iter;
	RInterval itv = (RInterval){addr, len};
	bool ret = false;
	r_list_foreach (io->cache.layers, iter, layer) {
		RRBNode *node = _find_entry_ci_node (layer->tree, &itv);
		if (!node) {
			continue;
		}
		ret = true;
		RIOCacheItem *ci = (RIOCacheItem *)node->data;
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
				st64 delta = (ba - aa);
				if (delta + bs > len) {
					itvlen = len - delta;
				}
				st64 offb = r_itv_begin (its) - r_itv_begin (ci->itv);
				// eprintf ("ITVLEN = %d (%d)\n", itvlen, delta);
				memcpy (buf + delta, ci->data + offb, itvlen);
				// r_sys_breakpoint ();
			} else {
				st64 offa = addr - r_itv_begin (its);
				st64 offb = r_itv_begin (its) - r_itv_begin (ci->itv);
				// eprintf ("OFFA (addr %llx iv %llx) %llx %llx\n", addr, r_itv_begin (its), offa, offb);
				memcpy (buf + offa, ci->data + offb, itvlen);
			}
			ci = node? (RIOCacheItem *)node->data: NULL;
		}
	}
	return ret;
}

R_API bool r_io_cache_writable(RIO *io) {
	const ut32 mode = R_PERM_X | R_PERM_W;
	return (io->cache.mode & mode) == mode;
}

R_API bool r_io_cache_readable(RIO *io) {
	const ut32 mode = R_PERM_R;
	return (io->cache.mode & mode) == mode;
}

// used only by the testsuite
R_API bool r_io_cache_at(RIO *io, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (io, false);
	RInterval itv = (RInterval){addr, 0};
	RIOCacheLayer *layer;
	RListIter *liter;
	r_list_foreach (io->cache.layers, liter, layer) {
		if (_find_entry_ci_node (layer->tree, &itv) != NULL) {
			return true;
		}
	}
	return false;
}

// this uses closed boundary input
R_API int r_io_cache_invalidate(RIO *io, ut64 from, ut64 to, bool many) {
	R_RETURN_VAL_IF_FAIL (io && from <= to, 0);
	RInterval itv = (RInterval){from, (to + 1) - from};
	void **iter;
	ut32 invalidated_cache_bytes = 0;
	RIOCacheLayer *layer;
	RListIter *liter;
	r_list_foreach (io->cache.layers, liter, layer) {
		r_pvector_foreach_prev (layer->vec, iter) {
			RIOCacheItem *ci = (RIOCacheItem *)*iter;
			if (!r_itv_overlap (itv, ci->itv)) {
				continue;
			}
			ci->written = false;
			if (r_itv_include (itv, ci->itv)) {
				if (ci->tree_itv) {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					r_crbtree_delete (layer->tree, ci, _ci_start_cmp_cb, NULL);
					R_FREE (ci->tree_itv);
				}
				r_pvector_remove_data (layer->vec, ci);
				continue;
			}
			if (r_itv_include (ci->itv, itv)) {
				RInterval iitv = (RInterval){r_itv_end (itv), r_itv_end (ci->itv) - r_itv_end (itv)};
				RIOCacheItem *_ci = iocache_item_new (io, &iitv);
				if (!_ci) {
					continue;
				}
				memcpy (_ci->data, &ci->data[r_itv_end (itv) - r_itv_begin (ci->itv)], r_itv_size (_ci->itv));
				memcpy (_ci->odata, &ci->odata[r_itv_end (itv) - r_itv_begin (ci->itv)], r_itv_size (_ci->itv));
				ci->itv.size = itv.addr - ci->itv.addr;
				ut8 *cidata = realloc (ci->data, (size_t)r_itv_size (ci->itv));
				if (cidata) {
					ci->data = cidata;
				} else {
					R_LOG_WARN ("first realloc failed");
					continue;
				}
				ut8 *ciodata = realloc (ci->odata, (size_t)r_itv_size (ci->itv));
				if (ciodata) {
					ci->odata = ciodata;
				} else {
					R_LOG_WARN ("second realloc failed");
					continue;
				}
				if (ci->tree_itv) {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					if (r_itv_overlap (ci->tree_itv[0], _ci->itv)) {
						_ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], _ci->itv);
						invalidated_cache_bytes -= r_itv_size (_ci->tree_itv[0]);
						r_crbtree_insert (layer->tree, _ci, _ci_start_cmp_cb, NULL);
					} else {
						R_FREE (_ci->tree_itv);
					}
					if (r_itv_overlap (ci->itv, ci->tree_itv[0])) {
						ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
						invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
					} else {
						r_crbtree_delete (layer->tree, ci, _ci_start_cmp_cb, NULL);
						R_FREE (ci->tree_itv);
					}
				} else {
					R_FREE (_ci->tree_itv);
				}
				r_pvector_push (layer->vec, _ci);
				continue;
			}
			if (r_itv_begin (ci->itv) < r_itv_begin (itv)) {
				ci->itv.size = itv.addr - ci->itv.addr;
				ut8 *cidata = realloc (ci->data, (size_t)r_itv_size (ci->itv));
				ut8 *ciodata = realloc (ci->odata, (size_t)r_itv_size (ci->itv));
				if (cidata && ciodata) {
					ci->data = cidata;
					ci->odata = ciodata;
				} else {
					R_LOG_ERROR ("Invalid size");
					continue;
				}
				if (ci->tree_itv) {
					if (!r_itv_overlap (ci->itv, ci->tree_itv[0])) {
						invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
						r_crbtree_delete (layer->tree, ci, _ci_start_cmp_cb, NULL);
						R_FREE (ci->tree_itv);
					} else {
						invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
						ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
						invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
					}
				}
				continue;
			}
			memcpy (ci->data, &ci->data[r_itv_end (itv) - r_itv_begin (ci->itv)],
				r_itv_end (ci->itv) - r_itv_end (itv));
			memcpy (ci->odata, &ci->odata[r_itv_end (itv) - r_itv_begin (ci->itv)],
				r_itv_end (ci->itv) - r_itv_end (itv));
			ci->itv.size = r_itv_end (ci->itv) - r_itv_end (itv);
			ci->itv.addr = r_itv_end (itv);	//this feels so wrong
			if (ci->tree_itv) {
				if (!r_itv_overlap (ci->itv, ci->tree_itv[0])) {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					r_crbtree_delete (layer->tree, ci, _ci_start_cmp_cb, NULL);
					R_FREE (ci->tree_itv);
				} else {
					invalidated_cache_bytes += r_itv_size (ci->tree_itv[0]);
					ci->tree_itv[0] = r_itv_intersect (ci->tree_itv[0], ci->itv);
					invalidated_cache_bytes -= r_itv_size (ci->tree_itv[0]);
				}
			}
		}
	}
	return invalidated_cache_bytes;
}

// this uses closed boundary input
R_API void r_io_cache_commit(RIO *io, ut64 from, ut64 to, bool many) {
	R_RETURN_IF_FAIL (io && from <= to);
	RListIter *iter;
	RIOCacheLayer *layer;
	r_list_foreach (io->cache.layers, iter, layer) {
		if (from == 0LL && to == UT64_MAX) {
			RRBNode *node = r_crbtree_first_node (layer->tree);
			while (node) {
				RIOCacheItem *ci = (RIOCacheItem *)node->data;
				node = r_rbnode_next (node);
				bool write_ok = r_io_bank_write_at (io, io->bank, r_itv_begin (ci->tree_itv[0]),
					&ci->data[r_itv_begin (ci->tree_itv[0]) - r_itv_begin (ci->itv)],
					r_itv_size (ci->tree_itv[0]));
				if (write_ok) {
					ci->written = true;
				} else {
					R_LOG_ERROR ("cannot write at 0x%08"PFMT64x, r_itv_begin (ci->itv));
				}
			}
			r_crbtree_clear (layer->tree);
		} else {
			RInterval itv = (RInterval){from, (to + 1) - from};
			RRBNode *node = _find_entry_ci_node (layer->tree, &itv);
			if (node) {
				RIOCacheItem *ci = (RIOCacheItem *)node->data;
				while (ci && r_itv_overlap (itv, ci->tree_itv[0])) {
					RInterval its = r_itv_intersect (itv, ci->tree_itv[0]);
					r_io_bank_write_at (io, io->bank, r_itv_begin (its),
						&ci->data[r_itv_begin (its) - r_itv_begin (ci->itv)], r_itv_size (its));
					node = r_rbnode_next (node);
					ci = node? (RIOCacheItem *)node->data: NULL;
				}
				r_io_cache_invalidate (io, from, to, many);
			}
		}
		if (!many) {
			break;
		}
	}
}

static char *list(RIO *io, RIOCacheLayer *layer, PJ *pj, int rad) {
	void **iter;
	size_t i, j = 0;
	RStrBuf *sb = pj? NULL: r_strbuf_new ("");
	r_pvector_foreach (layer->vec, iter) {
		RIOCacheItem *ci = *iter;
		const ut64 dataSize = r_itv_size (ci->itv);
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "idx", j);
			pj_kn (pj, "addr", r_itv_begin (ci->itv));
			pj_kn (pj, "size", dataSize);
			char *hex = r_hex_bin2strdup (ci->odata, dataSize);
			pj_ks (pj, "after", hex);
			free (hex);
			hex = r_hex_bin2strdup (ci->data, dataSize);
			pj_ks (pj, "before", hex);
			free (hex);
			pj_kb (pj, "written", ci->written);
			pj_end (pj);
		} else if (rad == 0) {
			r_strbuf_appendf (sb, "idx=%"PFMTSZu" addr=0x%08"PFMT64x" size=%"PFMT64u" ", j,
					r_itv_begin (ci->itv), dataSize);
			for (i = 0; i < dataSize; i++) {
				r_strbuf_appendf (sb, "%02x", ci->odata[i]);
			}
			r_strbuf_append (sb, " -> ");
			for (i = 0; i < dataSize; i++) {
				r_strbuf_appendf (sb, "%02x", ci->data[i]);
			}
			r_strbuf_appendf (sb, " %s\n", ci->written? "(written)": "(not written)");
		} else if (rad == 1) {
			r_strbuf_append ("wx ");
			for (i = 0; i < dataSize; i++) {
				r_strbuf_appendf (sb, "%02x", (ut8)(ci->data[i] & 0xff));
			}
			r_strbuf_appendf (sb, " @ 0x%08"PFMT64x, r_itv_begin (ci->itv));
			r_strbuf_append (sb, " # replaces: ");
			for (i = 0; i < dataSize; i++) {
				r_strbuf_appendf (sb, "%02x", (ut8)(ci->odata[i] & 0xff));
			}
			r_strbuf_append (sb, "\n");
		}
		j++;
	}
	if (pj) {
		return NULL;
	}
	return r_strbuf_drain (sb);
}

R_API char *r_io_cache_list(RIO *io, int rad, bool many) {
	R_RETURN_IF_FAIL (io);
	if (r_list_empty (io->cache.layers)) {
		return;
	}
	char *res = NULL;
	PJ *pj = NULL;
	if (rad == 2 || rad == 'j') {
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_o (pj);
		pj_ka (pj, many? "layers": "layer");
	}
	RIOCacheLayer *layer;
	if (many) {
		RListIter *liter;
		r_list_foreach (io->cache.layers, liter, layer) {
			if (pj) {
				pj_a (pj);
			}
			if (pj) {
				pj_end (pj);
				pj_end (pj);
			} else {
				res = list (io, layer, pj, rad);
			}
		}
	} else {
		if (!r_list_empty (io->cache.layers)) {
			layer = r_list_last (io->cache.layers);
			res = list (io, layer, pj, rad);
		}
	}
	if (pj) {
		pj_end (pj);
		pj_end (pj);
		res = pj_drain (pj);
	}
	return res;
}

static RIOCacheLayer *iocache_layer_new(void) {
	RIOCacheLayer *cl = R_NEW (RIOCacheLayer);
	cl->tree = r_crbtree_new (NULL);
	cl->vec = r_pvector_new ((RPVectorFree)_io_cache_item_free);
	// cl->ci_cmp_cb = _ci_start_cmp_cb; // move into the tree
	return cl;
}

R_API void r_io_cache_push(RIO *io) {
	r_list_append (io->cache.layers, iocache_layer_new ());
}

R_API bool r_io_cache_pop(RIO *io) {
	if (!r_list_empty (io->cache.layers)) {
		RIOCacheLayer *cl = r_list_pop (io->cache.layers);
		iocache_layer_free (cl);
		return true;
	}
	return false;
}

R_API bool r_io_cache_undo(RIO *io) { // "wcu"
	R_RETURN_VAL_IF_FAIL (io, false);
	if (r_list_empty (io->cache.layers)) {
		return false;
	}
	RIOCacheLayer *layer = r_list_last (io->cache.layers);
	void **iter;
	r_pvector_foreach_prev (layer->vec, iter) {
		RIOCacheItem *c = *iter;
		ut32 mode = io->cache.mode;
		io->cache.mode = 0;
		r_io_write_at (io, r_itv_begin (c->itv), c->odata, r_itv_size (c->itv));
		c->written = false;
		io->cache.mode = mode;
		// tf is all this shit
		r_pvector_remove_data (layer->vec, c);
		RPVectorFree free_elem = layer->vec->v.free_user;
		if (c->tree_itv) {
			r_crbtree_delete (layer->tree, c, _ci_start_cmp_cb, NULL);
			R_FREE (c->tree_itv);
		}
		free_elem (c);
		break;
	}
	return true;
}

R_API bool r_io_cache_redo(RIO *io) { // "wcU"
	// TODO : not implemented
	return false;
}
