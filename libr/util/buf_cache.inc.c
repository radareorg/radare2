/* radare2 - LGPL - Copyright 2024 - pancake */

#include <r_util.h>
#include <r_io.h>

static void iocache_item_free(RIOCacheItem *ci) {
	if (ci) {
		free (ci->tree_itv);
		free (ci->data);
		free (ci->odata);
		free (ci);
	}
}

static RIOCacheLayer *iocache_layer_new(void) {
	RIOCacheLayer *cl = R_NEW (RIOCacheLayer);
	cl->tree = r_crbtree_new (NULL);
	cl->vec = RVecRIOCacheItemPtr_new ();
	return cl;
}

static void iocache_layer_free(void *arg) {
	RIOCacheLayer *cl = arg;
	if (cl) {
		r_crbtree_free (cl->tree);
		if (cl->vec) {
			RIOCacheItem **iter;
			R_VEC_FOREACH (cl->vec, iter) {
				iocache_item_free (*iter);
			}
			RVecRIOCacheItemPtr_free (cl->vec);
		}
		// cl->cache.mode = 0;
		free (cl);
	}
}

static RIOCacheItem *iocache_item_new(RInterval *itv) {
	RIOCacheItem *ci = R_NEW0 (RIOCacheItem);
	ci->data = R_NEWS (ut8, itv->size);
	ci->odata = R_NEWS (ut8, itv->size);
	ci->tree_itv = R_NEWCOPY (RInterval, itv);
	if (ci->data && ci->odata && ci->tree_itv) {
		ci->itv = (*itv);
		return ci;
	}
	free (ci->odata);
	free (ci->data);
	free (ci);
	return NULL;
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

static st64 buf_cache_seek(RBuffer *b, st64 addr, int whence);

static st64 buf_cache_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_RETURN_VAL_IF_FAIL (b && buf && (len > 0), false);
	R_WARN_IF_FAIL (b->rb_cache);
	ut64 addr = b->rb_cache->offset;
	if ((UT64_MAX - len + 1) < addr) {
		st64 ret = buf_cache_read (b, buf, UT64_MAX - addr + 1);
		len = len - (UT64_MAX - addr + 1);
		buf_cache_seek (b, 0LL, R_BUF_SET);
		return ret + buf_cache_read (b, &buf[UT64_MAX - addr + 1], len);
	}
	RInterval itv = (RInterval){addr, len};
	r_buf_read_at (b->rb_cache->sb, addr, buf, len);
	RIOCacheLayer *layer = b->rb_cache->cl; // r_list_last (io->cache.layers);
	RRBNode *node = _find_entry_ci_node (layer->tree, &itv);
	if (!node) {
		return len;
	}
	RIOCacheItem *ci = (RIOCacheItem *)node->data;
	while (ci && r_itv_overlap (ci->tree_itv[0], itv)) {
		node = r_rbnode_next (node);
		RInterval its = r_itv_intersect (ci->tree_itv[0], itv);
		int itvlen = R_MIN (r_itv_size (its), r_itv_size (ci->itv));
		if (r_itv_begin (its) > addr) {
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
			memcpy (buf + delta, ci->data + offb, itvlen);
		} else {
			st64 offa = addr - r_itv_begin (its);
			st64 offb = r_itv_begin (its) - r_itv_begin (ci->itv);
			memcpy (buf + offa, ci->data + offb, itvlen);
		}
		ci = node? (RIOCacheItem *)node->data: NULL;
	}
	return len;
}

static int _ci_start_cmp_cb(void *incoming, void *in, void *user) {
	RIOCacheItem *incoming_ci = (RIOCacheItem *)incoming;
	RIOCacheItem *in_ci = (RIOCacheItem *)in;
	if (incoming_ci->tree_itv->addr < in_ci->tree_itv->addr) {
		return -1;
	}
	if (incoming_ci->tree_itv->addr > in_ci->tree_itv->addr) {
		return 1;
	}
	return 0;
}

static st64 buf_cache_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_RETURN_VAL_IF_FAIL (b && buf && (len > 0), 0);
	R_WARN_IF_FAIL (b->rb_cache);
	ut64 addr = b->rb_cache->offset;

	if ((UT64_MAX - len + 1) < addr) {
		st64 ret = buf_cache_write (b, buf, UT64_MAX - addr + 1);
		len = len - (UT64_MAX - addr + 1);
		buf_cache_seek (b, 0LL, R_BUF_SET);
		return ret + buf_cache_write (b, &buf[UT64_MAX - addr + 1], len);
	}
	RInterval itv = (RInterval){addr, len};
	RIOCacheItem *ci = iocache_item_new (&itv);
	if (!ci) {
		return false;
	}
	r_buf_read_at (b->rb_cache->sb, addr, ci->odata, len);
	// (void)r_io_read_at (io, addr, ci->odata, len); // ignore failed reads?
	memcpy (ci->data, buf, len);
	RIOCacheLayer *layer = b->rb_cache->cl; // r_list_last (io->cache.layers);
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
			r_crbtree_delete (layer->tree, _ci, _ci_start_cmp_cb, NULL);
			R_FREE (_ci->tree_itv);
			_ci = node? (RIOCacheItem *)node->data: NULL;
		}
		if (_ci && r_itv_contain (itv, _ci->tree_itv->addr)) {
			_ci->tree_itv->size = r_itv_end (_ci->tree_itv[0]) - r_itv_end (itv);
			_ci->tree_itv->addr = r_itv_end (itv);
		}
	}
	r_crbtree_insert (layer->tree, ci, _ci_start_cmp_cb, NULL);
	RVecRIOCacheItemPtr_push_back (layer->vec, &ci);
	return true;
}

//////////////////////////////////////////

static bool buf_cache_init(RBuffer *b, const void *user) {
	// TODO take sb and owned from user instead of setting it in with_cache() after init
	b->rb_cache = R_NEW0 (RBufferCache);
	if (!b->rb_cache) {
		return false;
	}
	b->rb_cache->cl = iocache_layer_new ();
	return true;
}

static bool buf_cache_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_cache);
	if (b->rb_cache->is_bufowner) {
		r_buf_free (b->rb_cache->sb);
	}
	iocache_layer_free (b->rb_cache->cl);
	R_FREE (b->rb_cache->buf);
	R_FREE (b->rb_cache);
	return true;
}

static bool buf_cache_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_cache);
	if (newsize > b->rb_cache->length) {
		r_buf_resize (b, newsize);
	}
	b->rb_cache->length = newsize;
	return true;
}

static ut64 buf_cache_get_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_cache);
	return b->rb_cache->length;
}

static st64 buf_cache_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_cache);
	if (addr < 0) {
		if (addr > -(st64)UT48_MAX) {
			if (-addr > (st64)b->rb_cache->offset) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	if (R_LIKELY (whence == R_BUF_SET)) {
		// 50%
		b->rb_cache->offset = addr;
	} else if (whence == R_BUF_CUR) {
		// 20%
		b->rb_cache->offset += addr;
	} else {
		// 5%
		b->rb_cache->offset = b->rb_cache->length + addr;
	}
	return b->rb_cache->offset;
}

static ut8 *buf_cache_get_whole_buf(RBuffer *b, ut64 *sz) {
	R_WARN_IF_FAIL (b->rb_cache);
	if (sz) {
		*sz = b->rb_cache->length;
	}
	if (b->rb_cache->buf) {
		R_FREE (b->rb_cache->buf);
	}
	ut8 *nbuf = malloc (b->rb_cache->length);
	if (nbuf) {
		r_buf_read_at (b, 0, nbuf, b->rb_cache->length);
		b->rb_cache->buf = nbuf;
	}
	return b->rb_cache->buf;
}

static const RBufferMethods buffer_cache_methods = {
	.init = buf_cache_init,
	.fini = buf_cache_fini,
	.read = buf_cache_read,
	.write = buf_cache_write,
	.get_size = buf_cache_get_size,
	.resize = buf_cache_resize,
	.seek = buf_cache_seek,
	.get_whole_buf = buf_cache_get_whole_buf
};
