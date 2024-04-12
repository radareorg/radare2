/* radare2 - LGPL - Copyright 2024 - pancake */

#include <r_util.h>

#if R2_USE_NEW_ABI

typedef struct buf_cache_priv {
	RBuffer *sb; // source/parent buffer
	RIOCacheLayer *cl;
	ut64 length;
	ut64 offset;
	bool is_bufowner;
} RBufCache;

static inline RBufCache *get_priv_cache_bytes(RBuffer *b) {
	RBufCache *priv = (RBufCache*)b->priv;
	r_warn_if_fail (priv);
	return priv;
}

static void iocache_item_free(void *data) {
	RIOCacheItem *ci = (RIOCacheItem *)data;
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
	cl->vec = r_pvector_new ((RPVectorFree)iocache_item_free);
	return cl;
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

static RIOCacheItem *iocache_item_new(RInterval *itv) {
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

static st64 buf_cache_read(RBuffer *b, ut8 *buf, ut64 len) {
	r_return_val_if_fail (b && buf && (len > 0), false);
	RBufCache *priv = get_priv_cache_bytes (b);
	ut64 addr = priv->offset;
	RInterval itv = (RInterval){addr, len};
	r_buf_read_at (priv->sb, addr, buf, len);
	RIOCacheLayer *layer = priv->cl; // r_list_last (io->cache.layers);
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
	r_return_val_if_fail (b && buf && (len > 0), 0);
	RBufCache *priv = get_priv_cache_bytes (b);
	ut64 addr = priv->offset;

	RInterval itv = (RInterval){addr, len};
	RIOCacheItem *ci = iocache_item_new (&itv);
	if (!ci) {
		return false;
	}
	r_buf_read_at (priv->sb, addr, ci->odata, len);
	// (void)r_io_read_at (io, addr, ci->odata, len); // ignore failed reads?
	memcpy (ci->data, buf, len);
	RIOCacheLayer *layer = priv->cl; // r_list_last (io->cache.layers);
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
	r_pvector_push (layer->vec, ci);
	return true;
}

//////////////////////////////////////////

static bool buf_cache_init(RBuffer *b, const void *user) {
	RBufCache *priv = R_NEW0 (RBufCache);
	if (!priv) {
		return false;
	}

	priv->cl = iocache_layer_new ();
	priv->offset = 0;
	priv->is_bufowner = false; // TODO never true
#if 0
	//priv->length = u->length;
	if (u->data_steal) {
		priv->buf = (ut8 *)u->data_steal;
		priv->is_bufowner = u->steal;
	} else {
#if 0
		size_t length = priv->length > 0? priv->length: 1;
		priv->buf = malloc (length);
		if (!priv->buf) {
			free (priv);
			return false;
		}
		if (priv->length > 0) {
			memmove (priv->buf, u->data, priv->length);
		}
#else
		if (priv->length > 0) {
			priv->buf = malloc (priv->length);
			if (!priv->buf) {
				free (priv);
				return false;
			}
			memmove (priv->buf, u->data, priv->length);
		}
#endif
		priv->is_bufowner = true;
	}
#endif
	b->priv = priv;
	return true;
}

static bool buf_cache_fini(RBuffer *b) {
	RBufCache *priv = get_priv_cache_bytes (b);
	if (priv->is_bufowner) {
		r_buf_free (priv->sb);
	}
	iocache_layer_free (priv->cl);
	R_FREE (b->priv);
	return true;
}

static bool buf_cache_resize(RBuffer *b, ut64 newsize) {
	RBufCache *priv = get_priv_cache_bytes (b);
	if (newsize > priv->length) {
		r_buf_resize (b, newsize);
	}
	priv->length = newsize;
	return true;
}

static ut64 buf_cache_get_size(RBuffer *b) {
	RBufCache *priv = get_priv_cache_bytes (b);
	return priv->length;
}

static st64 buf_cache_seek(RBuffer *b, st64 addr, int whence) {
	RBufCache *priv = get_priv_cache_bytes (b);
	if (addr < 0) {
		if (addr > -UT48_MAX) {
	       		if (-addr > (st64)priv->offset) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	if (R_LIKELY (whence == R_BUF_SET)) {
		// 50%
		priv->offset = addr;
	} else if (whence == R_BUF_CUR) {
		// 20%
		priv->offset += addr;
	} else {
		// 5%
		priv->offset = priv->length + addr;
	}
	return priv->offset;
}

static ut8 *buf_cache_get_whole_buf(RBuffer *b, ut64 *sz) {
	RBufCache *priv = get_priv_cache_bytes (b);
	if (sz) {
		*sz = priv->length;
	}
	R_LOG_ERROR ("wholebuf not supported for cachebuffer yet");
	return NULL; // priv->buf;
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
#endif
