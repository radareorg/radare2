/* radare - LGPL - Copyright 2009-2026 - ret2libc */

#include <r_util.h>

typedef struct {
	RBNode rb;
	RBufferSparseItem si;
} SparseChunk;

// chunks are sorted by address and never overlap; the index lives behind the public struct
typedef struct {
	RBufferSparse pub;
	RBNode *chunks;
} SparseState;

static void buffer_sparse_item_free(void *a) {
	RBufferSparseItem *si = a;
	free (si->data);
	free (container_of (si, SparseChunk, si));
}

static int sparse_cmp_from(const void *incoming, const RBNode *in_tree, void *user) {
	const ut64 addr = *(const ut64 *)incoming;
	const ut64 from = container_of (in_tree, const SparseChunk, rb)->si.from;
	return (addr > from) - (addr < from);
}

// lower bound is the first chunk ending after addr
static int sparse_cmp_end(const void *incoming, const RBNode *in_tree, void *user) {
	const ut64 addr = *(const ut64 *)incoming;
	return addr < container_of (in_tree, const SparseChunk, rb)->si.to? -1: 1;
}

static ut64 sparse_end(SparseState *s) {
	RBNode *node = s->chunks;
	if (!node) {
		return 0;
	}
	while (node->child[1]) {
		node = node->child[1];
	}
	return container_of (node, SparseChunk, rb)->si.to;
}

static bool sparse_chunk_add(SparseState *s, ut64 addr, const ut8 *data, ut64 len) {
	SparseChunk *c = R_NEW0 (SparseChunk);
	c->si.data = malloc (len);
	if (!c->si.data) {
		free (c);
		return false;
	}
	memcpy (c->si.data, data, len);
	c->si.from = addr;
	c->si.to = addr + len;
	c->si.size = len;
	r_list_append (s->pub.sparse, &c->si);
	r_rbtree_insert (&s->chunks, &addr, &c->rb, sparse_cmp_from, NULL);
	return true;
}

//ret -1 if failed; # of bytes copied if success
static st64 sparse_write(SparseState *s, ut64 addr, const ut8 *data, ut64 len) {
	const ut64 olen = len;
	while (len > 0) {
		RBNode *node = r_rbtree_lower_bound (s->chunks, &addr, sparse_cmp_end, NULL);
		RBufferSparseItem *si = node? &container_of (node, SparseChunk, rb)->si: NULL;
		ut64 n = len;
		if (si && si->from <= addr) {
			n = R_MIN (len, si->to - addr);
			memcpy (si->data + addr - si->from, data, n);
		} else {
			// fill the gap up to the next chunk
			if (si && si->from - addr < len) {
				n = si->from - addr;
			}
			if (!sparse_chunk_add (s, addr, data, n)) {
				return -1;
			}
		}
		data += n;
		addr += n;
		len -= n;
	}
	return olen;
}

static bool buf_sparse_init(RBuffer *b, const void *user) {
	SparseState *s = R_NEW0 (SparseState);
	s->pub.sparse = r_list_newf (buffer_sparse_item_free);
	b->rb_sparse = &s->pub;
	return true;
}

static bool buf_sparse_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_sparse);
	r_list_free (b->rb_sparse->sparse);
	R_FREE (b->rb_sparse);
	return true;
}

static bool buf_sparse_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_sparse);
	SparseState *s = (SparseState *)b->rb_sparse;
	RListIter *iter, *tmp;
	RBufferSparseItem *si;

	r_list_foreach_safe (s->pub.sparse, iter, tmp, si) {
		if (si->from >= newsize) {
			r_rbtree_delete (&s->chunks, &si->from, sparse_cmp_from, NULL, NULL, NULL);
			r_list_delete (s->pub.sparse, iter);
		} else if (si->to > newsize) {
			si->to = newsize;
			si->size = newsize - si->from;
		}
	}
	if (sparse_end (s) < newsize) {
		return sparse_write (s, newsize - 1, &b->Oxff_priv, 1) == 1;
	}
	return true;
}

static ut64 buf_sparse_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_sparse);
	return sparse_end ((SparseState *)b->rb_sparse);
}

static st64 buf_sparse_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_sparse);
	SparseState *s = (SparseState *)b->rb_sparse;
	ut64 offset = s->pub.offset;
	const ut64 max = sparse_end (s);

	memset (buf, b->Oxff_priv, len);
	if (offset > max) {
		return -1;
	}
	RBIter it = r_rbtree_lower_bound_forward (s->chunks, &offset, sparse_cmp_end, NULL);
	SparseChunk *c;
	r_rbtree_iter_while (it, c, SparseChunk, rb) {
		RBufferSparseItem *si = &c->si;
		if (si->from >= offset + len) {
			break;
		}
		if (offset < si->from) {
			const ut64 l = R_MIN (offset + len - si->from, si->size);
			memcpy (buf + si->from - offset, si->data, l);
		} else {
			const ut64 l = R_MIN (si->to - offset, len);
			memcpy (buf, si->data + offset - si->from, l);
		}
	}
	ut64 r = R_MIN (max - offset, len);
	s->pub.offset += r;
	return r;
}

static st64 buf_sparse_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_sparse);
	st64 r = sparse_write ((SparseState *)b->rb_sparse, b->rb_sparse->offset, buf, len);
	if (r > 0) {
		b->rb_sparse->offset += r;
	}
	return r;
}

static st64 buf_sparse_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_sparse);
	if (addr < 0 && (-addr) > (st64)b->rb_sparse->offset) {
		return -1;
	}

	switch (whence) {
	case R_BUF_CUR:
		b->rb_sparse->offset += addr;
		break;
	case R_BUF_SET:
		b->rb_sparse->offset = addr;
		break;
	case R_BUF_END:
		b->rb_sparse->offset = sparse_end ((SparseState *)b->rb_sparse) + addr;
		break;
	default:
		R_WARN_IF_REACHED ();
		return -1;
	}
	return b->rb_sparse->offset;
}

static RList *buf_sparse_nonempty_list(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_sparse);
	RList *chunks = r_list_new ();
	RBIter it;
	SparseChunk *c;
	r_rbtree_foreach (((SparseState *)b->rb_sparse)->chunks, it, c, SparseChunk, rb) {
		r_list_append (chunks, &c->si);
	}
	return chunks;
}

static const RBufferMethods buffer_sparse_methods = {
	.init = buf_sparse_init,
	.fini = buf_sparse_fini,
	.read = buf_sparse_read,
	.write = buf_sparse_write,
	.get_size = buf_sparse_size,
	.resize = buf_sparse_resize,
	.seek = buf_sparse_seek,
	.nonempty_list = buf_sparse_nonempty_list,
};
