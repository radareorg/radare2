/* radare - LGPL - Copyright 2009-2020 - ret2libc */

#include <r_util.h>

static void buffer_sparse_item_free(void *a) {
	RBufferSparseItem *si = a;
	free (si->data);
	free (si);
}

static bool sparse_limits(RList *l, ut64 *max) {
	bool set = false;
	RBufferSparseItem *si;
	RListIter *iter;

	r_list_foreach (l, iter, si) {
		if (set) {
			if (max && si->to > *max) {
				*max = si->to;
			}
			continue;
		}
		set = true;
		if (max) {
			*max = si->to;
		}
	}
	return set;
}

static RBufferSparseItem *sparse_item_append(RList *l, ut64 addr, const ut8 *data, ut64 len) {
	if (!(l && data)) {
		return NULL;
	}
	RBufferSparseItem *si = R_NEW0 (RBufferSparseItem);
	if (!si) {
		return NULL;
	}
	si->data = calloc (sizeof (ut8), len);
	if (!si->data) {
		free (si);
		return NULL;
	}
	si->from = addr;
	si->to = addr + len;
	si->size = len;
	memcpy (si->data, data, len);
	return r_list_append (l, si)? si: NULL;
}

//ret -1 if failed; # of bytes copied if success
static st64 sparse_write(RList *l, ut64 addr, const ut8 *data, ut64 len) {
	RBufferSparseItem *si;
	RListIter *iter;
	ut64 olen = len;

	r_list_foreach (l, iter, si) {
		if (addr >= si->from && addr < si->to) {
			ut64 delta = addr - si->from;
			ut64 reallen = si->size - delta >= len? len: si->size - delta;
			memcpy (si->data + delta, data, reallen);
			data += reallen;
			len -= reallen;
			addr += reallen;
		}
		if (len == 0) {
			return olen;
		}
	}
	if (len > 0 && !sparse_item_append (l, addr, data, len)) {
		return -1;
	}
	return olen;
}

static bool buf_sparse_init(RBuffer *b, const void *user) {
	b->rb_sparse = R_NEW (RBufferSparse);
	if (!b->rb_sparse) {
		return false;
	}
	b->rb_sparse[0] = (RBufferSparse){.sparse = r_list_newf (buffer_sparse_item_free)};
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
	RListIter *iter, *tmp;
	RBufferSparseItem *si;

	r_list_foreach_safe (b->rb_sparse->sparse, iter, tmp, si) {
		if (si->from >= newsize) {
			r_list_delete (b->rb_sparse->sparse, iter);
		} else if (si->to >= newsize) {
			RBufferSparseItem *nsi = R_NEW (RBufferSparseItem);
			nsi->from = si->from;
			nsi->to = newsize;
			nsi->size = nsi->to - nsi->from;
			ut8 *tmp = realloc (si->data, si->size);
			if (!tmp) {
				free (nsi);
				return false;
			}
			// otherwise it will be double-freed by r_list_delete
			si->data = NULL;
			nsi->data = tmp;
			nsi->written = si->written;
			r_list_append (b->rb_sparse->sparse, nsi);
			r_list_delete (b->rb_sparse->sparse, iter);
		}
	}
	ut64 max;
	max = sparse_limits (b->rb_sparse->sparse, &max)? max: 0;
	if (max < newsize) {
		return !!sparse_write (b->rb_sparse->sparse, newsize - 1, &b->Oxff_priv, 1);
	}
	return true;
}

static ut64 buf_sparse_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_sparse);
	ut64 max;

	return sparse_limits (b->rb_sparse->sparse, &max)? max: 0;
}

static st64 buf_sparse_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_sparse);
	RBufferSparseItem *si;
	RListIter *iter;
	ut64 max = 0;

	memset (buf, b->Oxff_priv, len);
	r_list_foreach (b->rb_sparse->sparse, iter, si) {
		if (max < si->to) {
			max = si->to;
		}
		if (!(b->rb_sparse->offset < si->to && si->from < b->rb_sparse->offset + len)) {
			continue;
		}
		if (b->rb_sparse->offset < si->from) {
			const ut64 l = R_MIN (b->rb_sparse->offset + len - si->from, si->size);
			memcpy (buf + si->from - b->rb_sparse->offset, si->data, l);
		} else {
			const ut64 l = R_MIN (si->to - b->rb_sparse->offset, len);
			memcpy (buf, si->data + b->rb_sparse->offset - si->from, l);
		}
	}
	if (b->rb_sparse->offset > max) {
		return -1;
	}
	ut64 r = R_MIN (max - b->rb_sparse->offset, len);
	b->rb_sparse->offset += r;
	return r;
}

static st64 buf_sparse_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_sparse);
	st64 r = sparse_write (b->rb_sparse->sparse, b->rb_sparse->offset, buf, len);
	b->rb_sparse->offset += r;
	return r;
}

static st64 buf_sparse_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_sparse);
	ut64 max;
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
		if (!sparse_limits (b->rb_sparse->sparse, &max)) {
			max = 0;
		}
		b->rb_sparse->offset = max + addr;
		break;
	default:
		R_WARN_IF_REACHED ();
		return -1;
	}
	return b->rb_sparse->offset;
}

static RList *buf_sparse_nonempty_list(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_sparse);
	return r_list_clone (b->rb_sparse->sparse, NULL);
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
