#include <r_util.h>

struct buf_ref_user {
	RBuffer *parent;
	ut64 offset;
	ut64 size;
};

struct buf_ref_priv {
	RBuffer *parent;
	ut64 cur;
	ut64 base;
	ut64 size;
};

static inline struct buf_ref_priv *get_priv_ref(RBuffer *b) {
	struct buf_ref_priv *priv = (struct buf_ref_priv *)b->priv;
	r_warn_if_fail (priv);
	return priv;
}

static bool buf_ref_init(RBuffer *b, const void *user) {
	const struct buf_ref_user *u = (const struct buf_ref_user *)user;
	struct buf_ref_priv *priv = R_NEW0 (struct buf_ref_priv);
	if (!priv) {
		return false;
	}

	// NOTE: we only support readonly ref-buffers for now. Supporting
	// read-write would mean to choose how we want to handle writing to the
	// referencer. Copy-on-write? Write to the buffer underneath?
	ut64 parent_sz = r_buf_size (u->parent);
	b->readonly = true;
	priv->parent = r_buf_ref (u->parent);
	priv->base = R_MIN (u->offset, parent_sz);
	priv->size = R_MIN (parent_sz - priv->base, u->size);
	b->priv = priv;
	return true;
}

static bool buf_ref_fini(RBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	r_buf_free (priv->parent);
	R_FREE (b->priv);
	return true;
}

static bool buf_ref_resize(RBuffer *b, ut64 newsize) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	ut64 parent_sz = r_buf_size (priv->parent);
	priv->size = R_MIN (parent_sz - priv->base, newsize);
	return true;
}

static st64 buf_ref_read(RBuffer *b, ut8 *buf, ut64 len) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	if (priv->size < priv->cur) {
		return -1;
	}
	len = R_MIN (len, priv->size - priv->cur);
	st64 r = r_buf_read_at (priv->parent, priv->base + priv->cur, buf, len);
	if (r < 0) {
		return r;
	}
	priv->cur += r;
	return r;
}

static ut64 buf_ref_get_size(RBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	return priv->size;
}

static st64 buf_ref_seek(RBuffer *b, st64 addr, int whence) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	switch (whence) {
	case R_BUF_CUR:
		priv->cur += addr;
		break;
	case R_BUF_SET:
		priv->cur = addr;
		break;
	case R_BUF_END:
		priv->cur = priv->size + addr;
		break;
	default:
		r_warn_if_reached ();
		return -1;
	}
	return priv->cur;
}

static const RBufferMethods buffer_ref_methods = {
	.init = buf_ref_init,
	.fini = buf_ref_fini,
	.read = buf_ref_read,
	.get_size = buf_ref_get_size,
	.resize = buf_ref_resize,
	.seek = buf_ref_seek,
};
