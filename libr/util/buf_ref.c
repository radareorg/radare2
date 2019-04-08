#include <r_util.h>

struct buf_ref_user {
	RBuffer *parent;
};

struct buf_ref_priv {
	RBuffer *parent;
	ut64 cur;
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

	priv->parent = r_buf_ref (u->parent);
	b->priv = priv;
	return true;
}

static bool buf_ref_fini (RBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	r_buf_free (priv->parent);
	R_FREE (b->priv);
	return true;
}

static bool buf_ref_resize(RBuffer *b, ut64 newsize) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	return r_buf_resize (priv->parent, newsize);
}

static int buf_ref_read(RBuffer *b, ut8 *buf, size_t len) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	int r = r_buf_read_at (priv->parent, priv->cur, buf, len);
	priv->cur += r;
	return r;
}

static int buf_ref_write(RBuffer *b, const ut8 *buf, size_t len) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	int r = r_buf_write_at (priv->parent, priv->cur, buf, len);
	priv->cur += r;
	return r;
}

static ut64 buf_ref_get_size(RBuffer *b) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	return r_buf_size (priv->parent);
}

static int buf_ref_seek(RBuffer *b, st64 addr, int whence) {
	struct buf_ref_priv *priv = get_priv_ref (b);
	switch (whence) {
	case R_BUF_CUR:
		priv->cur += addr;
		break;
	case R_BUF_SET:
		priv->cur = addr;
		break;
	case R_BUF_END:
		priv->cur = r_buf_size (priv->parent) + addr;
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
	.write = buf_ref_write,
	.get_size = buf_ref_get_size,
	.resize = buf_ref_resize,
	.seek = buf_ref_seek,
};
