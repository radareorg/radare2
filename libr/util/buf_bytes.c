#include <r_util.h>

struct buf_bytes_user {
	const ut8 *data;
	const ut8 *data_steal;
	ut64 length;
	bool steal;
};

struct buf_bytes_priv {
	ut8 *buf;
	ut64 length;
	ut64 offset;
	bool is_bufowner;
};

static inline struct buf_bytes_priv *get_priv_bytes(RBuffer *b) {
	struct buf_bytes_priv *priv = (struct buf_bytes_priv *)b->priv;
	r_warn_if_fail (priv);
	return priv;
}

static bool buf_bytes_init(RBuffer *b, const void *user) {
	const struct buf_bytes_user *u = (const struct buf_bytes_user *)user;
	struct buf_bytes_priv *priv = R_NEW0 (struct buf_bytes_priv);
	if (!priv) {
		return false;
	}

	priv->offset = 0;
	priv->length = u->length;
	if (u->data_steal) {
		priv->buf = (ut8 *)u->data_steal;
		priv->is_bufowner = u->steal;
	} else {
		priv->buf = malloc (priv->length);
		if (!priv->buf) {
			free (priv);
			return NULL;
		}
		if (priv->length) {
			memmove (priv->buf, u->data, priv->length);
		}
		priv->is_bufowner = true;
	}
	b->priv = priv;
	return true;
}

static bool buf_bytes_fini(RBuffer *b) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	if (priv->is_bufowner) {
		free (priv->buf);
	}
	R_FREE (b->priv);
	return true;
}

static bool buf_bytes_resize(RBuffer *b, ut64 newsize) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	if (newsize > priv->length) {
		ut8 *t = realloc (priv->buf, newsize);
		if (!t) {
			return false;
		}
		priv->buf = t;
		memset (priv->buf + priv->length, b->Oxff_priv, newsize - priv->length);
	}
	priv->length = newsize;
	return true;
}

static st64 buf_bytes_read(RBuffer *b, ut8 *buf, ut64 len) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	ut64 real_len = priv->length < priv->offset? 0: R_MIN (priv->length - priv->offset, len);
	memmove (buf, priv->buf + priv->offset, real_len);
	priv->offset += real_len;
	return real_len;
}

static st64 buf_bytes_write(RBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	if (priv->offset > priv->length || priv->offset + len >= priv->length) {
		bool r = r_buf_resize (b, priv->offset + len);
		if (!r) {
			return -1;
		}
	}
	memmove (priv->buf + priv->offset, buf, len);
	priv->offset += len;
	return len;
}

static ut64 buf_bytes_get_size(RBuffer *b) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	return priv->length;
}

static st64 buf_bytes_seek(RBuffer *b, st64 addr, int whence) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	if (addr < 0 && (-addr) > (st64)priv->offset) {
		return -1;
	}

	switch (whence) {
	case R_BUF_CUR:
		priv->offset += addr;
		break;
	case R_BUF_SET:
		priv->offset = addr;
		break;
	case R_BUF_END:
		priv->offset = priv->length + addr;
		break;
	default:
		r_warn_if_reached ();
		return -1;
	}
	return priv->offset;
}

static ut8 *buf_bytes_get_whole_buf(RBuffer *b, ut64 *sz) {
	struct buf_bytes_priv *priv = get_priv_bytes (b);
	if (sz) {
		*sz = priv->length;
	}
	return priv->buf;
}

static const RBufferMethods buffer_bytes_methods = {
	.init = buf_bytes_init,
	.fini = buf_bytes_fini,
	.read = buf_bytes_read,
	.write = buf_bytes_write,
	.get_size = buf_bytes_get_size,
	.resize = buf_bytes_resize,
	.seek = buf_bytes_seek,
	.get_whole_buf = buf_bytes_get_whole_buf
};
