#include <r_util.h>

struct buf_mmap_user {
	const char *filename;
	int perm;
};

// "subclass"" of buf_bytes_priv
struct buf_mmap_priv {
	// NOTE: this needs to be first, so that bytes operations will work without changes
	struct buf_bytes_priv bytes_priv;
	RMmap *mmap;
};

static inline struct buf_mmap_priv *get_priv_mmap(RBuffer *b) {
	struct buf_mmap_priv *priv = (struct buf_mmap_priv *)b->priv;
	r_warn_if_fail (priv);
	return priv;
}

static bool buf_mmap_init(RBuffer *b, const void *user) {
	const struct buf_mmap_user *u = (const struct buf_mmap_user *)user;
	struct buf_mmap_priv *priv = R_NEW0 (struct buf_mmap_priv);
	if (!priv) {
		return false;
	}

	priv->mmap = r_file_mmap (u->filename, u->perm & R_PERM_W, 0);
	if (!priv->mmap) {
		free (priv);
		return false;
	}
	priv->bytes_priv.buf = priv->mmap->buf;
	priv->bytes_priv.length = priv->mmap->len;
	priv->bytes_priv.offset = 0;
	b->priv = priv;
	return true;
}

static bool buf_mmap_fini(RBuffer *b) {
	struct buf_mmap_priv *priv = get_priv_mmap (b);
	r_file_mmap_free (priv->mmap);
	R_FREE (b->priv);
	return true;
}

static bool buf_mmap_resize(RBuffer *b, ut64 newsize) {
	struct buf_mmap_priv *priv = get_priv_mmap (b);
	if (newsize > priv->mmap->len) {
		ut8 *t = r_mem_mmap_resize (priv->mmap, newsize);
		if (!t) {
			return false;
		}
		priv->bytes_priv.buf = t;
	}
	priv->bytes_priv.length = newsize;
	return true;
}

static const RBufferMethods buffer_mmap_methods = {
	.init = buf_mmap_init,
	.fini = buf_mmap_fini,
	.read = buf_bytes_read,
	.write = buf_bytes_write,
	.get_size = buf_bytes_get_size,
	.resize = buf_mmap_resize,
	.seek = buf_bytes_seek,
};
