#include <r_types.h>
#include <r_util.h>

struct buf_file_user {
	const char *file;
	int perm;
	int mode;
};

struct buf_file_priv {
	int fd;
	ut8 tmp[8];
};

static inline struct buf_file_priv *get_priv_file(RBuffer *b) {
	struct buf_file_priv *priv = (struct buf_file_priv *)b->priv;
	r_warn_if_fail (priv);
	return priv;
}

static bool buf_file_init(RBuffer *b, const void *user) {
	const struct buf_file_user *u = (const struct buf_file_user *)user;
	struct buf_file_priv *priv = R_NEW0 (struct buf_file_priv);
	if (!priv) {
		return false;
	}
	int fd = r_sandbox_open (u->file, u->perm, u->mode);
	if (fd == -1) {
		free (priv);
		return false;
	}
	priv->fd = fd;
	b->priv = priv;
	return true;
}

static bool buf_file_fini(RBuffer *b) {
	struct buf_file_priv *priv = get_priv_file (b);
	r_sandbox_close (priv->fd);
	R_FREE (b->priv);
	return true;
}

static ut64 buf_file_get_size(RBuffer *b) {
	struct buf_file_priv *priv = get_priv_file (b);
	int pos = r_sandbox_lseek (priv->fd, 0, SEEK_CUR);
	int res = r_sandbox_lseek (priv->fd, 0, SEEK_END);
	r_sandbox_lseek (priv->fd, pos, SEEK_SET);
	return (ut64)res;
}

static st64 buf_file_read(RBuffer *b, ut8 *buf, ut64 len) {
	struct buf_file_priv *priv = get_priv_file (b);
	return r_sandbox_read (priv->fd, buf, len);
}

static st64 buf_file_write(RBuffer *b, const ut8 *buf, ut64 len) {
	struct buf_file_priv *priv = get_priv_file (b);
	return r_sandbox_write (priv->fd, buf, len);
}

static st64 buf_file_seek(RBuffer *b, st64 addr, int whence) {
	struct buf_file_priv *priv = get_priv_file (b);
	switch (whence) {
	case R_BUF_CUR: whence = SEEK_CUR; break;
	case R_BUF_SET: whence = SEEK_SET; break;
	case R_BUF_END: whence = SEEK_END; break;
	}
	return r_sandbox_lseek (priv->fd, addr, whence);
}

static bool buf_file_resize(RBuffer *b, ut64 newsize) {
	struct buf_file_priv *priv = get_priv_file (b);
	return r_sandbox_truncate (priv->fd, newsize) >= 0;
}

static const RBufferMethods buffer_file_methods = {
	.init = buf_file_init,
	.fini = buf_file_fini,
	.read = buf_file_read,
	.write = buf_file_write,
	.get_size = buf_file_get_size,
	.resize = buf_file_resize,
	.seek = buf_file_seek,
};
