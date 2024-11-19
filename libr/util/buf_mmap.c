/* radare - LGPL - Copyright 2009-2020 - ret2libc */

#include <r_util.h>

struct buf_mmap_user {
	const char *filename;
	int perm;
};

static bool buf_mmap_init(RBuffer *b, const void *user) {
	const struct buf_mmap_user *u = user;
	b->rb_mmap = R_NEW0 (RBufferMmap);
	if (!b->rb_mmap) {
		return false;
	}

	b->rb_mmap->mmap = r_file_mmap (u->filename, u->perm & R_PERM_W, 0);
	if (!b->rb_mmap->mmap) {
		free (b->rb_mmap);
		return false;
	}
	b->rb_mmap->bytes.buf = b->rb_mmap->mmap->buf;
	b->rb_mmap->bytes.length = b->rb_mmap->mmap->len;
	b->rb_mmap->bytes.offset = 0;
	return true;
}

static bool buf_mmap_fini(RBuffer *b) {
	r_warn_if_fail (b->rb_mmap);
	r_file_mmap_free (b->rb_mmap->mmap);
	R_FREE (b->rb_mmap);
	return true;
}

static bool buf_mmap_resize(RBuffer *b, ut64 newsize) {
	r_warn_if_fail (b->rb_mmap);
	if (newsize > b->rb_mmap->mmap->len) {
		ut8 *t = r_mem_mmap_resize (b->rb_mmap->mmap, newsize);
		if (!t) {
			return false;
		}
		b->rb_mmap->bytes.buf = t;
	}
	b->rb_mmap->bytes.length = newsize;
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
