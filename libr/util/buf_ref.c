/* radare - LGPL - Copyright 2009-2020 - ret2libc */

#include <r_util.h>

struct buf_ref_user {
	RBuffer *parent;
	ut64 offset;
	ut64 size;
};

static bool buf_ref_init(RBuffer *b, const void *user) {
	const struct buf_ref_user *u = user;
	b->rb_ref = R_NEW0 (RBufferRef);
	if (!b->rb_ref) {
		return false;
	}

	// NOTE: we only support readonly ref-buffers for now. Supporting
	// read-write would mean to choose how we want to handle writing to the
	// referencer. Copy-on-write? Write to the buffer underneath?
	ut64 parent_sz = r_buf_size (u->parent);
	b->readonly = true;
	b->rb_ref->parent = r_buf_ref (u->parent);
	b->rb_ref->base = R_MIN (u->offset, parent_sz);
	b->rb_ref->size = R_MIN (parent_sz - b->rb_ref->base, u->size);
	return true;
}

static bool buf_ref_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_ref);
	r_buf_free (b->rb_ref->parent);
	R_FREE (b->rb_ref);
	return true;
}

static bool buf_ref_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_ref);
	const ut64 parent_sz = r_buf_size (b->rb_ref->parent);
	b->rb_ref->size = R_MIN (parent_sz - b->rb_ref->base, newsize);
	return true;
}

static st64 buf_ref_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_ref);
	if (b->rb_ref->size < b->rb_ref->cur) {
		return -1;
	}
	len = R_MIN (len, b->rb_ref->size - b->rb_ref->cur);
	st64 r = r_buf_read_at (b->rb_ref->parent, b->rb_ref->base + b->rb_ref->cur, buf, len);
	if (r < 0) {
		return r;
	}
	b->rb_ref->cur += r;
	return r;
}

static ut64 buf_ref_get_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_ref);
	return b->rb_ref->size;
}

static st64 buf_ref_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_ref);
	switch (whence) {
	case R_BUF_CUR:
		b->rb_ref->cur += addr;
		break;
	case R_BUF_SET:
		b->rb_ref->cur = addr;
		break;
	case R_BUF_END:
		b->rb_ref->cur = b->rb_ref->size + addr;
		break;
	default:
		R_WARN_IF_REACHED ();
		return -1;
	}
	return b->rb_ref->cur;
}

static const RBufferMethods buffer_ref_methods = {
	.init = buf_ref_init,
	.fini = buf_ref_fini,
	.read = buf_ref_read,
	.get_size = buf_ref_get_size,
	.resize = buf_ref_resize,
	.seek = buf_ref_seek,
};
