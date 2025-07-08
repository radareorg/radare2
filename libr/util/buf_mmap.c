/* radare - LGPL - Copyright 2009-2025 - pancake, ret2libc */

#define SAFE_MMAP 1

#include <r_util.h>

struct buf_mmap_user {
	const char *filename;
	int perm;
};

static bool buf_mmap_init(RBuffer *b, const void *user) {
	const struct buf_mmap_user *u = user;
	RMmap *map = r_file_mmap (u->filename, u->perm & R_PERM_W, 0);
	if (!map) {
		return false;
	}
	b->rb_mmap = R_NEW0 (RBufferMmap);
	b->rb_mmap->mmap = map;
	b->rb_mmap->bytes.buf = b->rb_mmap->mmap->buf;
	b->rb_mmap->bytes.length = b->rb_mmap->mmap->len;
	b->rb_mmap->bytes.offset = 0;
	return true;
}

static bool buf_mmap_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_mmap);
	r_file_mmap_free (b->rb_mmap->mmap);
	R_FREE (b->rb_mmap);
	return true;
}

static bool buf_mmap_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_mmap);
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

static st64 buf_mmap_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (!b->rb_bytes->buf) {
		return 0;
	}
	RBufferBytes *bb = &b->rb_mmap->bytes;
#if SAFE_MMAP
	RMmap *m = b->rb_mmap->mmap;
	ut64 realsize = r_file_mmap_size (m);
	if (bb->length != realsize) {
		R_LOG_WARN ("Baked mmap size changed from %"PFMT64d" to %"PFMT64d", writing and reading the same file maybe?", bb->length, realsize);
		bb->length = realsize;
	}
	ut64 left = realsize - bb->offset;
#else
	ut64 left = bb->length - bb->offset;
#endif
	ut64 real_len = bb->length < bb->offset? 0: R_MIN (left, len);
	if (real_len < 1 || b->rb_bytes->offset >= bb->length) {
		return -1;
	}
	// reproducer: cp /bin/ls aaa ; r2 -qcq -e io.va=0 -c 's 0x4000;wtf aaa' aaa
	memmove (buf, b->rb_bytes->buf + b->rb_bytes->offset, real_len);
	// XXX memcpy only works on aligned addresses which may cause segfaults on release builds
	// memcpy (buf, b->rb_bytes->buf + b->rb_bytes->offset, real_len);
	b->rb_bytes->offset += real_len;
	return real_len;
}

static const RBufferMethods buffer_mmap_methods = {
	.init = buf_mmap_init,
	.fini = buf_mmap_fini,
	.read = buf_mmap_read,
	//.read = buf_bytes_read,
	.write = buf_bytes_write,
	.get_size = buf_bytes_get_size,
	.resize = buf_mmap_resize,
	.seek = buf_bytes_seek,
};
