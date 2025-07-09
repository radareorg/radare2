/* radare - LGPL - Copyright 2009-2025 - pancake, ret2libc */

#define SAFE_MMAP 1

#include <r_util.h>
#if R2__UNIX__
#include <sys/mman.h>
#endif

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
	RMmap *map = b->rb_mmap->mmap;
#if 1
	if (newsize != map->len) {
		bool ok = r_file_mmap_resize (map, newsize);
		if (!ok) {
			return false;
		}
	}
#endif
	// eprintf ("buf_mmap_resize> mmaplen=%d newsize=%d\n", map->len, newsize);
	b->rb_mmap->bytes.length = newsize;
	b->rb_mmap->bytes.buf = map->buf;
	// map->len = newsize;
	return true;
}

static st64 buf_mmap_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_mmap);
	if (!b->rb_mmap->bytes.buf) {
		return 0;
	}
	// memset (buf, 0xff, len);
	RBufferBytes *bb = &b->rb_mmap->bytes;
#if SAFE_MMAP
	// TODO: RFile.mmapRead() instead
	RMmap *m = b->rb_mmap->mmap;
	ut64 realsize = r_file_mmap_size (m);
	if (realsize < 1) {
		return 0;
	}
	if (bb->length != realsize) {
		R_LOG_WARN ("mmap baked file changed size from %"PFMT64d" to %"PFMT64d", writing and reading the same file maybe?", bb->length, realsize);
		buf_mmap_resize (b, realsize);
		bb->length = realsize;
	}
	// eprintf ("REALSIZE %d\n", realsize);
	// eprintf ("OFFSET %d\n", bb->offset);
	ut64 left = realsize - bb->offset + 1;
#else
	ut64 left = bb->length - bb->offset;
#endif
	ut64 real_len = R_MIN (left, len);
	// eprintf ("READ off=%d len=%d left=%d return=%d\n", bb->offset, len, left, real_len);
	if (real_len < 1 || bb->offset >= bb->length) {
		memset (buf, 0xff, len);
		return -1;
	}
	// reproducer: cp /bin/ls aaa ; r2 -qcq -e io.va=0 -c "s 0x4000; wtf aaa" aaa
	memmove (buf, bb->buf + bb->offset, real_len);
	// XXX memcpy only works on aligned addresses which may cause segfaults on release builds
	// memcpy (buf, bb->buf + bb->offset, real_len);
	bb->offset += real_len;
	return real_len;
}

static st64 buf_mmap_write(RBuffer *b, const ut8 *buf, ut64 len) {
	// eprintf ("write mmap at %d '%s' %d\n", b->rb_mmap->bytes.offset, buf, len);
	// memmove (b->rb_mmap->bytes.buf + b->rb_mmap->bytes.offset, buf, len);
	R_WARN_IF_FAIL (b->rb_mmap);
	if (b->rb_mmap->bytes.offset + len >= b->rb_mmap->bytes.length) {
		bool r = r_buf_resize (b, b->rb_bytes->offset + len);
		if (!r) {
			return -1;
		}
	}
	memmove (b->rb_mmap->bytes.buf + b->rb_mmap->bytes.offset, buf, len);
#if R2__UNIX__
	msync (b->rb_mmap->bytes.buf + b->rb_mmap->bytes.offset, len, MS_SYNC);
#endif
	b->rb_mmap->bytes.offset += len;
	return len;
}

static st64 buf_mmap_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_mmap);
	if (whence == R_BUF_END) {
		st64 r = r_file_mmap_size (b->rb_mmap->mmap);
		b->rb_mmap->bytes.offset = r;
		b->rb_mmap->bytes.length = r;
		b->rb_mmap->mmap->len = r;
		return r;
	}
	if (R_UNLIKELY (addr < 0)) {
		if (addr > -(st64)UT48_MAX) {
	       		if (-addr > (st64)b->rb_mmap->bytes.offset) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	ut64 po = b->rb_mmap->bytes.offset;
	if (R_LIKELY (whence == R_BUF_SET)) {
		// 50%
		po = addr;
	} else if (whence == R_BUF_CUR) {
		// 20%
		po += addr;
	} else {
		// 5%
		po = b->rb_mmap->bytes.length + addr;
	}
	b->rb_mmap->bytes.offset = po;
	return po;
}

static ut64 buf_mmap_get_size(RBuffer *b) {
	ut64 r = r_file_mmap_size (b->rb_mmap->mmap);
	b->rb_bytes->length = r;
	b->rb_mmap->mmap->len = r;
	return r;
}

static const RBufferMethods buffer_mmap_methods = {
	.init = buf_mmap_init,
	.fini = buf_mmap_fini,
	.read = buf_mmap_read,
	.write = buf_mmap_write,
	// .read = buf_bytes_read,
	// .write = buf_bytes_write,
	// .get_size = buf_bytes_get_size,
	.get_size = buf_mmap_get_size,
	.resize = buf_mmap_resize,
	.seek = buf_mmap_seek,
};
