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
	if (newsize != map->len) {
		bool ok = r_file_mmap_resize (map, newsize);
		if (!ok) {
			return false;
		}
		// After resize, ensure the buffer's offset is still within bounds
		if (b->rb_mmap->offset > newsize) {
			b->rb_mmap->offset = newsize;
		}
	}
	return true;
}

static st64 buf_mmap_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_mmap);
	RBufferMmap *bm = b->rb_mmap;
	if (!bm->mmap->buf) {
		return 0;
	}
	RMmap *m = b->rb_mmap->mmap;
	// memset (buf, 0xff, len);
#if SAFE_MMAP
	// TODO: implement and use RFile.mmapRead() instead
	ut64 oldsize = m->len;
	ut64 currsize = r_file_mmap_size (m);
	if (currsize < 1) {
		return 0;
	}
	if (currsize != oldsize) {
		R_LOG_WARN ("mmap baked file changed size from %"PFMT64d" to %"PFMT64d", writing and reading the same file maybe?", m->len, currsize);
		// buf_mmap_resize (b, currsize);
	}
	// eprintf ("REALSIZE %d\n", realsize);
	// eprintf ("OFFSET %d\n", bb->offset);
	ut64 left = currsize - bm->offset;
#else
	ut64 left = m->len - bm->offset;
#endif
	ut64 real_len = R_MIN (left, len);
	// eprintf ("READ off=%d len=%d left=%d return=%d\n", bb->offset, len, left, real_len);
	if (real_len < 1 || bm->offset >= m->len) {
		memset (buf, 0xff, len);
		return -1;
	}
	// reproducer: cp /bin/ls aaa ; r2 -qcq -e io.va=0 -c "s 0x4000; wtf aaa" aaa
	memmove (buf, m->buf + bm->offset, real_len);
	// XXX memcpy only works on aligned addresses which may cause segfaults on release builds
	// memcpy (buf, bb->buf + bb->offset, real_len);
	bm->offset += real_len;
	return real_len;
}

static st64 buf_mmap_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->type == R_BUFFER_MMAP);
	RBufferMmap *bm = b->rb_mmap;
	if (bm->offset + len > bm->mmap->len) {
		bool r = r_buf_resize (b, bm->offset + len);
		if (!r) {
			return -1;
		}
		// After resize operation, ensure we're working with the correct buffer pointer
		// since it may have been remapped
	}
	if (!bm->mmap->buf) {
		return -1;
	}
	int left = bm->mmap->len - bm->offset;
	int rlen = R_MIN (len, left);
	memcpy (bm->mmap->buf + bm->offset, buf, rlen);
	// memmove (bm->mmap->buf + bm->offset, buf, len);
#if R2__UNIX__ && !__wasi__
	// msync (bm->mmap->buf + bm->offset, len, MS_SYNC);
	msync (bm->mmap->buf, len, MS_SYNC);
#endif
	bm->offset += rlen;
	return rlen;
}

static st64 buf_mmap_seek(RBuffer *b, st64 addr, int whence) {
	RBufferMmap *bm = b->rb_mmap;
	if (whence == R_BUF_END) {
		bm->offset = r_file_mmap_size (bm->mmap);
		return bm->offset;
	}
	if (R_UNLIKELY (addr < 0)) {
		if (addr > -(st64)UT48_MAX) {
	       		if (-addr > (st64)bm->offset) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	ut64 po = bm->offset;
	if (R_LIKELY (whence == R_BUF_SET)) {
		// 50%
		po = addr;
	} else if (whence == R_BUF_CUR) {
		// 20%
		po += addr;
	} else {
		// 5%
		po = bm->mmap->len + addr;
	}
	bm->offset = po;
	return po;
}

static ut64 buf_mmap_get_size(RBuffer *b) {
	ut64 r = r_file_mmap_size (b->rb_mmap->mmap);
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
