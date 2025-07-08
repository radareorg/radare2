/* radare - LGPL - Copyright 2009-2025 - ret2libc */

#include <r_util.h>

struct buf_bytes_user {
	const ut8 *data;
	const ut8 *data_steal;
	ut64 length;
	bool steal;
};

static bool buf_bytes_init(RBuffer *b, const void *user) {
	const struct buf_bytes_user *u = user;
	b->rb_bytes = R_NEW0 (RBufferBytes);
	if (!b->rb_bytes) {
		return false;
	}

	b->rb_bytes->offset = 0;
	b->rb_bytes->length = u->length;
	if (u->data_steal) {
		b->rb_bytes->buf = (ut8 *)u->data_steal;
		b->rb_bytes->is_bufowner = u->steal;
	} else {
#if 0
		size_t length = b->rb_bytes->length > 0? b->rb_bytes->length: 1;
		b->rb_bytes->buf = malloc (length);
		if (!b->rb_bytes->buf) {
			free (b->rb_bytes);
			return false;
		}
		if (b->rb_bytes->length > 0) {
			memmove (b->rb_bytes->buf, u->data, b->rb_bytes->length);
		}
#else
		if (b->rb_bytes->length > 0) {
			b->rb_bytes->buf = malloc (b->rb_bytes->length);
			if (!b->rb_bytes->buf) {
				free (b->rb_bytes);
				return false;
			}
			memmove (b->rb_bytes->buf, u->data, b->rb_bytes->length);
		}
#endif
		b->rb_bytes->is_bufowner = true;
	}
	return true;
}

static bool buf_bytes_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (b->rb_bytes->is_bufowner) {
		free (b->rb_bytes->buf);
	}
	R_FREE (b->rb_bytes);
	return true;
}

static bool buf_bytes_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (newsize > b->rb_bytes->length) {
		ut8 *t = realloc (b->rb_bytes->buf, newsize);
		if (!t) {
			return false;
		}
		b->rb_bytes->buf = t;
		memset (b->rb_bytes->buf + b->rb_bytes->length, b->Oxff_priv, newsize - b->rb_bytes->length);
	}
	b->rb_bytes->length = newsize;
	return true;
}

static st64 buf_bytes_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (!b->rb_bytes->buf) {
		return 0;
	}
	ut64 real_len = b->rb_bytes->length < b->rb_bytes->offset? 0: R_MIN (b->rb_bytes->length - b->rb_bytes->offset, len);
	// reproducer: cp /bin/ls aaa ; r2 -qcq -e io.va=0 -c "s 0x4000; wtf aaa" aaa
	memmove (buf, b->rb_bytes->buf + b->rb_bytes->offset, real_len);
	// XXX memcpy only works on aligned addresses which may cause segfaults on release builds
	// memcpy (buf, b->rb_bytes->buf + b->rb_bytes->offset, real_len);
	b->rb_bytes->offset += real_len;
	return real_len;
}

static st64 buf_bytes_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (b->rb_bytes->offset > b->rb_bytes->length || b->rb_bytes->offset + len >= b->rb_bytes->length) {
		bool r = r_buf_resize (b, b->rb_bytes->offset + len);
		if (!r) {
			return -1;
		}
	}
	memmove (b->rb_bytes->buf + b->rb_bytes->offset, buf, len);
	b->rb_bytes->offset += len;
	return len;
}

static ut64 buf_bytes_get_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_bytes);
	return b->rb_bytes->length;
}

static st64 buf_bytes_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (R_UNLIKELY (addr < 0)) {
		if (addr > -(st64)UT48_MAX) {
	       		if (-addr > (st64)b->rb_bytes->offset) {
				return -1;
			}
		} else {
			return -1;
		}
	}
	ut64 po = b->rb_bytes->offset;
	if (R_LIKELY (whence == R_BUF_SET)) {
		// 50%
		po = addr;
	} else if (whence == R_BUF_CUR) {
		// 20%
		po += addr;
	} else {
		// 5%
		po = b->rb_bytes->length + addr;
	}
	b->rb_bytes->offset = po;
	return po;
}

static ut8 *buf_bytes_get_whole_buf(RBuffer *b, ut64 *sz) {
	R_WARN_IF_FAIL (b->rb_bytes);
	if (sz) {
		*sz = b->rb_bytes->length;
	}
	return b->rb_bytes->buf;
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
