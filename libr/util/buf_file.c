/* radare - LGPL - Copyright 2009-2020 - ret2libc */

#include <r_types.h>
#include <r_util.h>

struct buf_file_user {
	const char *file;
	int perm;
	int mode;
};

static bool buf_file_init(RBuffer *b, const void *user) {
	const struct buf_file_user *u = user;
	b->rb_file = R_NEW0 (RBufferFile);
	if (!b->rb_file) {
		return false;
	}
	b->rb_file->fd = r_sandbox_open (u->file, u->perm, u->mode);
	if (b->rb_file->fd == -1) {
		free (b->rb_file);
		return false;
	}
	return true;
}

static bool buf_file_fini(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_file);
	r_sandbox_close (b->rb_file->fd);
	R_FREE (b->rb_file);
	return true;
}

static ut64 buf_file_get_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_file);
	int pos = r_sandbox_lseek (b->rb_file->fd, 0, SEEK_CUR);
	int res = r_sandbox_lseek (b->rb_file->fd, 0, SEEK_END);
	r_sandbox_lseek (b->rb_file->fd, pos, SEEK_SET);
	return (ut64)res;
}

static st64 buf_file_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_file);
	return r_sandbox_read (b->rb_file->fd, buf, len);
}

static st64 buf_file_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_file);
	return r_sandbox_write (b->rb_file->fd, buf, len);
}

static st64 buf_file_seek(RBuffer *b, st64 addr, int whence) {
	R_WARN_IF_FAIL (b->rb_file);
	switch (whence) {
	case R_BUF_CUR: whence = SEEK_CUR; break;
	case R_BUF_SET: whence = SEEK_SET; break;
	case R_BUF_END: whence = SEEK_END; break;
	}
	return r_sandbox_lseek (b->rb_file->fd, addr, whence);
}

static bool buf_file_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_file);
	return r_sandbox_truncate (b->rb_file->fd, newsize) >= 0;
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
