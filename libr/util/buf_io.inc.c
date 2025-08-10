/* radare - LGPL - Copyright 2009-2025 - pancake, ret2libc */

#include <r_util.h>
#include <r_io.h>

static bool buf_io_init(RBuffer *b, const void *user) {
	b->rb_io = r_mem_dup (user, sizeof (RBufferIO));
	return true;
}

static bool buf_io_fini(RBuffer *b) {
	R_FREE (b->rb_io);
	return true;
}

static st64 buf_io_seek(RBuffer *b, st64 addr, int whence) {
	int io_whence;

	R_WARN_IF_FAIL (b->rb_io);
	switch (whence) {
	default:
		R_WARN_IF_REACHED ();
	case R_BUF_SET:
		io_whence = R_IO_SEEK_SET;
		break;
	case R_BUF_END:
		io_whence = R_IO_SEEK_END;
		break;
	case R_BUF_CUR:
		io_whence = R_IO_SEEK_CUR;
		break;
	}
	return b->rb_io->iob->fd_seek (b->rb_io->iob->io, b->rb_io->fd, addr, io_whence);
}

static ut64 buf_io_get_size(RBuffer *b) {
	R_WARN_IF_FAIL (b->rb_io);
	RIOBind *iob = b->rb_io->iob;
	return iob->fd_size (iob->io, b->rb_io->fd);
}

static bool buf_io_resize(RBuffer *b, ut64 newsize) {
	R_WARN_IF_FAIL (b->rb_io);
	return b->rb_io->iob->fd_resize (b->rb_io->iob->io, b->rb_io->fd, newsize);
}

static st64 buf_io_read(RBuffer *b, ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_io);
	RIOBind *iob = b->rb_io->iob;
	// ut64 cur = b->rb_io->iob->fd_seek (b->rb_io->iob->io, b->rb_io->fd, 0, R_IO_SEEK_CUR);
	st64 res = iob->fd_read (iob->io, b->rb_io->fd, buf, len);
	// b->rb_io->iob->fd_seek (b->rb_io->iob->io, b->rb_io->fd, cur, R_IO_SEEK_SET);
	return res;
}

static st64 buf_io_write(RBuffer *b, const ut8 *buf, ut64 len) {
	R_WARN_IF_FAIL (b->rb_io);
	RIOBind *iob = b->rb_io->iob;
	ut64 cur = b->rb_io->iob->fd_seek (b->rb_io->iob->io, b->rb_io->fd, 0, R_IO_SEEK_CUR);
	st64 res = iob->fd_write (iob->io, b->rb_io->fd, buf, len);
	b->rb_io->iob->fd_seek (b->rb_io->iob->io, b->rb_io->fd, cur + res, R_IO_SEEK_SET);
	return res;
}

static const RBufferMethods buffer_io_methods = {
	.init = buf_io_init,
	.fini = buf_io_fini,
	.read = buf_io_read,
	.write = buf_io_write,
	.get_size = buf_io_get_size,
	.resize = buf_io_resize,
	.seek = buf_io_seek,
};
