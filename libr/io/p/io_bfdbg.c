/* radare - LGPL - Copyright 2011-2024 - pancake */

#include <r_io.h>
#include "../debug/p/bfvm.h"
#include "../debug/p/bfvm.c"

typedef struct {
	ut32 magic;
	int fd;
	ut8 *buf;
	ut32 size;
	ut64 seek;
	BfvmCPU *bfvm;
} RIOBfdbg;

#define RIOBFDBG_FD(x) (((RIOBfdbg *) (x)->data)->fd)
#define RIOBFDBG_SZ(x) (((RIOBfdbg *) (x)->data)->size)
#define RIOBFDBG_BUF(x) (((RIOBfdbg *) (x)->data)->buf)

static inline int is_in_screen(ut64 off, BfvmCPU *c) {
	return off >= c->screen && off < c->screen + c->screen_size;
}

static inline int is_in_input(ut64 off, BfvmCPU *c) {
	return off >= c->input && off < c->input + c->input_size;
}

static inline int is_in_base(ut64 off, BfvmCPU *c) {
	return off >= c->base && off < c->base + c->size;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOBfdbg *riom;
	int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	/* data base buffer */
	if (is_in_base (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->base;
		if (n > count) {
			count = n;
		}
		memcpy (riom->bfvm->mem + n, buf, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* screen buffer */
	if (is_in_screen (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->screen;
		if (n > count) {
			count = riom->bfvm->screen_size - n;
		}
		memcpy (riom->bfvm->screen_buf + n, buf, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* input buffer */
	if (is_in_input (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->input;
		if (n > count) {
			count = riom->bfvm->input_size - n;
		}
		memcpy (riom->bfvm->input_buf + n, buf, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* read from file */
	sz = RIOBFDBG_SZ (fd);
	if (riom->seek + count >= sz) {
		count = sz - riom->seek;
	}
	if (riom->seek >= sz) {
		return -1;
	}
	memcpy (RIOBFDBG_BUF (fd) + riom->seek, buf, count);
	riom->seek = R_MIN (count + riom->seek, riom->size);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOBfdbg *riom;
	int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	/* data base buffer */
	if (is_in_base (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->base;
		if (n > count) {
			count = n;
		}
		memcpy (buf, riom->bfvm->mem + n, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* screen buffer */
	if (is_in_screen (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->screen;
		if (n > count) {
			count = riom->bfvm->screen_size - n;
		}
		memcpy (buf, riom->bfvm->screen_buf + n, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* input buffer */
	if (is_in_input (riom->seek, riom->bfvm)) {
		int n = riom->seek - riom->bfvm->input;
		if (n > count) {
			count = riom->bfvm->input_size - n;
		}
		memcpy (buf, riom->bfvm->input_buf + n, count);
		riom->seek = R_MIN (count + riom->seek, riom->size);
		return count;
	}
	/* read from file */
	sz = RIOBFDBG_SZ (fd);
	if (riom->seek + count >= sz) {
		count = sz - riom->seek;
	}
	if (riom->seek >= sz) {
		return -1;
	}
	memcpy (buf, RIOBFDBG_BUF (fd) + riom->seek, count);
	riom->seek = R_MIN (count + riom->seek, riom->size);
	return count;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOBfdbg *riom = fd->data;
	bfvm_free (riom->bfvm);
	R_FREE (riom->buf);
	R_FREE (fd->data);
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOBfdbg *d = fd->data;
	switch (whence) {
	case R_IO_SEEK_SET:
		d->seek = R_MIN (offset, d->size);
		break;
	case R_IO_SEEK_CUR:
		d->seek = R_MIN (d->seek + offset, d->size);
		break;
	case R_IO_SEEK_END:
		d->seek = d->size;
		break;
	}
	return d->seek;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "bfdbg://");
}

static inline int getmalfd(RIOBfdbg *mal) {
	return UT16_MAX & (unsigned int) (size_t) mal->buf;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		RIOBfdbg *mal = R_NEW0 (RIOBfdbg);
		if (!mal) {
			return NULL;
		}
		RIOBind iob;
		r_io_bind (io, &iob);
		mal->fd = getmalfd (mal);
		mal->bfvm = bfvm_new (&iob);
		if (!mal->bfvm) {
			free (mal);
			return NULL;
		}
		size_t rlen;
		char *out = r_file_slurp (pathname + 8, &rlen);
		if (!out || rlen < 1) {
			free (mal);
			free (out);
			return NULL;
		}
		mal->size = (ut32) rlen;
		mal->buf = malloc (mal->size + 1);
		if (R_LIKELY (mal->buf)) {
			memcpy (mal->buf, out, rlen);
			free (out);
			return r_io_desc_new (io, &r_io_plugin_bfdbg,
				pathname, rw, mode, mal);
		}
		R_LOG_ERROR ("Cannot allocate %"PFMT32u " byte(s) for %s",
			mal->size, pathname + 9);
		free (mal);
		free (out);
	}
	return NULL;
}

RIOPlugin r_io_plugin_bfdbg = {
	.meta = {
		.name = "bfdbg",
		.author = "pancake",
		.desc = "Attach to brainfuck debugger instance",
		.license = "LGPL-3.0-only",
	},
	.uris = "bfdbg://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_bfdbg,
	.version = R2_VERSION
};
#endif
