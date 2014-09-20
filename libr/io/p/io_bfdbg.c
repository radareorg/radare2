/* radare - LGPL - Copyright 2011-2013 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#undef R_API
#define R_API static inline
#include "../debug/p/bfvm.h"
#include "../debug/p/bfvm.c"

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
	BfvmCPU *bfvm;
} RIOBfdbg;

#define RIOBFDBG_FD(x) (((RIOBfdbg*)x->data)->fd)
#define RIOBFDBG_SZ(x) (((RIOBfdbg*)x->data)->size)
#define RIOBFDBG_BUF(x) (((RIOBfdbg*)x->data)->buf)

static inline int is_in_screen(ut64 off, BfvmCPU *c) {
	return (off >= c->screen && off < c->screen+c->screen_size);
}

static inline int is_in_input(ut64 off, BfvmCPU *c) {
	return (off >= c->input && off < c->input+c->input_size);
}

static inline int is_in_base(ut64 off, BfvmCPU *c) {
	return (off >= c->base && off < c->base+c->size);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOBfdbg *riom;
	int sz;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	/* data base buffer */
	if (is_in_base (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->base;
		if (n>count)
			count = n;
		memcpy (riom->bfvm->mem+n, buf, count);
		return count;
	}
	/* screen buffer */
	if (is_in_screen (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->screen;
		if (n>count)
			count = riom->bfvm->screen_size-n;
		memcpy (riom->bfvm->screen_buf+n, buf, count);
		return count;
	}
	/* input buffer */
	if (is_in_input (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->input;
		if (n>count)
			count = riom->bfvm->input_size-n;
		memcpy (riom->bfvm->input_buf+n, buf, count);
		return count;
	}
	/* read from file */
	sz = RIOBFDBG_SZ (fd);
	if (io->off+count >= sz)
		count = sz-io->off;
	if (io->off >= sz)
		return -1;
	memcpy (RIOBFDBG_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOBfdbg *riom;
	int sz;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	/* data base buffer */
	if (is_in_base (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->base;
		if (n>count)
			count = n;
		memcpy (buf, riom->bfvm->mem+n, count);
		return count;
	}
	/* screen buffer */
	if (is_in_screen (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->screen;
		if (n>count)
			count = riom->bfvm->screen_size-n;
		memcpy (buf, riom->bfvm->screen_buf+n, count);
		return count;
	}
	/* input buffer */
	if (is_in_input (io->off, riom->bfvm)) {
		int n = io->off-riom->bfvm->input;
		if (n>count)
			count = riom->bfvm->input_size-n;
		memcpy (buf, riom->bfvm->input_buf+n, count);
		return count;
	}
	/* read from file */
	sz = RIOBFDBG_SZ (fd);
	if (io->off+count >= sz)
		count = sz-io->off;
	if (io->off >= sz)
		return -1;
	memcpy (buf, RIOBFDBG_BUF (fd)+io->off, count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOBfdbg *riom;
	if (fd == NULL || fd->data == NULL)
		return -1;
	riom = fd->data;
	bfvm_free (riom->bfvm);
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	fd->state = R_IO_DESC_TYPE_CLOSED;
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RIOBFDBG_SZ (fd);
	}
	return offset;
}

static int __plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "bfdbg://", 8));
}

static inline int getmalfd (RIOBfdbg *mal) {
	return 0xffff & (int)(size_t)mal->buf;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	char *out;
	int rlen;
	if (__plugin_open (io, pathname, 0)) {
		RIOBind iob;
		RIOBfdbg *mal = R_NEW0 (RIOBfdbg);
		r_io_bind (io, &iob);
		mal->fd = getmalfd (mal);
		mal->bfvm = bfvm_new (&iob);
		out = r_file_slurp (pathname+8, &rlen);
		if (!out || rlen < 1) {
			free (mal);
			free (out);
			return NULL;
		}
		mal->size = rlen;
		mal->buf = malloc (mal->size+1);
		if (mal->buf != NULL) {
			memcpy (mal->buf, out, rlen);
			free (out);
			return r_io_desc_new (&r_io_plugin_bfdbg,
				mal->fd, pathname, rw, mode, mal);
		}
		eprintf ("Cannot allocate (%s) %d bytes\n",
			pathname+9, mal->size);
		free (mal);
		free (out);
	}
	return NULL;
}

RIOPlugin r_io_plugin_bfdbg = {
	.name = "bfdbg",
	.desc = "BrainFuck Debugger (bfdbg://path/to/file)",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_bfdbg
};
#endif
