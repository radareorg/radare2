/* radare - LGPL - Copyright 2022-2024 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_reg.h>
#include <r_core.h>
#include <r_cons.h>

static RRegArena *get_arena(RIO *io) {
	RCore *core = io->coreb.core;
	if (!core) {
		return NULL;
	}
	RRegSet *rs = &core->anal->reg->regset[0];
	if (!rs) {
		return NULL;
	}
	RRegArena *arena = rs->arena;
	if (!arena) {
		return NULL;
	}
	return arena;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	RRegArena *arena = get_arena (io);
	if (!arena) {
		return -1;
	}
	if (io->off >= arena->size) {
		return -1;
	}
	int left = arena->size - io->off;
	memset (buf, io->Oxff, len);
	memcpy (buf, arena->bytes + io->off, R_MIN (left, len));
	return len;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	RRegArena *arena = get_arena (io);
	if (!arena) {
		return -1;
	}
	if (io->off >= arena->size) {
		return -1;
	}
	int left = arena->size - io->off;
	memcpy (arena->bytes + io->off, buf, R_MIN (left, len));
	return len;
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "reg://");
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		RRegArena *arena = get_arena (io);
		if (!arena) {
			return NULL;
		}
		return r_io_desc_new (io, &r_io_plugin_reg, file, R_PERM_RW, 0, NULL);
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RRegArena *arena = get_arena (io);
	if (!arena) {
		return io->off;
	}
	const int size = arena->size;
	switch (whence) {
	case R_IO_SEEK_SET:
		if (offset >= size) {
			return size;
		}
		return offset;
	case R_IO_SEEK_CUR:
		return io->off + offset;
	case R_IO_SEEK_END:
		return size;
	}
	return io->off;
}

static bool __close(RIODesc *fd) {
	R_FREE (fd->data);
	return 0 == 0;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (r_str_startswith (cmd, "pid")) {
		io->cb_printf ("%d\n", -1);
	}
	return NULL;
}

RIOPlugin r_io_plugin_reg = {
	.meta = {
		.name = "reg",
		.author = "pancake",
		.desc = "read and write the register arena",
		.license = "LGPL-3.0-only",
	},
	.uris = "reg://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_reg,
	.version = R2_VERSION
};
#endif
