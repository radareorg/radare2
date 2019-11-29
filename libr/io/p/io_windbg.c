// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#include <transport.h>
#include <windbg.h>

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return (!strncmp (file, "windbg://", 9));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}

	if (!iob_select ("pipe")) {
		eprintf("Could not initialize the IO backend\n");
		return NULL;
	}

	void *io_ctx = iob_open (file + 9);
	if (!io_ctx) {
		eprintf ("Could not open the pipe\n");
		return NULL;
	}
	eprintf ("Opened pipe %s with fd %p\n", file + 9, io_ctx);

	WindCtx *ctx = windbg_ctx_new (io_ctx);
	if (!ctx) {
		eprintf ("Failed to initialize windbg context\n");
		return NULL;
	}
	return r_io_desc_new (io, &r_io_plugin_windbg, file, rw, mode, ctx);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}
	if (windbg_get_target (fd->data)) {
		return windbg_write_at_uva (fd->data, buf, io->off, count);
	}
	return windbg_write_at (fd->data, buf, io->off, count);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		return io->off = offset;
	case R_IO_SEEK_CUR:
		return io->off + offset;
	case R_IO_SEEK_END:
		return ST64_MAX;
	default:
		return offset;
	}
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd) {
		return -1;
	}

	if (windbg_get_target (fd->data)) {
		return windbg_read_at_uva (fd->data, buf, io->off, count);
	}

	return windbg_read_at (fd->data, buf, io->off, count);
}

static int __close(RIODesc *fd) {
	windbg_ctx_free ((WindCtx**)&fd->data);
	return true;
}

RIOPlugin r_io_plugin_windbg = {
	.name = "windbg",
	.desc = "Attach to a KD debugger",
	.uris = "windbg://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_windbg,
	.version = R2_VERSION
};
#endif
