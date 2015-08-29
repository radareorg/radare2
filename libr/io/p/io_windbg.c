// Copyright (c) 2014, The Lemon Man, All rights reserved.

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
#include <wind.h>

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return !strncmp (file, "windbg://", strlen ("windbg://"));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	void *io_ctx;
	WindCtx *ctx;

	if (!__plugin_open (io, file, 0))
		return NULL;

	if (!iob_select ("pipe")) {
		eprintf("Could not initialize the IO backend\n");
		return NULL;
	}

	io_ctx = iob_open (file + 9);
	if (!io_ctx) {
		eprintf ("Could not open the pipe\n");
		return NULL;
	}

	ctx = wind_ctx_new (io_ctx);

	if (!ctx)
		return NULL;

	return r_io_desc_new (io, &r_io_plugin_windbg, file, true, mode, ctx);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd)
		return -1;

	if (wind_get_target(fd->data)) {
		ut64 va;
		if (!wind_va_to_pa (fd->data, io->off, &va))
			return -1;
		return wind_write_at_phys (fd->data, buf, va, count);
	}

	return wind_write_at (fd->data, buf, io->off, count);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd)
		return -1;

	if (wind_get_target(fd->data)) {
		ut64 va;
		if (!wind_va_to_pa (fd->data, io->off, &va))
			return -1;
		return wind_read_at_phys(fd->data, buf, va, count);
	}

	return wind_read_at(fd->data, buf, io->off, count);
}

static int __close(RIODesc *fd) {
	wind_ctx_free (fd->data);
	return true;
}

RIOPlugin r_io_plugin_windbg = {
	.name = "windbg",
	.desc = "Attach to a KD debugger",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.isdbg = true,
};
