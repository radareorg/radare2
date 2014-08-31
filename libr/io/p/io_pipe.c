#include <r_io.h>
#include <r_lib.h>
#include <r_socket.h>
#include <r_util.h>
#include <wind.h>

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	return !strncmp (file, "pipe://", 7);
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	void *io_ctx;
	wind_ctx_t *ctx;

	if (!__plugin_open (io, file, 0))
		return NULL;

	if (!iob_select("pipe")) {
		eprintf("Could not initialize the IO backend\n");
		return NULL;
	}

	io_ctx = iob_open(file + 7);
	if (!io_ctx) {
		eprintf("Could not open the pipe\n");
		return NULL;
	}

	ctx = wind_ctx_new (io_ctx);

	if (!ctx)
		return NULL;

	return r_io_desc_new (&r_io_plugin_pipe, -1, file, R_TRUE, mode, ctx);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd)
		return -1;

	return wind_write_at(fd->data, buf, io->off, count);
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd)
		return -1;

	return wind_read_at(fd->data, buf, io->off, count);
}

static int __close(RIODesc *fd) {
	wind_ctx_free (fd->data);
	return R_TRUE;
}

RIOPlugin r_io_plugin_pipe = {
	.name = "pipe",
	.desc = "shove it down the pipe!",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.plugin_open = __plugin_open,
	.lseek = __lseek,
};

