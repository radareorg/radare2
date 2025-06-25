/* radare - LGPL - Copyright 2022-2024 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#include "../io_memory.h"
#include "../io_stream.h"

#define SERIALURI "serial://"
#define SERIALURI_EXAMPLE "serial:///dev/ttyS0:115200:1"

typedef struct {
	RSocket *sc;
	RIOStream *ios;
	int count;
} RIOSocketData;

static void free_socketdata(RIOSocketData *sd) {
	if (sd) {
		r_socket_free (sd->sc);
		free (sd);
	}
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	int ret = -1;
	if (mal) {
		RIOSocketData *data = (RIOSocketData*)(mal->data);
		RSocket *s = data->sc;
		RIOStream *ios = data->ios;
		r_io_stream_write (ios, buf, count);
		// ret = r_socket_write (s, buf, count);
		ret = write (s->fd, buf, count);
		if (ret == -1) {
			perror ("write");
			R_LOG_DEBUG ("serial.write: %d", ret);
		}
	}
	return ret;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		ut64 addr = mal->offset;
		RIOSocketData *sdat = mal->data;
		RSocket *s = sdat->sc;
		ut8 *mem = malloc (4096);
		if (mem) {
			int c = r_socket_read (s, mem, 4096);
			if (c == -1) {
				perror ("write");
				R_LOG_DEBUG ("serial.read: %d", c);
			}
			if (c > 0) {
				r_io_stream_read (sdat->ios, mem, c);
				int osz = mal->size;
				io_memory_resize (io, desc, mal->size + c);
				memcpy (mal->buf + osz, mem, c);
				io->coreb.cmdf (io->coreb.core, "f nread_%d %d %d",
					sdat->count, c, mal->size);
				// io->coreb.cmdf (io->coreb.core, "omr 1 %d", mal->size);
				sdat->count++;
			}
			free (mem);
		}
		mal->offset = addr;
		return io_memory_read (io, desc, buf, count);
	}
	return -1;
}

static bool __close(RIODesc *desc) {
	R_FREE (desc->data);
	return true;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, SERIALURI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("The " SERIALURI " uri is not permitted in sandbox mode");
		return NULL;
	}
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	RIOMalloc *mal = R_NEW0 (RIOMalloc);
	if (!mal) {
		return NULL;
	}
	RIOSocketData *data = R_NEW0 (RIOSocketData);
	if (!mal || !data) {
		free (mal);
		free_socketdata (data);
		return NULL;
	}
	data->ios = r_io_stream_new ();
	mal->data = data;
	mal->buf = calloc (1, 1);
	if (!mal->buf) {
		free (mal);
		free_socketdata (data);
		return NULL;
	}
	mal->size = 1;
	mal->offset = 0;
	pathname += strlen (SERIALURI);

	if (*pathname == '?') {
		R_LOG_ERROR ("Usage: r2 " SERIALURI_EXAMPLE);
	} else {
		int speed = 115200;
		int parity = 1;
		char *path = strdup (pathname);
		char *arg = strchr (path, ':');
		if (arg) {
			*arg++ = 0;
			speed = atoi (arg);
			char *arg2 = strchr (arg, ':');
			if (arg2) {
				parity = atoi (arg);
			}
		}
		data->sc = r_socket_new (false);
		int res = r_socket_connect_serial (data->sc, path, speed, parity);
		if (res == -1) {
			R_LOG_ERROR ("Cannot connect");
			free (path);
			free_socketdata (data);
			return NULL;
		}
		// r_socket_block_time (data->sc, false, 100, 100);
		free (path);
	}
	if (io->va) {
		R_LOG_WARN ("This is a raw stream and growing io plugin, You may disable io.va to not depend on maps");
	}
	return r_io_desc_new (io, &r_io_plugin_serial, pathname, R_PERM_RW | (rw & R_PERM_X), mode, mal);
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	RIOSocketData *data = (RIOSocketData*)mal->data;
	ut8 buf[1024];
	__read (io, desc, buf, sizeof (buf));
	return r_io_stream_system (data->ios, cmd);
}

RIOPlugin r_io_plugin_serial = {
	.meta = {
		.name = "serial",
		.author = "pancake",
		.desc = "Connect to a serial port (" SERIALURI_EXAMPLE ")",
		.license = "MIT",
	},
	.uris = SERIALURI,
	.open = __open,
	.close = __close,
	.read = __read,
	.seek = io_memory_lseek,
	.check = __check,
	.write = __write,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_serial,
	.version = R2_VERSION
};
#endif
