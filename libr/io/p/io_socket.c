/* radare - LGPL - Copyright 2021-2024 - pancake */

#include <r_io.h>
#include <r_cons.h>
#include "../io_memory.h"
#include "../io_stream.h"

#define SOCKETURI "socket://"

typedef struct {
	RSocket *sc;
	RSocket *sl;
	RIOStream *ios;
	int count;
} RIOSocketData;

static void free_socketdata(RIOSocketData *sd) {
	if (sd) {
		r_socket_free (sd->sc);
		r_socket_free (sd->sl);
		free (sd);
	}
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		RIOSocketData *data = (RIOSocketData*)(mal->data);
		RSocket *s = data->sc;
		RIOStream *ios = data->ios;
		r_io_stream_write (ios, buf, count);
		return r_socket_write (s, buf, count);
	}
	return -1;
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
		if (sdat->ios && sdat->ios->buf) {
			return r_buf_read_at (sdat->ios->buf, mal->offset, buf, count);
		}
		return -1;
		// return io_memory_read (io, desc, buf, count);
	}
	return -1;
}

static bool __close(RIODesc *desc) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	RIOSocketData *data = (RIOSocketData*)(mal->data);
	r_io_stream_free (data->ios);
	R_FREE (desc->data);
	return true;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, SOCKETURI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("Do not permit " SOCKETURI " in sandbox mode");
		return NULL;
	}
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	RIOMalloc *mal = R_NEW0 (RIOMalloc);
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
	pathname += strlen (SOCKETURI);

	if (*pathname == '?') {
		eprintf ("Usage: $ nc -l -p 9999 ; r2 socket://localhost:9999\n");
		eprintf ("   or: $ nc localhost 9999 ; r2 socket://:9999\n");
	} else if (*pathname == ':') {
		/* listen and wait for connection */
		data->sl = r_socket_new (false);
		if (!r_socket_listen (data->sl, pathname + 1, NULL)) {
			R_LOG_ERROR ("Cannot listen");
			r_socket_free (data->sl);
			data->sl = NULL;
			return NULL;
		}
		data->sc = r_socket_accept (data->sl);
		r_socket_block_time (data->sc, false, 0, 0);
	} else {
		/* connect and slurp the end point */
		char *host = strdup (pathname);
		if (!host) {
			return NULL;
		}
		char *port = strchr (host, ':');
		if (port) {
			*port++ = 0;
		} else {
			R_LOG_ERROR ("Missing port");
			free_socketdata (data);
			free (host);
			return NULL;
		}
		/* listen and wait for connection */
		data->sc = r_socket_new (false);
		if (!r_socket_connect (data->sc, host, port, R_SOCKET_PROTO_TCP, 0)) {
			R_LOG_ERROR ("Cannot connect");
			free (host);
			free_socketdata (data);
			return NULL;
		}
		r_socket_block_time (data->sc, false, 0, 0);
		free (host);
	}
	if (io->va) {
		R_LOG_WARN ("This is a raw stream and growing io plugin, You may disable io.va to not depend on maps");
	}
	return r_io_desc_new (io, &r_io_plugin_socket, pathname, R_PERM_RW | (rw & R_PERM_X), mode, mal);
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	RIOSocketData *data = (RIOSocketData*)mal->data;
	ut8 buf[1024];
	__read (io, desc, buf, sizeof (buf));
	return r_io_stream_system (data->ios, cmd);
}

RIOPlugin r_io_plugin_socket = {
	.meta = {
		.name = "socket",
		.author = "pancake",
		.desc = "Connect or listen via TCP on a growing io",
		.license = "MIT",
	},
	.uris = SOCKETURI,
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
	.data = &r_io_plugin_socket,
	.version = R2_VERSION
};
#endif
