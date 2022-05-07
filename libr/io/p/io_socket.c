/* radare - LGPL - Copyright 2021 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include "../io_memory.h"

#define SOCKETURI "socket://"

typedef struct {
	RSocket *sc;
	RSocket *sl;
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
		r_cons_break_push (NULL, NULL);
		RSocket *s = ((RIOSocketData*)(mal->data))->sc;
		return r_socket_write (s, buf, count);
	}
	return -1;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RIOMalloc *mal = (RIOMalloc*)desc->data;
	if (mal) {
		ut64 addr = mal->offset;
		r_cons_break_push (NULL, NULL);
		RIOSocketData *sdat = mal->data;
		RSocket *s = sdat->sc;
		ut8 *mem = malloc (4096);
		if (mem) {
			int c = r_socket_read (s, mem, 4096);
			if (c > 0) {
				int osz = mal->size;
				io_memory_resize (io, desc, mal->size + c);
				memcpy (mal->buf + osz, mem, c);
				io->coreb.cmdf (io->coreb.core, "f nread_%d %d %d",
					sdat->count, c, mal->size);
				io->coreb.cmdf (io->coreb.core, "omr 1 %d", mal->size);
				sdat->count++;
			}
			free (mem);
		}
		r_cons_break_pop ();
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
	return !strncmp (pathname, SOCKETURI, strlen (SOCKETURI));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_sandbox_enable (false)) {
		eprintf ("Do not permit " SOCKETURI " in sandbox mode.\n");
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
			eprintf ("Cannot listen\n");
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
			eprintf ("Missing port.\n");
			free_socketdata (data);
			free (host);
			return NULL;
		}
		/* listen and wait for connection */
		data->sc = r_socket_new (false);
		if (!r_socket_connect (data->sc, host, port, R_SOCKET_PROTO_TCP, 0)) {
			eprintf ("Cannot connect\n");
			free (host);
			free_socketdata (data);
			return NULL;
		}
		r_socket_block_time (data->sc, false, 0, 0);
		free (host);
	}
	return r_io_desc_new (io, &r_io_plugin_socket, pathname, R_PERM_RW | rw, mode, mal);
}

RIOPlugin r_io_plugin_socket = {
	.name = "socket",
	.desc = "Connect or listen via TCP on a growing io.",
	.uris = SOCKETURI,
	.license = "MIT",
	.open = __open,
	.close = __close,
	.read = __read,
	.seek = io_memory_lseek,
	.check = __check,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_socket,
	.version = R2_VERSION
};
#endif
