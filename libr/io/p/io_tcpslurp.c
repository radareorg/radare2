/* radare - LGPL - Copyright 2016-2022 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include "../io_memory.h"

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "tcp-slurp://");
}

static ut8 *tcpme(const char *pathname, int *code, int *len) {
	pathname += strlen ("tcp-slurp://");
	*code = 404;
	if (*pathname == '?') {
		eprintf ("Usage: $ nc -l -p 9999 < /bin/ls ; r2 tcp-slurp://localhost:9999\n");
		eprintf ("   or: $ nc localhost 9999 < /bin/ls ; r2 tcp-slurp://:9999\n");
	} else if (*pathname == ':') {
		/* listen and wait for connection */
		RSocket *sl = r_socket_new (false);
		if (!r_socket_listen (sl, pathname + 1, NULL)) {
			R_LOG_ERROR ("Cannot listen");
			r_socket_free (sl);
			return NULL;
		}
		RSocket *sc = r_socket_accept (sl);
		ut8 *res = r_socket_slurp (sc, len);
		r_socket_free (sc);
		r_socket_free (sl);
		if (res) {
			*code = 200;
			return res;
		}
	} else {
		/* connect and slurp the end point */
		char *host = strdup (pathname);
		if (!host) {
			return NULL;
		}
		char *port = strchr (host, ':');
		if (port) {
			*port++ = 0;
			RSocket *s = r_socket_new (false);
			if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
				ut8 *res = r_socket_slurp (s, len);
				if (*len < 1) {
					R_FREE (res);
				} else {
					*code = 200;
				}
				r_socket_free (s);
				free (host);
				return res;
			}
			r_socket_free (s);
		} else {
			R_LOG_ERROR ("Missing port");
		}
		free (host);
	}
	return NULL;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (__check (io, pathname, 0)) {
		int rlen, code;
		RIOMalloc *mal = R_NEW0 (RIOMalloc);
		if (!mal) {
			return NULL;
		}
		mal->offset = 0;
		mal->buf = tcpme (pathname, &code, &rlen);
		if (mal->buf && rlen > 0) {
			mal->size = rlen;
			return r_io_desc_new (io, &r_io_plugin_tcpslurp, pathname, rw & R_PERM_RWX, mode, mal);
		}
		free (mal);
	}
	return NULL;
}

RIOPlugin r_io_plugin_tcpslurp = {
	.meta = {
		.name = "tcp",
		.author = "pancake",
		.desc = "Slurp/load remote files via TCP (tcp-slurp://:9999 or tcp-slurp://host:port)",
		.license = "LGPL-3.0-only",
	},
	.uris = "tcp-slurp://",
	.open = __open,
	.close = io_memory_close,
	.read = io_memory_read,
	.check = __check,
	.seek = io_memory_lseek,
	.write = io_memory_write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_tcpslurp,
	.version = R2_VERSION
};
#endif
