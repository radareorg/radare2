/* radare - LGPL - Copyright 2016 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	ut8 *buf;
	ut32 size;
} RIOMalloc;

#define RIOTCP_FD(x) (((RIOMalloc*)x->data)->fd)
#define RIOTCP_SZ(x) (((RIOMalloc*)x->data)->size)
#define RIOTCP_BUF(x) (((RIOMalloc*)x->data)->buf)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	if (io->off + count > RIOTCP_SZ (fd)) {
		return -1;
	}
	memcpy (RIOTCP_BUF (fd)+io->off, buf, count);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	unsigned int sz;
	if (!fd || !fd->data) {
		return -1;
	}
	sz = RIOTCP_SZ (fd);
	if (io->off >= sz) {
		return -1;
	}
	if (io->off + count >= sz) {
		count = sz - io->off;
	}
	memcpy (buf, RIOTCP_BUF (fd) + io->off, count);
	return count;
}

static int __close(RIODesc *fd) {
	RIOMalloc *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	free (riom->buf);
	riom->buf = NULL;
	free (fd->data);
	fd->data = NULL;
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return RIOTCP_SZ (fd);
	}
	return offset;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "tcp://", 6));
}

static inline int getmalfd (RIOMalloc *mal) {
	return (UT32_MAX >> 1) & (int)(size_t)mal->buf;
}

static ut8 *tcpme (const char *pathname, int *code, int *len) {
	pathname += 6;
	*code = 404;
#if __UNIX__
	signal (SIGINT, 0);
#endif
	if (*pathname == ':') {
		/* listen and wait for connection */
		RSocket *sl = r_socket_new (false);
		if (!r_socket_listen (sl, pathname + 1, NULL)) {
			eprintf ("Cannot listen\n");
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
					free (res);
					res = NULL;
				} else {
					*code = 200;
				}
				r_socket_free (s);
				free (host);
				return res;
			}
			r_socket_free (s);
		} else {
			eprintf ("Missing port.\n");
		}
		free (host);
	}
	return NULL;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	ut8 *out;
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		out = tcpme (pathname, &code, &rlen);
		if (out && rlen > 0) {
			RIOMalloc *mal = R_NEW0 (RIOMalloc);
			if (!mal) {
				free (out);
				return NULL;
			}
			mal->size = rlen;
			mal->buf = malloc (mal->size + 1);
			if (!mal->buf) {
				free (mal);
				free (out);
				return NULL;
			}
			if (mal->buf != NULL) {
				mal->fd = getmalfd (mal);
				memcpy (mal->buf, out, mal->size);
				free (out);
				rw = 7;
				return r_io_desc_new (io, &r_io_plugin_tcp,
					pathname, rw, mode, mal);
			}
			eprintf ("Cannot allocate (%s) %d bytes\n", pathname + 9, mal->size);
			free (mal);
		}
		free (out);
	}
	return NULL;
}

RIOPlugin r_io_plugin_tcp = {
	.name = "tcp",
        .desc = "load files via TCP (listen or connect)",
	.license = "LGPL3",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_tcp,
	.version = R2_VERSION
};
#endif
