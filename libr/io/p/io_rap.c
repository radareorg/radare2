/* radare - MIT - Copyright 2011-2026 - pancake */

#define R_LOG_ORIGIN "io.rap"

#include <r_io.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_socket.h>
#include <sys/types.h>

#define RIORAP_FD(x) (((x)->data)?(((RIORap*)((x)->data))->client):NULL)
#define RIORAP_IS_LISTEN(x) (((RIORap*)((x)->data))->listener)
#define RIORAP_IS_VALID(x) ((x) && ((x)->data) && ((x)->plugin == &r_io_plugin_rap))

static int __rap_write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RSocket *s = RIORAP_FD (desc);
	return r_socket_rap_client_write (s, buf, count);
}

static bool __rap_accept(RIO *io, RIODesc *desc, int fd) {
	RIORap *rap = desc? desc->data: NULL;
	if (rap && fd != -1) {
		if (rap->client) {
			r_socket_free (rap->client);
		}
		rap->client = r_socket_new_from_fd (fd);
		return rap->client != NULL;
	}
	return false;
}

static int __rap_read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RSocket *s = RIORAP_FD (desc);
	return r_socket_rap_client_read (s, buf, count);
}

static bool __rap_close(RIODesc *desc) {
	if (RIORAP_IS_VALID (desc)) {
		RIORap *rap = desc->data;
		if (rap) {
			if (rap->fd) {
				r_socket_close (rap->fd);
			}
			if (rap->client) {
				r_socket_close (rap->client);
			}
			free (rap);
		}
	} else {
		R_LOG_ERROR ("fdesc is not a r_io_rap plugin");
	}
	return true;
}

static ut64 __rap_lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	RSocket *s = RIORAP_FD (desc);
	if (RIORAP_IS_LISTEN (desc)) {
		switch (whence) {
		case R_IO_SEEK_SET:
			io->off = offset;
			break;
		case R_IO_SEEK_CUR:
			io->off += offset;
			break;
		case R_IO_SEEK_END:
			io->off = UT64_MAX;
			break;
		default:
			io->off = UT64_MAX;
			break;
		}
		return io->off;
	}
	return r_socket_rap_client_seek (s, offset, whence);
}

static bool __rap_plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "rap://") || r_str_startswith (pathname, "raps://");
}

static RIODesc *__rap_open(RIO *io, const char *pathname, int rw, int mode) {
	int i;
	char *port;

	if (!__rap_plugin_open (io, pathname, 0)) {
		return NULL;
	}
	bool is_ssl = r_str_startswith (pathname, "raps://");
	char *host = strdup (pathname + (is_ssl? 7: 6));
	if (!host) {
		return NULL;
	}
	if (!(port = strchr (host, ':'))) {
		R_LOG_ERROR ("rap: wrong uri");
		free (host);
		return NULL;
	}
	int listenmode = (*host == ':');
	*port++ = 0;
	if (!*port) {
		free (host);
		return NULL;
	}
	int p = atoi (port);
	char *file = r_str_after (port + 1, '/');
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: Cannot use network");
		free (host);
		return NULL;
	}
	if (listenmode) {
		if (p <= 0) {
			R_LOG_ERROR ("cannot listen. Try rap://:9999");
			free (host);
			return NULL;
		}
		// TODO: Handle ^C signal (SIGINT, exit); // ???
		R_LOG_INFO ("listening at port %s ssl %s", port, is_ssl? "on": "off");
		RIORap *rior = R_NEW0 (RIORap);
		rior->listener = true;
		rior->client = rior->fd = r_socket_new (is_ssl);
		if (!rior->fd) {
			free (rior);
			free (host);
			return NULL;
		}
		if (is_ssl) {
			if (R_STR_ISNOTEMPTY (file)) {
				if (!r_socket_listen (rior->fd, port, file)) {
					r_socket_free (rior->fd);
					free (rior);
					free (host);
					return NULL;
				}
			} else {
				free (rior);
				free (host);
				return NULL;
			}
		} else {
			if (!r_socket_listen (rior->fd, port, NULL)) {
				r_socket_free (rior->fd);
				free (rior);
				free (host);
				return NULL;
			}
		}
		RIODesc *desc = r_io_desc_new (io, &r_io_plugin_rap,
			pathname, rw, mode, rior);
		free (host);
		return desc;
	}
	RSocket *s = r_socket_new (is_ssl);
	if (!s) {
		R_LOG_ERROR ("Cannot create new socket");
		free (host);
		return NULL;
	}
	R_LOG_INFO ("Connecting to %s, port %s", host, port);
	if (!r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
		R_LOG_ERROR ("Cannot connect to '%s' (%d)", host, p);
		r_socket_free (s);
		free (host);
		return NULL;
	}
	R_LOG_INFO ("Connected to: %s at port %s", host, port);
	RIORap *rior = R_NEW0 (RIORap);
	if (!rior) {
		r_socket_free (s);
		free (host);
		return NULL;
	}
	rior->listener = false;
	rior->client = rior->fd = s;
	if (R_STR_ISNOTEMPTY (file)) {
		i = r_socket_rap_client_open (s, file, rw);
		if (i == -1) {
			free (rior);
			r_socket_free (s);
			free (host);
			return NULL;
		}
		if (i > 0) {
			R_LOG_INFO ("rap connection was successful. open %d", i);
			// io->coreb.cmd (io->coreb.core, "e io.va=0");
			io->coreb.cmd (io->coreb.core, ".:i*");
			io->coreb.cmd (io->coreb.core, ".:f*");
			io->coreb.cmd (io->coreb.core, ".:om*");
		}
	}
	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_rap,
		pathname, rw, mode, rior);
	free (host);
	return desc;
}

static RIODescInfo __rap_info(RIODesc *desc) {
	RIODescInfo di = {0};
	di.listener = RIORAP_IS_VALID (desc) && RIORAP_IS_LISTEN (desc);
	return di;
}

static char *__rap_system(RIO *io, RIODesc *desc, const char *command) {
	RSocket *s = RIORAP_FD (desc);
	return r_socket_rap_client_command (s, command, &io->coreb);
}

RIOPlugin r_io_plugin_rap = {
	.meta = {
		.name = "rap",
		.author = "pancake",
		.desc = "Remote binary protocol plugin",
		.license = "MIT",
	},
	.uris = "rap://,raps://",
	.getinfo = __rap_info,
	.open = __rap_open,
	.close = __rap_close,
	.read = __rap_read,
	.check = __rap_plugin_open,
	.seek = __rap_lseek,
	.system = __rap_system,
	.write = __rap_write,
	.accept = __rap_accept,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_rap,
	.version = R2_VERSION
};
#endif
