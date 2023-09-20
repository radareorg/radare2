/* radare - MIT - Copyright 2011-2023 - pancake */

#define R_LOG_ORIGIN "io.rap"

#include <r_io.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_socket.h>
#include <sys/types.h>

#define RIORAP_FD(x) (((x)->data)?(((RIORap*)((x)->data))->client):NULL)
#define RIORAP_IS_LISTEN(x) (((RIORap*)((x)->data))->listener)
#define RIORAP_IS_VALID(x) ((x) && ((x)->data) && ((x)->plugin == &r_io_plugin_rap))

static int __rap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RSocket *s = RIORAP_FD (fd);
	return r_socket_rap_client_write (s, buf, count);
}

static bool __rap_accept(RIO *io, RIODesc *desc, int fd) {
	RIORap *rap = desc? desc->data: NULL;
	if (rap && fd != -1) {
		rap->client = r_socket_new_from_fd (fd);
		return true;
	}
	return false;
}

static int __rap_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RSocket *s = RIORAP_FD (fd);
	return r_socket_rap_client_read (s, buf, count);
}

static bool __rap_close(RIODesc *desc) {
	bool ret = false;
	if (RIORAP_IS_VALID (desc)) {
		if (RIORAP_FD (desc)) {
			RIORap *rap = desc->data;
			if (rap && desc->fd != -1) {
				if (rap->fd) {
					r_socket_close (rap->fd);
				}
				if (rap->client) {
					r_socket_close (rap->client);
				}
				free (rap);
			}
		}
	} else {
		R_LOG_ERROR ("fdesc is not a r_io_rap plugin");
	}
	return ret;
}

static ut64 __rap_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RSocket *s = RIORAP_FD (fd);
	return r_socket_rap_client_seek (s, offset, whence);
}

static bool __rap_plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "rap://") || r_str_startswith (pathname, "raps://");
}

static RIODesc *__rap_open(RIO *io, const char *pathname, int rw, int mode) {
	int i, listenmode;
	char *port;

	if (!__rap_plugin_open (io, pathname, 0)) {
		return NULL;
	}
	bool is_ssl = r_str_startswith (pathname, "raps://");
	const char *host = pathname + (is_ssl? 7: 6);
	if (!(port = strchr (host, ':'))) {
		R_LOG_ERROR ("rap: wrong uri");
		return NULL;
	}
	listenmode = (*host == ':');
	*port++ = 0;
	if (!*port) {
		return NULL;
	}
	int p = atoi (port);
	char *file = r_str_after (port + 1, '/');
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: Cannot use network");
		return NULL;
	}
	if (listenmode) {
		if (p <= 0) {
			R_LOG_ERROR ("cannot listen. Try rap://:9999");
			return NULL;
		}
		// TODO: Handle ^C signal (SIGINT, exit); // ???
		R_LOG_INFO ("listening at port %s ssl %s", port, is_ssl? "on": "off");
		RIORap *rior = R_NEW0 (RIORap);
		rior->listener = true;
		rior->client = rior->fd = r_socket_new (is_ssl);
		if (!rior->fd) {
			free (rior);
			return NULL;
		}
		if (is_ssl) {
			if (R_STR_ISNOTEMPTY (file)) {
				if (!r_socket_listen (rior->fd, port, file)) {
					r_socket_free (rior->fd);
					free (rior);
					return NULL;
				}
			} else {
				free (rior);
				return NULL;
			}
		} else {
			if (!r_socket_listen (rior->fd, port, NULL)) {
				r_socket_free (rior->fd);
				free (rior);
				return NULL;
			}
		}
		return r_io_desc_new (io, &r_io_plugin_rap,
			pathname, rw, mode, rior);
	}
	RSocket *s = r_socket_new (is_ssl);
	if (!s) {
		R_LOG_ERROR ("Cannot create new socket");
		return NULL;
	}
	R_LOG_INFO ("Connecting to %s, port %s", host, port);
	if (!r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
		R_LOG_ERROR ("Cannot connect to '%s' (%d)", host, p);
		r_socket_free (s);
		return NULL;
	}
	R_LOG_INFO ("Connected to: %s at port %s", host, port);
	RIORap *rior = R_NEW0 (RIORap);
	if (!rior) {
		r_socket_free (s);
		return NULL;
	}
	rior->listener = false;
	rior->client = rior->fd = s;
	if (R_STR_ISNOTEMPTY (file)) {
		i = r_socket_rap_client_open (s, file, rw);
		if (i == -1) {
			free (rior);
			r_socket_free (s);
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
	return r_io_desc_new (io, &r_io_plugin_rap,
		pathname, rw, mode, rior);
}

static int __rap_listener(RIODesc *fd) {
	return (RIORAP_IS_VALID (fd))? RIORAP_IS_LISTEN (fd): 0; // -1 ?
}

static char *__rap_system(RIO *io, RIODesc *fd, const char *command) {
	RSocket *s = RIORAP_FD (fd);
	// TODO: bind core into RSocket instead of pass the one from io?
	return r_socket_rap_client_command (s, command, &io->coreb);
#if 0
	int ret, reslen = 0, cmdlen = 0;
	unsigned int i;
	char *ptr, *res, *str;
	ut8 buf[RMT_MAX];

	buf[0] = RMT_CMD;
	i = strlen (command) + 1;
	if (i > RMT_MAX - 5) {
		R_LOG_ERROR ("Command too long");
		return NULL;
	}
	r_write_be32 (buf + 1, i);
	memcpy (buf + 5, command, i);
	(void)r_socket_write (s, buf, i+5);
	r_socket_flush (s);

	/* read reverse cmds */
	for (;;) {
		ret = r_socket_read_block (s, buf, 1);
		if (ret != 1) {
			return NULL;
		}
		/* system back in the middle */
		/* TODO: all pkt handlers should check for reverse queries */
		if (buf[0] != RMT_CMD) {
			break;
		}
		// run io->cmdstr
		// return back the string
		buf[0] |= RMT_REPLY;
		memset (buf + 1, 0, 4);
		ret = r_socket_read_block (s, buf + 1, 4);
		if (ret != 4) {
			return NULL;
		}
		cmdlen = r_read_at_be32 (buf, 1);
		if (cmdlen + 1 == 0) { // check overflow
			cmdlen = 0;
		}
		str = calloc (1, cmdlen + 1);
		ret = r_socket_read_block (s, (ut8*)str, cmdlen);
		R_LOG_INFO ("RUN %d CMD(%s)", ret, str);
		if (str && *str) {
			res = io->cb_core_cmdstr (io->user, str);
		} else {
			res = strdup ("");
		}
		R_LOG_INFO ("[%s]=>(%s)", str, res);
		reslen = strlen (res);
		free (str);
		r_write_be32 (buf + 1, reslen);
		memcpy (buf + 5, res, reslen);
		free (res);
		(void)r_socket_write (s, buf, reslen + 5);
		r_socket_flush (s);
	}

	// read
	ret = r_socket_read_block (s, buf + 1, 4);
	if (ret != 4) {
		return NULL;
	}
	if (buf[0] != (RMT_CMD | RMT_REPLY)) {
		R_LOG_ERROR ("Unexpected rap cmd reply");
		return NULL;
	}

	i = r_read_at_be32 (buf, 1);
	ret = 0;
	if (i > ST32_MAX) {
		R_LOG_ERROR ("Invalid length");
		return NULL;
	}
	ptr = (char *)calloc (1, i + 1);
	if (ptr) {
		int ir, tr = 0;
		do {
			ir = r_socket_read_block (s, (ut8*)ptr + tr, i - tr);
			if (ir < 1) {
				break;
			}
			tr += ir;
		} while (tr < i);
		// TODO: use io->cb_printf() with support for \x00
		ptr[i] = 0;
		if (io->cb_printf) {
			io->cb_printf ("%s", ptr);
		} else {
			if (write (1, ptr, i) != i) {
				R_LOG_ERROR ("Failed to write");
			}
		}
		free (ptr);
	}
#if DEAD_CODE
	/* Clean */
	if (ret > 0) {
		ret -= r_socket_read (s, (ut8*)buf, RMT_MAX);
	}
#endif
#endif
	return NULL;
}

RIOPlugin r_io_plugin_rap = {
	.meta = {
		.name = "rap",
		.desc = "Remote binary protocol plugin",
		.license = "MIT",
	},
	.uris = "rap://,raps://",
	.listener = __rap_listener,
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
