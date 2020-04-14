/* radare - MIT - Copyright 2011-2020 - pancake */

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

static int __rap_close(RIODesc *fd) {
	int ret = -1;
	if (RIORAP_IS_VALID (fd)) {
		if (RIORAP_FD (fd) != NULL) {
			RIORap *r = fd->data;
			if (r && fd->fd != -1) {
				if (r->fd) {
					(void)r_socket_close (r->fd);
				}
				if (r->client) {
					ret = r_socket_close (r->client);
				}
				R_FREE (r);
			}
		}
	} else {
		eprintf ("__rap_close: fdesc is not a r_io_rap plugin\n");
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
	int i, p, listenmode;
	char *file, *port;

	if (!__rap_plugin_open (io, pathname, 0)) {
		return NULL;
	}
	bool is_ssl = (!strncmp (pathname, "raps://", 7));
	const char *host = pathname + (is_ssl? 7: 6);
	if (!(port = strchr (host, ':'))) {
		eprintf ("rap: wrong uri\n");
		return NULL;
	}
	listenmode = (*host == ':');
	*port++ = 0;
	if (!*port) {
		return NULL;
	}
	p = atoi (port);
	if ((file = strchr (port + 1, '/'))) {
		*file = 0;
		file++;
	}
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: Cannot use network\n");
		return NULL;
	}
	if (listenmode) {
		if (p <= 0) {
			eprintf ("rap: cannot listen here. Try rap://:9999\n");
			return NULL;
		}
		//TODO: Handle ^C signal (SIGINT, exit); // ???
		eprintf ("rap: listening at port %s ssl %s\n", port, (is_ssl)?"on":"off");
		RIORap *rior = R_NEW0 (RIORap);
		rior->listener = true;
		rior->client = rior->fd = r_socket_new (is_ssl);
		if (!rior->fd) {
			free (rior);
			return NULL;
		}
		if (is_ssl) {
			if (file && *file) {
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
		eprintf ("Cannot create new socket\n");
		return NULL;
	}
	eprintf ("Connecting to %s, port %s\n", host, port);
	if (!r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, 0)) {
		eprintf ("Cannot connect to '%s' (%d)\n", host, p);
		r_socket_free (s);
		return NULL;
	}
	eprintf ("Connected to: %s at port %s\n", host, port);
	RIORap *rior = R_NEW0 (RIORap);
	if (!rior) {
		r_socket_free (s);
		return NULL;
	}
	rior->listener = false;
	rior->client = rior->fd = s;
	if (file && *file) {
		i = r_socket_rap_client_open (s, file, rw);
		if (i == -1) {
			free (rior);
			r_socket_free (s);
			return NULL;
		}
		if (i > 0) {
			eprintf ("rap connection was successful. open %d\n", i);
			// io->corebind.cmd (io->corebind.core, "e io.va=0");
			io->corebind.cmd (io->corebind.core, ".=!i*");
			io->corebind.cmd (io->corebind.core, ".=!f*");
			io->corebind.cmd (io->corebind.core, ".=!om*");
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
	return r_socket_rap_client_command (s, command, &io->corebind);
#if 0
	int ret, reslen = 0, cmdlen = 0;
	unsigned int i;
	char *ptr, *res, *str;
	ut8 buf[RMT_MAX];

	buf[0] = RMT_CMD;
	i = strlen (command) + 1;
	if (i > RMT_MAX - 5) {
		eprintf ("Command too long\n");
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
		eprintf ("RUN %d CMD(%s)\n", ret, str);
		if (str && *str) {
			res = io->cb_core_cmdstr (io->user, str);
		} else {
			res = strdup ("");
		}
		eprintf ("[%s]=>(%s)\n", str, res);
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
		eprintf ("Unexpected rap cmd reply\n");
		return NULL;
	}

	i = r_read_at_be32 (buf, 1);
	ret = 0;
	if (i > ST32_MAX) {
		eprintf ("Invalid length\n");
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
				eprintf ("Failed to write\n");
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
	.name = "rap",
	.desc = "Remote binary protocol plugin",
	.uris = "rap://,raps://",
	.license = "MIT",
	.listener = __rap_listener,
	.open = __rap_open,
	.close = __rap_close,
	.read = __rap_read,
	.check = __rap_plugin_open,
	.lseek = __rap_lseek,
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
