/* radare - MIT - Copyright 2011-2019 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include <r_core.h>
#include <r_socket.h>
#include <sys/types.h>

// TODO: implement the rap API in r_socket ?
#define RIORAP_FD(x) (((x)->data)?(((RIORap*)((x)->data))->client):NULL)
#define RIORAP_IS_LISTEN(x) (((RIORap*)((x)->data))->listener)
#define RIORAP_IS_VALID(x) ((x) && ((x)->data) && ((x)->plugin == &r_io_plugin_rap))

static int __rap_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RSocket *s = RIORAP_FD (fd);
	ut8 *tmp;
	int ret;

	if (count < 1) {
		return count;
	}
	// TOOD: if count > RMT_MAX iterate !
	if (count > RMT_MAX) {
		count = RMT_MAX;
	}
	if (!(tmp = (ut8 *)malloc (count + 5))) {
		eprintf ("__rap_write: malloc failed\n");
		return -1;
	}
	tmp[0] = RMT_WRITE;
	r_write_be32 (tmp + 1, count);
	memcpy (tmp + 5, buf, count);

	(void)r_socket_write (s, tmp, count + 5);
	r_socket_flush (s);
	if (r_socket_read (s, tmp, 5) != 5) { // TODO read_block?
		eprintf ("__rap_write: error\n");
		ret = -1;
	} else {
		ret = r_read_be32 (tmp + 1);
		if (!ret) {
			ret = -1;
		}
	}
	free (tmp);
	return ret;
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
	int ret, i = (int)count;
	ut8 tmp[5];

	// XXX. if count is > RMT_MAX, just perform multiple queries
	if (count > RMT_MAX) {
		count = RMT_MAX;
	}
	// send
	tmp[0] = RMT_READ;
	r_write_be32 (tmp + 1, count);
	(void)r_socket_write (s, tmp, 5);
	r_socket_flush (s);
	// recv
	ret = r_socket_read_block (s, tmp, 5);
	if (ret != 5 || tmp[0] != (RMT_READ | RMT_REPLY)) {
		eprintf ("__rap_read: Unexpected rap read reply "
			"(%d=0x%02x) expected (%d=0x%02x)\n",
			ret, tmp[0], 2, (RMT_READ | RMT_REPLY));
		return -1;
	}
	i = r_read_at_be32 (tmp, 1);
	if (i > count) {
		eprintf ("__rap_read: Unexpected data size %d vs %d\n", i, count);
		return -1;
	}
	r_socket_read_block (s, buf, i);
	return count;
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
	ut8 tmp[10];
	tmp[0] = RMT_SEEK;
	tmp[1] = (ut8)whence;
	r_write_be64 (tmp + 2, offset);
	(void)r_socket_write (s, &tmp, 10);
	r_socket_flush (s);
	int ret = r_socket_read_block (s, (ut8*)&tmp, 9);
	if (ret != 9) {
		eprintf ("Truncated socket read\n");
		return -1;
	}
	if (tmp[0] != (RMT_SEEK | RMT_REPLY)) {
		// eprintf ("%d %d  - %02x %02x %02x %02x %02x %02x %02x\n",
		// ret, whence, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6]);
		eprintf ("Unexpected lseek reply (%02x -> %02x)\n", tmp[0], (RMT_SEEK | RMT_REPLY));
		return -1;
	}
	return r_read_at_be64 (tmp, 1);
}

static bool __rap_plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "rap://") || r_str_startswith (pathname, "raps://");
}

static RIODesc *__rap_open(RIO *io, const char *pathname, int rw, int mode) {
	int i, p, listenmode;
	char *file, *port;
	const char *ptr;
	RSocket *rap_fd;
	char buf[1024];
	RIORap *rior;

	if (!__rap_plugin_open (io, pathname, 0)) {
		return NULL;
	}
	bool is_ssl = (!strncmp (pathname, "raps://", 7));
	ptr = pathname + (is_ssl? 7: 6);
	if (!(port = strchr (ptr, ':'))) {
		eprintf ("rap: wrong uri\n");
		return NULL;
	}
	listenmode = (*ptr == ':');
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
		rior = R_NEW0 (RIORap);
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
	if (!(rap_fd = r_socket_new (is_ssl))) {
		eprintf ("Cannot create new socket\n");
		return NULL;
	}
	if (r_socket_connect_tcp (rap_fd, ptr, port, 30) == false) {
		eprintf ("Cannot connect to '%s' (%d)\n", ptr, p);
		r_socket_free (rap_fd);
		return NULL;
	}
	eprintf ("Connected to: %s at port %s\n", ptr, port);
	rior = R_NEW0 (RIORap);
	if (!rior) {
		r_socket_free (rap_fd);
		return NULL;
	}
	rior->listener = false;
	rior->client = rior->fd = rap_fd;
	if (file && *file) {
		// send
		buf[0] = RMT_OPEN;
		buf[1] = rw;
		buf[2] = (ut8)strlen (file);
		memcpy (buf + 3, file, buf[2]);
		(void)r_socket_write (rap_fd, buf, buf[2] + 3);
		r_socket_flush (rap_fd);
		// read
		eprintf ("waiting... ");
		buf[0] = 0;
		r_socket_read_block (rap_fd, (ut8*)buf, 5);
		if (buf[0] != (char)(RMT_OPEN | RMT_REPLY)) {
			eprintf ("rap: Expecting OPEN|REPLY packet. got %02x\n", buf[0]);
			r_socket_free (rap_fd);
			free (rior);
			return NULL;
		}
		i = r_read_at_be32 (buf, 1);
		if (i > 0) {
			eprintf ("ok\n");
		}
		// io->cb_core_cmd (io->user, "e io.va=0");
		io->cb_core_cmd (io->user, ".=!i*");
		io->cb_core_cmd (io->user, ".=!f*");
		io->cb_core_cmd (io->user, ".=!om*");
#if 0
		/* Read meta info */
		r_socket_read (rap_fd, (ut8 *)&buf, 4);
		r_mem_copyendian ((ut8 *)&i, (ut8*)buf, 4, ENDIAN);
		while (i>0) {
			int n = r_socket_read (rap_fd, (ut8 *)&buf, i);
			if (n<1) break;
			buf[i] = 0;
			io->core_cmd_cb (io->user, buf);
			n = r_socket_read (rap_fd, (ut8 *)&buf, 4);
			if (n<1) break;
			r_mem_copyendian ((ut8 *)&i, (ut8*)buf, 4, ENDIAN);
			i -= n;
		}
#endif
	} else {
	//	r_socket_free (rap_fd);
	//	free (rior);
		//return NULL;
	}
	//r_socket_free (rap_fd);
	return r_io_desc_new (io, &r_io_plugin_rap,
		pathname, rw, mode, rior);
}

static int __rap_listener(RIODesc *fd) {
	return (RIORAP_IS_VALID (fd))? RIORAP_IS_LISTEN (fd): 0; // -1 ?
}

static char *__rap_system(RIO *io, RIODesc *fd, const char *command) {
	int ret, reslen = 0, cmdlen = 0;
	RSocket *s = RIORAP_FD (fd);
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
