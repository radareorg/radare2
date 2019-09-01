/* radare - LGPL - Copyright 2015 - pancake */

#include "r_io.h"
#include "r_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
	int fd;
	char *url;
} RIOR2Web;

#define rFD(x) (((RIOR2Web*)(x)->data)->fd)
#define rURL(x) (((RIOR2Web*)(x)->data)->url)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	int code, rlen;
	char *out, *url, *hexbuf;
	if (!fd || !fd->data) {
		return -1;
	}
	if (count * 3 < count) {
		return -1;
	}
	hexbuf = malloc (count * 3);
	if (!hexbuf) {
		return -1;
	}
	hexbuf[0] = 0;
	r_hex_bin2str (buf, count, hexbuf);
	url = r_str_newf ("%s/wx%%20%s@%"PFMT64d,
		rURL(fd), hexbuf, io->off);
	out = r_socket_http_get (url, &code, &rlen);
	free (out);
	free (url);
	free (hexbuf);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	int code, rlen;
	char *out, *url;
	int ret = 0;
	if (!fd || !fd->data) {
		return -1;
	}
	url = r_str_newf ("%s/p8%%20%d@0x%"PFMT64x,
		rURL(fd), count, io->off);
	out = r_socket_http_get (url, &code, &rlen);
	if (out && rlen > 0) {
		ut8 *tmp = calloc (1, rlen+1);
		if (!tmp) {
			goto beach;
		}
		ret = r_hex_str2bin (out, tmp);
		memcpy (buf, tmp, R_MIN (count, rlen));
		free (tmp);
		if (ret < 0) {
			ret = -ret;
		}
	}

beach:
	free (out);
	free (url);
	return ret;
}

static int __close(RIODesc *fd) {
	RIOR2Web *riom;
	if (!fd || !fd->data) {
		return -1;
	}
	riom = fd->data;
	R_FREE (riom->url);
	R_FREE (fd->data);
	return 0;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET: return offset;
	case SEEK_CUR: return io->off + offset;
	case SEEK_END: return UT64_MAX;
	}
	return offset;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	const char *uri = "r2web://";
	return (!strncmp (pathname, uri, strlen (uri)));
}

static inline int getmalfd (RIOR2Web *mal) {
	return 0xfffffff & (int)(size_t)mal;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	char *out;
	int rlen, code;
	if (__plugin_open (io, pathname, 0)) {
		RIOR2Web *mal = R_NEW0 (RIOR2Web);
		if (!mal) {
			return NULL;
		}
		char *path = strdup (pathname + 8);
		int path_len = strlen (path);
		if (path_len > 0) {
			if (path[path_len - 1] == '/') {
				path[path_len - 1] = 0;
			}
		}
		char *url = r_str_newf ("http://%s/?V", path);
		//eprintf  ("URL:(%s)\n", url);
		out = r_socket_http_get (url, &code, &rlen);
		//eprintf ("RES %d %d\n", code, rlen);
		//eprintf ("OUT(%s)\n", out);
		if (out && rlen > 0) {
			mal->fd = getmalfd (mal);
			mal->url = r_str_newf ("http://%s", path);
			free (path);
			free (out);
			free (url);
			return r_io_desc_new (io, &r_io_plugin_r2web,
				pathname, rw, mode, mal);
		}
		free (url);
		free (mal);
		free (out);
		free (path);
		eprintf ("Error: Try http://localhost:9090/cmd/");
	}
	return NULL;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	if (!*command) {
		return NULL;
	}
	int code, rlen;
	char *cmd = r_str_uri_encode (command);
	char *url = r_str_newf ("%s/%s", rURL(fd), cmd);
	char *out = r_socket_http_get (url, &code, &rlen);
	if (out && rlen > 0) {
		io->cb_printf ("%s", out);
	}
	free (out);
	free (url);
	free (cmd);
	return NULL;
}

RIOPlugin r_io_plugin_r2web = {
	.name = "r2web",
	.desc = "r2web io client plugin",
	.uris = "r2web://",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2web,
	.version = R2_VERSION
};
#endif
