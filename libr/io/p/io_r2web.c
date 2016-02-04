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

#define rFD(x) (((RIOR2Web*)x->data)->fd)
#define rURL(x) (((RIOR2Web*)x->data)->url)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	int code, rlen;
	char *out, *url, *hexbuf;
	if (!fd || !fd->data)
		return -1;
	if (count * 3 < count) return -1;
	hexbuf = malloc (count * 3);
	if (!hexbuf) return -1;
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
	if (!fd || !fd->data)
		return -1;
	url = r_str_newf ("%s/p8%%20%d@%"PFMT64d,
		rURL(fd), count, io->off);
	out = r_socket_http_get (url, &code, &rlen);
	if (out && rlen>0) {
		ut8 *tmp = malloc (rlen+1);
		if (!tmp) goto beach;
		ret = r_hex_str2bin (out, tmp);
		memcpy (buf, tmp, R_MIN (count, rlen));
		free (tmp);
		if (ret<0) ret = -ret;
	}

beach:
	free (out);
	free (url);
	return ret;
}

static int __close(RIODesc *fd) {
	RIOR2Web *riom;
	if (!fd || !fd->data)
		return -1;
	riom = fd->data;
	free (riom->url);
	riom->url = NULL;
	free (fd->data);
	fd->data = NULL;
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
		if (!mal) return NULL;
		char *url = r_str_newf ("http://%s/?V", pathname+8);
		//eprintf  ("URL:(%s)\n", url);
		out = r_socket_http_get (url, &code, &rlen);
		//eprintf ("RES %d %d\n", code, rlen);
		//eprintf ("OUT(%s)\n", out);
		if (out && rlen>0) {
			mal->fd = getmalfd (mal);
			mal->url = r_str_newf ("http://%s", pathname+8);
			free (out);
			free (url);
			return r_io_desc_new (&r_io_plugin_r2web,
				mal->fd, pathname, rw, mode, mal);
		}
		free (url);
		free (mal);
		free (out);
	}
	return NULL;
}

static int __system(RIO *io, RIODesc *fd, const char *command) {
	int code, rlen;
	char *out;
	int ret = 0;
	char *url = r_str_newf ("%s/%s", rURL(fd), command);
	out = r_socket_http_get (url, &code, &rlen);
	if (out && rlen>0) {
		io->cb_printf ("%s", out);
	}
	free (out);
	free (url);
	return ret;
}

RIOPlugin r_io_plugin_r2web = {
	.name = "r2web",
	.desc = "r2web io client (r2web://cloud.rada.re/cmd/)",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2web,
	.version = R2_VERSION
};
#endif
