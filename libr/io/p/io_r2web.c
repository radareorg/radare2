/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_io.h>
#include <r_lib.h>

typedef struct {
	char *url;
	ut64 addr;
	int fd;
} RIOR2Web;

#define rFD(x) (((RIOR2Web*)(x)->data)->fd)
#define rURL(x) (((RIOR2Web*)(x)->data)->url)

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data || count < 1 || count > ST32_MAX / 2 - 1) {
		return -1;
	}
	char *hexbuf = malloc (count * 2 + 1);
	if (!hexbuf) {
		return -1;
	}
	r_hex_bin2str (buf, count, hexbuf);
	RIOR2Web *r2w = fd->data;
	char *url = r_str_newf ("%s/wx%%20%s@%"PFMT64d, rURL (fd), hexbuf, r2w->addr);
	int code, rlen;
	char *out = r_socket_http_get (url, NULL, &code, &rlen);
	r2w->addr += count;
	free (out);
	free (url);
	free (hexbuf);
	return count;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	RIOR2Web *r2w = fd->data;
	char *url = r_str_newf ("%s/p8%%20%d@0x%"PFMT64x, rURL (fd), count, r2w->addr);
	int code, rlen, ret = 0;
	char *out = r_socket_http_get (url, NULL, &code, &rlen);
	free (url);
	if (out && rlen > 0) {
		ut8 *tmp = calloc (1, rlen + 1);
		if (tmp) {
			ret = r_hex_str2bin (out, tmp);
			if (ret < 0) {
				ret = -ret;
			}
			memcpy (buf, tmp, R_MIN (count, ret));
			free (tmp);
			r2w->addr += ret;
		}
	}
	free (out);
	return ret;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	RIOR2Web *riom = fd->data;
	R_FREE (riom->url);
	R_FREE (fd->data);
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOR2Web *r2w = fd->data;
	switch (whence) {
	case R_IO_SEEK_SET:
		r2w->addr = offset;
		return offset;
	case R_IO_SEEK_CUR:
		r2w->addr += offset;
		return r2w->addr;
	case R_IO_SEEK_END:
		r2w->addr = UT64_MAX - 1;
		return UT64_MAX - 1;
	}
	return r2w->addr;
}

static bool __plugin_open(RIO *io, const char *pathname, bool many) {
	const char uri[] = "r2web://";
	return r_str_startswith (pathname, uri);
}

static inline int getmalfd(RIOR2Web *mal) {
	return 0xfffffff & (int)(size_t)mal;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__plugin_open (io, pathname, 0)) {
		return NULL;
	}
	char *path = strdup (pathname + 8);
	size_t path_len = strlen (path);
	if (path_len > 0 && path[path_len - 1] == '/') {
		path[path_len - 1] = 0;
	}
	int rlen, code;
	char *url = r_str_newf ("http://%s/?V", path);
	char *out = r_socket_http_get (url, NULL, &code, &rlen);
	free (url);
	RIODesc *desc = NULL;
	if (out && rlen > 0) {
		RIOR2Web *mal = R_NEW0 (RIOR2Web);
		mal->fd = getmalfd (mal);
		mal->url = r_str_newf ("http://%s", path);
		desc = r_io_desc_new (io, &r_io_plugin_r2web, pathname, rw, mode, mal);
	} else {
		R_LOG_WARN ("Try http://localhost:9090/cmd/");
	}
	free (out);
	free (path);
	return desc;
}

static char *__system(RIO *io, RIODesc *fd, const char *command) {
	if (!*command) {
		return NULL;
	}
	int code, rlen;
	char *cmd = r_str_uri_encode (command);
	char *url = r_str_newf ("%s/%s", rURL(fd), cmd);
	char *out = r_socket_http_get (url, NULL, &code, &rlen);
	if (out && rlen > 0) {
		io->cb_printf ("%s", out);
	}
	free (out);
	free (url);
	free (cmd);
	return NULL;
}

RIOPlugin r_io_plugin_r2web = {
	.meta = {
		.name = "r2web",
		.author = "pancake",
		.desc = "r2web io client plugin",
		.license = "LGPL-3.0-only",
	},
	.uris = "r2web://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
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
