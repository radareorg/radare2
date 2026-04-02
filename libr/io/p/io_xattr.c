/* radare - LGPL - Copyright 2022 - pancake */

#include <r_io.h>
#include <r_lib.h>
#include "../io_memory.h"

#if 0
#define HAS_XATTR 0
#elif __APPLE__
#define HAS_XATTR 1
# define r_listxattr(x,y,z) listxattr(x,y,z,0)
# define r_getxattr(x,y,z,u) getxattr(x,y,z,u,0,0)
# define r_setxattr(x,y,z,u,v) setxattr(x,y,z,u,v,0)
#elif __linux__
#define HAS_XATTR 1
# define r_listxattr listxattr
# define r_getxattr getxattr
# define r_setxattr setxattr
#else
#define HAS_XATTR 0
#endif

#if HAS_XATTR

#include <sys/xattr.h>

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "xattr://");
}

static void list_xattr(const char *path) {
	int total = r_listxattr (path, NULL, 0);
	if (total < 1) {
		return;
	}
	char *namebuf = malloc (total);
	if (!namebuf) {
		return;
	}
	int res = r_listxattr (path, namebuf, total);
	const char *p = namebuf;
	const char *end = namebuf + res;
	while (p < end) {
		printf ("%s\n", p);
		p += strlen (p) + 1;
	}
	free (namebuf);
}

static bool write_xattr(const char *path, const char *attrname, const ut8 *data, size_t size) {
	return r_setxattr (path, attrname, data, size, 0) == 0;
}

static ut8 *read_xattr(const char *path, const char *attrname, int *osize) {
	int size = r_getxattr (path, attrname, NULL, 0);
	if (size < 1) {
		return NULL;
	}
	ut8 *buf = malloc (size);
	if (!buf) {
		return NULL;
	}
	r_getxattr (path, attrname, buf, size);
	*osize = size;
	return buf;
}

// splits "xattr://path//attr" into an owned path string and an attrname pointer into it
static char *split_xattr_uri(const char *pathname, char **attrname) {
	char *path = strdup (pathname + strlen ("xattr://"));
	char *sep = strstr (path, "//");
	if (sep) {
		*sep = 0;
		*attrname = sep + 2;
	} else {
		*attrname = NULL;
	}
	return path;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	char *attrname;
	char *path = split_xattr_uri (pathname, &attrname);
	if (!attrname) {
		list_xattr (path);
		free (path);
		return NULL;
	}
	int size = 0;
	ut8 *attrvalue = read_xattr (path, attrname, &size);
	free (path);
	if (!attrvalue) {
		return NULL;
	}
	RIOMalloc *mal = R_NEW0 (RIOMalloc);
	mal->size = size;
	mal->buf = attrvalue;
	return r_io_desc_new (io, &r_io_plugin_xattr, pathname,
		R_PERM_RW | (rw & R_PERM_X), mode, mal);
}

static bool __close(RIODesc *fd) {
	RIOMalloc *riom = fd->data;
	char *attrname;
	char *path = split_xattr_uri (fd->name, &attrname);
	if (attrname && riom->buf && riom->size > 0) {
		write_xattr (path, attrname, riom->buf, riom->size);
	}
	free (path);
	io_memory_close (fd);
	return true;
}

RIOPlugin r_io_plugin_xattr = {
	.meta = {
		.name = "xattr",
		.desc = "access extended file attribute",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.uris = "xattr://",
	.open = __open,
	.close = __close,
	.read = io_memory_read,
	.check = __check,
	.seek = io_memory_lseek,
	.write = io_memory_write,
	.resize = io_memory_resize,
};

#else // HAS_XATTR

RIOPlugin r_io_plugin_xattr = {
	.meta = {
		.name = "xattr",
		.author = "pancake",
		.desc = "access extended file attribute (not supported)",
		.license = "LGPL-3.0-only",
	},
	.uris = "xattr://",
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_xattr,
	.version = R2_VERSION
};
#endif
