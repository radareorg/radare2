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
	int total = r_listxattr (path, NULL, -1);
	if (total < 1) {
		return;
	}
	char *namebuf = malloc (total);
	if (!namebuf) {
		return;
	}
	int i, res = r_listxattr (path, namebuf, total);
	for (i = 0; i < res; i++) {
		const char *n = namebuf + i;
		printf ("%s\n", n);
		i += strlen (n);
	}
	free (namebuf);
}

static bool write_xattr(const char *path, const char *attrname, const ut8 *data, size_t size) {
	return r_setxattr (path, attrname, data, size, 0) == 0;
}

static char *read_xattr(const char *path, const char *attrname, int *osize) {
	int size = r_getxattr (path, attrname, NULL, -1);
	if (size < 1) {
		return NULL;
	}
	char *buf = calloc (size, 1);
	r_getxattr (path, attrname, buf, size);
	*osize = size;
	return buf;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, 0)) {
		return NULL;
	}
	char *path = strdup (pathname + 8);
	char *attrname = strstr (path, "//");
	if (!attrname) {
		list_xattr (path);
		free (path);
		return NULL;
	}
	*attrname = 0;
	attrname += 2;

	int size = 0;
	char *attrvalue = read_xattr (path, attrname, &size);
	free (path);
	if (!attrvalue || size < 1) {
		return NULL;
	}

	RIOMalloc *mal = R_NEW0 (RIOMalloc);
	if (!mal) {
		return NULL;
	}
	mal->size = size;
	mal->buf = (ut8*)attrvalue;
	mal->offset = 0;
	if (mal->buf) {
		return r_io_desc_new (io, &r_io_plugin_xattr, pathname, R_PERM_RW | rw, mode, mal);
	}
	R_LOG_ERROR ("Cannot allocate %d bytes for %s", mal->size, pathname);
	free (mal);
	return NULL;
}

static bool __close(RIODesc *fd) {
	RIOMalloc *riom = fd->data;
	const char *pathname = fd->name;
	char *path = strdup (pathname + 8);
	char *attrname = strstr (path, "//");
	if (!attrname) {
		// should never happen, but just in case
		return NULL;
	}
	*attrname = 0;
	attrname += 2;
	write_xattr (path, attrname, (const ut8*)riom->buf, riom->size);
	free (path);
	io_memory_close (fd);
	return true;
}

RIOPlugin r_io_plugin_xattr = {
	.name = "xattr",
	.desc = "access extended file attribute",
	.author = "pancake",
	.uris = "xattr://",
	.license = "LGPL3",
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
	.name = "xattr",
	.desc = "access extended file attribute (not supported)",
	.uris = "xattr://",
	.license = "LGPL3",
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_xattr,
	.version = R2_VERSION
};
#endif
