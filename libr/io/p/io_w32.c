/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include "r_io.h"
#include "r_lib.h"

#if __WINDOWS__
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
} RIOW32;
#define RIOW32_HANDLE(x) (((RIOW32*)x)->hnd)

static int w32__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data)
		return -1;
	return WriteFile (RIOW32_HANDLE (fd), buf, count, NULL, NULL);
}

static int w32__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	DWORD ret;
	return ReadFile (RIOW32_HANDLE (fd), buf, count, &ret, NULL)?ret:-1;
}

static int w32__close(RIODesc *fd) {
	if (fd->data) {
		// TODO: handle return value
		CloseHandle (RIOW32_HANDLE (fd));
		free (fd->data);
		fd->data = NULL;
		return 0;
	}
	return -1;
}

// TODO: handle filesize and so on
static ut64 w32__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	SetFilePointer (RIOW32_HANDLE (fd), offset, 0, !whence?FILE_BEGIN:whence==1?FILE_CURRENT:FILE_END);
        return (!whence)?offset:whence==1?io->off+offset:UT64_MAX;
}

static int w32__plugin_open(RIO *io, const char *pathname, ut8 many) {
	return (!strncmp (pathname, "w32://", 6));
}

static inline int getw32fd (RIOW32 *w32) {
	return (int)(size_t)w32->hnd;
}

static RIODesc *w32__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "w32://", 6)) {
		RIOW32 *w32 = R_NEW0 (RIOW32);
		const char *filename = pathname+6;
		w32->hnd = CreateFile (filename,
			GENERIC_READ | rw?GENERIC_WRITE:0,
			FILE_SHARE_READ | rw? FILE_SHARE_WRITE:0,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (w32->hnd != INVALID_HANDLE_VALUE)
			return r_io_desc_new (io, &r_io_plugin_w32,
				pathname, rw, mode, w32);
		free (w32);
	}
	return NULL;
}

RIOPlugin r_io_plugin_w32 = {
	.name = "w32",
        .desc = "w32 API io",
	.license = "LGPL3",
        .open = w32__open,
        .close = w32__close,
	.read = w32__read,
        .check = w32__plugin_open,
	.lseek = w32__lseek,
	.system = NULL, // w32__system,
	.write = w32__write,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32,
	.version = R2_VERSION
};
#endif

#else
struct r_io_plugin_t r_io_plugin_w32 = {
	.name = (void*)0 
};

#endif
