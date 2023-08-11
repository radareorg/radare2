/* radare - LGPL - Copyright 2008-2022 pancake */

#include "r_io.h"
#include "r_lib.h"

#if R2__WINDOWS__
#include <sys/types.h>

typedef struct {
	HANDLE hnd;
	ut64 winbase;
} RIOW32;
#define RIOW32_HANDLE(x) (((RIOW32*)x)->hnd)

static int w32__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data) {
		return -1;
	}
	return WriteFile (RIOW32_HANDLE (fd), buf, count, NULL, NULL);
}

static int w32__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	DWORD ret;
	return ReadFile (RIOW32_HANDLE (fd), buf, count, &ret, NULL)?ret:-1;
}

static bool w32__close(RIODesc *fd) {
	if (fd->data) {
		CloseHandle (RIOW32_HANDLE (fd));
		R_FREE (fd->data);
		return true;
	}
	return false;
}

static ut64 w32__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	int where = !whence? FILE_BEGIN: whence == 1? FILE_CURRENT: FILE_END;
	SetFilePointer (RIOW32_HANDLE (fd), offset, 0, where);
	return (whence == 0)? offset: (whence == 1)? io->off + offset: ST64_MAX;
}

static bool w32__plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "w32://");
}

static RIODesc *w32__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_str_startswith (pathname, "w32://")) {
		RIOW32 *w32 = R_NEW0 (RIOW32);
		if (!w32) {
			return NULL;
		}
		const char *filename = pathname + 6;
		LPTSTR filename_ = r_sys_conv_utf8_to_win (filename);
		w32->hnd = CreateFile (filename_,
			GENERIC_READ | (rw ? GENERIC_WRITE : 0),
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		free (filename_);
		if (w32->hnd != INVALID_HANDLE_VALUE)
			return r_io_desc_new (io, &r_io_plugin_w32,
				pathname, rw, mode, w32);
		free (w32);
	}
	return NULL;
}

static char *w32__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (io && fd && fd->data && cmd && !strcmp (cmd, "winbase")) {
		RIOW32 *w32 = (RIOW32 *)fd->data;
		io->cb_printf ("%"PFMT64u , w32->winbase);
	}
	return NULL;
}

RIOPlugin r_io_plugin_w32 = {
	.meta = {
		.name = "w32",
		.desc = "w32 API io",
		.author = "pancake",
		.license = "LGPL3",
	},
	.uris = "w32://",
	.open = w32__open,
	.close = w32__close,
	.read = w32__read,
	.check = w32__plugin_open,
	.seek = w32__lseek,
	.system = w32__system,
	.write = w32__write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32,
	.version = R2_VERSION
};
#endif

#else
struct r_io_plugin_t r_io_plugin_w32 = {
	.meta = {
		.name = (void*)0
	}
};

#endif
