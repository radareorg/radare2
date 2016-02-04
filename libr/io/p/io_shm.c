/* radare - LGPL - Copyright 2008-2015 pancake */

#include "r_io.h"
#include "r_lib.h"
#include <sys/types.h>

#if __ANDROID__ || EMSCRIPTEN
#undef __UNIX__
#define __UNIX__ 0
#endif

#if __UNIX__ && !defined (__QNX__) && !defined (__HAIKU__)
#include <sys/ipc.h>
#include <sys/shm.h>

typedef struct {
	int fd;
	int id;
	ut8 *buf;
	ut32 size;
} RIOShm;
#define RIOSHM_FD(x) (((RIOShm*)x)->fd)

#define SHMATSZ 0x9000; // 32*1024*1024; /* 32MB : XXX not used correctly? */

static int shm__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOShm *shm;
	if (!fd || !fd->data)
		return -1;
	shm = fd->data;
	if (shm->buf != NULL) {
        	(void)memcpy (shm->buf+io->off, buf, count);
		return count;
	}
	return -1;
}

static int shm__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOShm *shm;
	if (!fd || !fd->data)
		return -1;
	shm = fd->data;
	if (io->off+count >= shm->size) {
		if (io->off > shm->size)
			return -1;
		count = shm->size - io->off;
	}
	if (count>32)
		count = 32;
	memcpy (buf, shm->buf+io->off , count);
        return count;
}

static int shm__close(RIODesc *fd) {
	int ret;
	if (!fd || !fd->data)
		return -1;
	ret = shmdt (((RIOShm*)(fd->data))->buf);
	free (fd->data);
	fd->data = NULL;
	return ret;
}

static ut64 shm__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOShm *shm;
	if (!fd || !fd->data)
		return -1;
	shm = fd->data;
	switch (whence) {
	case SEEK_SET:
		return offset;
	case SEEK_CUR:
		if (io->off+offset>shm->size)
			return shm->size;
		return io->off + offset;
	case SEEK_END:
		return 0xffffffff;
	}
	return io->off;
}

static bool shm__plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "shm://", 6));
}

static inline int getshmid (const char *str) {
	return atoi (str);
}

static inline int getshmfd (RIOShm *shm) {
	return (int)(size_t)shm->buf;
}

static RIODesc *shm__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "shm://", 6)) {
		RIOShm *shm = R_NEW0 (RIOShm);
		if (!shm) return NULL;
		const char *ptr = pathname+6;
		shm->id = getshmid (ptr);
		shm->buf = shmat (shm->id, 0, 0);
		shm->fd = getshmfd (shm);
		shm->size = SHMATSZ;
		if (shm->fd != -1) {
			eprintf ("Connected to shared memory 0x%08x\n", shm->id);
			return r_io_desc_new (io, &r_io_plugin_shm, pathname, rw, mode, shm);
		}
		eprintf ("Cannot connect to shared memory (%d)\n", shm->id);
		free (shm);
	}
	return NULL;
}

static int shm__init(RIO *io) {
	return true;
}

RIOPlugin r_io_plugin_shm = {
	.name = "shm",
        .desc = "shared memory resources (shm://key)",
	.license = "LGPL3",
        .open = shm__open,
        .close = shm__close,
	.read = shm__read,
        .check = shm__plugin_open,
	.lseek = shm__lseek,
	.init = shm__init,
	.write = shm__write,
};

#else
struct r_io_plugin_t r_io_plugin_shm = {
	.name = "shm",
        .desc = "shared memory resources (not for w32)",
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_shm,
	.version = R2_VERSION
};
#endif
