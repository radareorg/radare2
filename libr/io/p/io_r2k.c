/* io_r2k - radare2 - LGPL - Copyright 2016-2025 - pancake, SkUaTeR, panda */

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <sys/types.h>

#if R2__WINDOWS__
#include "io_r2k_windows.h"
#elif defined (__linux__) && !defined (__GNU__)
#include "io_r2k_linux.h"
struct io_r2k_linux r2k_struct; // TODO: move this into desc->data
#else
int r2k_struct; // dummy
#endif

int r2k__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
#if R2__WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory (io->off, buf, count);
#elif defined (__linux__) && !defined (__GNU__)
	switch (r2k_struct.beid) {
	case 0:
		return WriteMemory (io, fd, IOCTL_WRITE_KERNEL_MEMORY, r2k_struct.pid, io->off, buf, count);
	case 1:
		return WriteMemory (io, fd, IOCTL_WRITE_PROCESS_ADDR, r2k_struct.pid, io->off, buf, count);
	case 2:
		return WriteMemory (io, fd, IOCTL_WRITE_PHYSICAL_ADDR, r2k_struct.pid, io->off, buf, count);
	default:
		R_LOG_ERROR ("Undefined beid in r2k__write");
		return -1;
	}
#else
	R_LOG_TODO ("r2k not implemented for this plataform");
	return -1;
#endif
}

static int r2k__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if R2__WINDOWS__
	return ReadKernelMemory (io->off, buf, count);
#elif defined (__linux__) && !defined (__GNU__)
	switch (r2k_struct.beid) {
	case 0:
		return ReadMemory (io, fd, IOCTL_READ_KERNEL_MEMORY, r2k_struct.pid, io->off, buf, count);
	case 1:
		return ReadMemory (io, fd, IOCTL_READ_PROCESS_ADDR, r2k_struct.pid, io->off, buf, count);
	case 2:
		return ReadMemory (io, fd, IOCTL_READ_PHYSICAL_ADDR, r2k_struct.pid, io->off, buf, count);
	default:
		R_LOG_ERROR ("Undefined beid in r2k__read");
		memset (buf, io->Oxff, count);
		return count;
	}
#else
	R_LOG_TODO ("r2k not implemented for this plataform");
	memset (buf, io->Oxff, count);
	return count;
#endif
}

static bool r2k__close(RIODesc *fd) {
#if R2__WINDOWS__
	if (gHandleDriver) {
		CloseHandle (gHandleDriver);
		StartStopService (TEXT ("r2k"),TRUE);
	}
#elif defined (__linux__) && !defined (__GNU__)
	if (fd) {
		close ((int)(size_t)fd->data);
	}
#else
	R_LOG_TODO ("r2k not implemented for this plataform");
#endif
	return true;
}

static ut64 r2k__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence) ? offset : whence == 1
		? io->off + offset : UT64_MAX - 1;
}

static bool r2k__plugin_open(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "r2k://");
}

static char *r2k__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (R_STR_ISEMPTY (cmd)) {
		return NULL;
	}
	if (r_str_startswith (cmd, "mod")) {
#if R2__WINDOWS__
		GetSystemModules (io);
#endif
	} else {
#if defined (__linux__) && !defined (__GNU__)
		(void)run_ioctl_command (io, fd, cmd);
#else
		R_LOG_WARN ("Try with: ':mod' or '.:mod'");
#endif
	}
	return NULL;
}

static RIODesc *r2k__open(RIO *io, const char *pathname, int rw, int mode) {
	if (r_str_startswith (pathname, "r2k://")) {
		rw |= R_PERM_WX;
#if R2__WINDOWS__
		RIOW32 *w32 = R_NEW0 (RIOW32);
		if (!w32 || !Init (pathname + 6)) {
			R_LOG_ERROR ("r2k__open: Error cant init driver: %s", pathname + 6);
			free (w32);
			return NULL;
		}
		//return r_io_desc_new (&r_io_plugin_r2k, -1, pathname, rw, mode, w32);
		return r_io_desc_new (io, &r_io_plugin_r2k, pathname, rw, mode, w32);
#elif defined (__linux__) && !defined (__GNU__)
		int fd = open ("/dev/r2k", O_RDONLY);
		if (fd == -1) {
			R_LOG_ERROR ("r2k__open: Error in opening /dev/r2k");
			return NULL;
		}

		r2k_struct.beid = 0;
		r2k_struct.pid = 0;
		r2k_struct.wp = 1;
		return r_io_desc_new (io, &r_io_plugin_r2k, pathname, rw, mode, (void *)(size_t)fd);
#else
		R_LOG_ERROR ("Not supported on this platform");
#endif
	}
	return NULL;
}

RIOPlugin r_io_plugin_r2k = {
	.meta = {
		.name = "r2k",
		.desc = "Client side to comunicate with the r2k kernel module",
		.author = "skuater,panda",
		.license = "LGPL-3.0-only",
	},
	.uris = "r2k://",
	.open = r2k__open,
	.close = r2k__close,
	.read = r2k__read,
	.check = r2k__plugin_open,
	.seek = r2k__lseek,
	.system = r2k__system,
	.write = r2k__write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2k,
	.version = R2_VERSION
};
#endif

