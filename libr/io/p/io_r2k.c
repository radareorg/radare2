/* io_r2k - radare2 - LGPL - Copyright 2016 - SkUaTeR + panda */

#include <r_io.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_print.h>
#include <r_util.h>
#include <sys/types.h>

#if __WINDOWS__
#include "io_r2k_windows.h"
#elif __linux__
#include "io_r2k_linux.h"
#endif

int r2k__write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
#if __WINDOWS__
	//eprintf("writing to: 0x%"PFMT64x" len: %x\n",io->off, count);
	return WriteKernelMemory (io->off, buf, count);
#elif __linux__
	return WriteMemory (io, fd, IOCTL_WRITE_KERNEL_MEMORY, 0, io->off, buf, count);
#else
	io->cb_printf ("TODO: r2k not implemented for this plataform.\n");
	return -1;
#endif
}

static int r2k__read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
#if __WINDOWS__
	return ReadKernelMemory (io->off, buf, count);
#elif __linux__
	return ReadMemory (io, fd, IOCTL_READ_KERNEL_MEMORY, 0, io->off, buf, count);
#else
	io->cb_printf ("TODO: r2k not implemented for this plataform.\n");
	memset (buf, '\xff', count);
	return count;
#endif
}

static int r2k__close(RIODesc *fd) {
#if __WINDOWS__
	if (gHandleDriver) {
		CloseHandle (gHandleDriver);
		StartStopService ("r2k",TRUE);
	}
#elif __linux__
	if (fd) {
		close (fd->fd);
	}
#else
	eprintf ("TODO: r2k not implemented for this plataform.\n");
#endif
	return 0;
}

static ut64 r2k__lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence) ? offset : whence == 1
		? io->off + offset : UT64_MAX;
}

static bool r2k__plugin_open(RIO *io, const char *pathname, bool many) {
	return (!strncmp (pathname, "r2k://", 6));
}

static int r2k__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (!strncmp (cmd, "mod", 3)) {
#if __WINDOWS__
		GetSystemModules (io);
#endif
	} else {
#if __linux__
		run_ioctl_command (io, fd, cmd);
#else
		eprintf ("Try: '=!mod'\n    '.=!mod'\n");
#endif
	}
	return -1;
}

static RIODesc *r2k__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!strncmp (pathname, "r2k://", 6)) {
#if __WINDOWS__
		RIOW32 *w32 = R_NEW0 (RIOW32);
		if (Init (&pathname[6]) == FALSE) {
			eprintf ("r2k__open: Error cant init driver: %s\n", &pathname[6]);
			free (w32);
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_r2k, -1, pathname, rw, mode, w32);
#elif __linux__
		int fd = open ("/dev/r2k", O_RDONLY);
		if (fd == -1) {
			io->cb_printf ("r2k__open: Error in opening /dev/r2k.");
			return NULL;
		}
		return r_io_desc_new (&r_io_plugin_r2k, fd, pathname, rw, mode, NULL);
#else
		io->cb_printf ("Not supported on this platform\n");
#endif
	}
	return NULL;
}

RIOPlugin r_io_plugin_r2k = {
	.name = "r2k",
	.desc = "kernel access API io (r2k://)",
	.license = "LGPL3",
	.open = r2k__open,
	.close = r2k__close,
	.read = r2k__read,
	.check = r2k__plugin_open,
	.lseek = r2k__lseek,
	.system = r2k__system,
	.write = r2k__write,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2k,
	.version = R2_VERSION
};
#endif

