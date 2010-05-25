/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __WINDOWS__

#undef R_IO_NFDS
#define R_IO_NFDS 2
extern int errno;
static int fds[3];

#include <windows.h>

static PROCESS_INFORMATION pi;

// FIX: the goto 'err' is buggy
static int debug_os_read_at(int pid, void *buf, int len, ut64 addr) {
	PDWORD ret;
        ReadProcessMemory(pi.hProcess, (PCVOID)(ULONG)addr,
                        buf, len, &ret);
	return (int)ret;
}

static int __read(struct r_io_t *io, int pid, ut8 *buf, int len) {
	ut64 addr = io->off;
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (pid, buf, len, addr);
}

static int w32dbg_write_at(int pid, const ut8 *buf, int len, ut64 addr) {
	PDWORD ret;
        WriteProcessMemory (pi.hProcess, (PCVOID)(ULONG)addr,
                        buf, len, &ret);
	return ret;
}

static int __write(struct r_io_t *io, int pid, const ut8 *buf, int len) {
	return w32dbg_write_at(pid, buf, len, io->off);
}

static int __handle_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "w32dbg://", 9))
		return R_TRUE;
	return R_FALSE;
}

static int __attach (int pid) {
	eprintf ("---> attach to %d\n", pid);
	return pid;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	int ret = -1;
	if (__handle_open (io, file)) {
		int pid = atoi (file+9);
		ret = __attach (pid);
	}
	fds[0] = ret;
	return ret;
}

static ut64 __lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	return offset;
}

static int __close(struct r_io_t *io, int pid) {
	// TODO: detach
	return R_TRUE;
}

static int __system(struct r_io_t *io, int fd, const char *cmd) {
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "pid")) {
		int pid = atoi (cmd+4);
		if (pid != 0)
			io->fd = pid;
		//printf("PID=%d\n", io->fd);
		return io->fd;
	} else eprintf ("Try: '|pid'\n");
	return R_TRUE;
}

static int __init(struct r_io_t *io) {
	eprintf ("w32dbg init\n");
	return R_TRUE;
}

// TODO: rename w32dbg to io_w32dbg .. err io.w32dbg ??
struct r_io_plugin_t r_io_plugin_w32dbg = {
        //void *handle;
	.name = "io_w32dbg",
        .desc = "w32dbg io",
        .open = __open,
        .close = __close,
	.read = __read,
        .handle_open = __handle_open,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
        //void *widget;
/*
        struct debug_t *debug;
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};
#else
struct r_io_plugin_t r_io_plugin_w32dbg = {
	.name = "w32dbg",
        .desc = "w32dbg io (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg
};
#endif
