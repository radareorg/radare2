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
#include <tlhelp32.h>

static PROCESS_INFORMATION pi;

static int debug_os_read_at(int pid, void *buf, int len, ut64 addr) {
	PDWORD ret;
        ReadProcessMemory (pi.hProcess, (PCVOID)(ULONG)addr, buf, len, &ret);
//	if (len != ret)
//		eprintf ("Cannot read 0x%08llx\n", addr);
	return len; // XXX: Handle read correctly and not break r2 shell
	//return (int)ret; //(int)len; //ret;
}

static int __read(struct r_io_t *io, int pid, ut8 *buf, int len) {
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (pid, buf, len, io->off);
}

static int w32dbg_write_at(int pid, const ut8 *buf, int len, ut64 addr) {
	PDWORD ret;
        WriteProcessMemory (pi.hProcess, (PCVOID)(ULONG)addr, buf, len, &ret);
	return ret;
}

static int __write(struct r_io_t *io, int pid, const ut8 *buf, int len) {
	return w32dbg_write_at (pid, buf, len, io->off);
}

static int __plugin_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "attach://", 9))
		return R_TRUE;
	return (!memcmp (file, "w32dbg://", 9))? R_TRUE: R_FALSE;
}

static int __attach (int pid) {
	eprintf ("---> attach to %d\n", pid);
	pi.hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (pi.hProcess == NULL)
		return -1;
	return pid;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	int ret = -1;
	if (__plugin_open (io, file)) {
		int pid = atoi (file+9);
		ret = __attach (pid);
	}
	if (ret != -1)
		fds[0] = ret;
	return ret;
}

static ut64 __lseek(RIO *io, int fildes, ut64 offset, int whence) {
	static ut64 malloc_seek = 0LL;
	switch (whence) {
	case SEEK_SET:
		malloc_seek = offset;
		break;
	case SEEK_CUR:
		malloc_seek += offset;
		break;
	case SEEK_END:
		malloc_seek = UT64_MAX;
		break;
	}
	return malloc_seek;
}

static int __close(RIO *io, int pid) {
	// TODO: detach
	return R_TRUE;
}

static int __system(RIO *io, int fd, const char *cmd) {
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
        //void *plugin;
	.name = "io_w32dbg",
        .desc = "w32dbg io",
        .open = __open,
        .close = __close,
	.read = __read,
        .plugin_open = __plugin_open,
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
