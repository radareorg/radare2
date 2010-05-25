/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

// XXX: maybe it works on other OS
#if __linux__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

static int fd;
static int pid;

static int __waitpid(int pid) {
	int st = 0;
	if (waitpid(pid, &st, 0) == -1)
		return R_FALSE;
	return R_TRUE;
}

static int debug_os_read_at(int pid, void *buf, int sz, ut64 addr) {
	// TODO: use map pid/fd
	lseek (fd, addr, 0);
	return read (fd, buf, sz);
}

static int __read(struct r_io_t *io, int pid, ut8 *buf, int len) {
	ut64 addr = io->off;
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (pid, buf, len, addr);
}

static int procpid_write_at(int pid, const ut8 *buf, int sz, ut64 addr) {
	lseek (fd, addr, 0);
	return write (fd, buf, sz);
}

static int __write(struct r_io_t *io, int pid, const ut8 *buf, int len) {
	return procpid_write_at (pid, buf, len, io->off);
}

static int __handle_open(struct r_io_t *io, const char *file) {
	if (!memcmp (file, "procpid://", 10))
		return R_TRUE;
	return R_FALSE;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	char procpidpath[64];
	int ret = -1;
	if (__handle_open (io, file)) {
		int pid = atoi (file+10);
		if (file[0]=='a') {
			ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
			if (ret == -1) {
				switch (errno) {
				case EPERM:
					ret = pid;
					eprintf ("Operation not permitted\n");
					break;
				case EINVAL:
					perror ("ptrace: Cannot attach");
					eprintf ("ERRNO: %d (EINVAL)\n", errno);
					break;
				}
			} else
			if (__waitpid(pid))
				ret = pid;
			else eprintf ("Error in waitpid\n");
		} else ret = pid;
	}
	fd = ret;//TODO: use r_io_fd api
	snprintf (procpidpath, sizeof (procpidpath), "/proc/%d/mem", pid);
	fd = open (procpidpath, O_RDWR);
	if (fd == -1) {
		/* kill children */
		eprintf ("Cannot open /proc/%d/mem of already attached process\n", pid);
		ptrace (PTRACE_DETACH, pid, 0, 0);
	}
	return ret;
}

static ut64 __lseek(struct r_io_t *io, int fildes, ut64 offset, int whence) {
	return offset;
}

static int __close(struct r_io_t *io, int pid) {
	return ptrace (PTRACE_DETACH, pid, 0, 0);
}

static int __system(struct r_io_t *io, int fd, const char *cmd) {
	//printf("ptrace io command (%s)\n", cmd);
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
	return R_TRUE;
}

// TODO: rename ptrace to io_ptrace .. err io.ptrace ??
struct r_io_plugin_t r_io_plugin_procpid = {
        //void *handle;
	.name = "procpid",
        .desc = "proc/pid/mem io",
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
struct r_io_plugin_t r_io_plugin_ptrace = {
	.name = "procpid",
        .desc = "proc/pid/mem io (NOT SUPPORTED FOR THIS PLATFORM)",
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_procpid
};
#endif
