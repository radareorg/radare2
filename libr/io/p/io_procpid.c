/* radare - LGPL - Copyright 2010-2016 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>

#if __linux__

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

typedef struct {
	int fd;
	int pid;
} RIOProcpid;

#define RIOPROCPID_PID(x) (((RIOProcpid*)x->data)->pid)
#define RIOPROCPID_FD(x) (((RIOProcpid*)x->data)->fd)

static int __waitpid(int pid) {
	int st = 0;
	return (waitpid(pid, &st, 0) != -1);
}

static int debug_os_read_at(int fdn, void *buf, int sz, ut64 addr) {
	if (lseek (fdn, addr, 0) < 0) {
		return -1;
	}
	return read (fdn, buf, sz);
}

static int __read(struct r_io_t *io, RIODesc *fd, ut8 *buf, int len) {
	memset (buf, 0xff, len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (RIOPROCPID_FD (fd), buf, len, io->off);
}

static int procpid_write_at(int fd, const ut8 *buf, int sz, ut64 addr) {
	if (lseek (fd, addr, 0) < 0) {
		return -1;
	}
	return write (fd, buf, sz);
}

static int __write(struct r_io_t *io, RIODesc *fd, const ut8 *buf, int len) {
	return procpid_write_at (RIOPROCPID_FD (fd), buf, len, io->off);
}

static bool __plugin_open(struct r_io_t *io, const char *file, bool many) {
	return (!strncmp (file, "procpid://", 10));
}

static RIODesc *__open(struct r_io_t *io, const char *file, int rw, int mode) {
	char procpidpath[64];
	int fd, ret = -1;
	if (__plugin_open (io, file, 0)) {
		int pid = atoi (file + 10);
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
			} else if (__waitpid(pid)) {
				ret = pid;
			} else {
				eprintf ("Error in waitpid\n");
			}
		} else {
			ret = pid;
		}
		fd = ret; //TODO: use r_io_fd api
		snprintf (procpidpath, sizeof (procpidpath), "/proc/%d/mem", pid);
		fd = r_sandbox_open (procpidpath, O_RDWR, 0);
		if (fd != -1) {
			RIOProcpid *riop = R_NEW0 (RIOProcpid);
			if (!riop) {
				close (fd);
				return NULL;
			}
			riop->pid = pid;
			riop->fd = fd;
			return r_io_desc_new (io, &r_io_plugin_procpid, file, true, 0, riop);
		}
		/* kill children */
		eprintf ("Cannot open /proc/%d/mem of already attached process\n", pid);
		(void)ptrace (PTRACE_DETACH, pid, 0, 0);
	}
	return NULL;
}

static ut64 __lseek(struct r_io_t *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __close(RIODesc *fd) {
	int ret = ptrace (PTRACE_DETACH, RIOPROCPID_PID (fd), 0, 0);
	free (fd->data);
	fd->data = NULL;
	return ret;
}

static int __system(struct r_io_t *io, RIODesc *fd, const char *cmd) {
	RIOProcpid *iop = (RIOProcpid*)fd->data;
	if (!strncmp (cmd, "pid", 3)) {
		int pid = atoi (cmd + 3);
		if (pid > 0) {
			iop->pid = pid;
		}
		io->cb_printf ("%d\n", iop->pid);
		return 0;
	} else eprintf ("Try: '=!pid'\n");
	return true;
}

static int __init(struct r_io_t *io) {
	return true;
}

RIOPlugin r_io_plugin_procpid = {
	.name = "procpid",
        .desc = "/proc/pid/mem io",
	.license = "LGPL3",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.init = __init,
	.write = __write,
};

#else
struct r_io_plugin_t r_io_plugin_procpid = {
	.name = NULL
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_procpid,
	.version = R2_VERSION
};
#endif
