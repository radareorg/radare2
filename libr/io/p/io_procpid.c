/* radare - LGPL - Copyright 2010-2024 - pancake */

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

#define RIOPROCPID_PID(x) (((RIOProcpid*)(x)->data)->pid)
#define RIOPROCPID_FD(x) (((RIOProcpid*)(x)->data)->fd)

static int __waitpid(int pid) {
	int st = 0;
	return waitpid (pid, &st, 0) != -1;
}

static int debug_os_read_at(int fdn, void *buf, int sz, ut64 addr) {
	if (lseek (fdn, addr, 0) < 0) {
		return -1;
	}
	return read (fdn, buf, sz);
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	memset (buf, io->Oxff, len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (RIOPROCPID_FD (fd), buf, len, io->off);
}

static int procpid_write_at(int fd, const ut8 *buf, int sz, ut64 addr) {
	if (lseek (fd, addr, 0) < 0) {
		return -1;
	}
	return write (fd, buf, sz);
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return procpid_write_at (RIOPROCPID_FD (fd), buf, len, io->off);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "procpid://");
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char procpidpath[64];
	int fd, ret = -1;
	if (__plugin_open (io, file, 0)) {
		int pid = atoi (file + 10);
		if (file[0] == 'a') {
			ret = ptrace (PTRACE_ATTACH, pid, 0, 0);
			if (ret == -1) {
				switch (errno) {
				case EPERM:
					ret = pid;
					R_LOG_ERROR ("Operation not permitted");
					break;
				case EINVAL:
					r_sys_perror ("ptrace: Cannot attach");
					break;
				}
			} else if (__waitpid (pid)) {
				ret = pid;
			} else {
				R_LOG_ERROR ("waitpid");
			}
		} else {
			ret = pid;
		}
		fd = ret; // TODO: use r_io_fd api
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
			RIODesc *d = r_io_desc_new (io, &r_io_plugin_procpid, file, true, 0, riop);
			d->name = r_sys_pid_to_path (riop->pid);
			return d;
		}
		/* kill children */
		R_LOG_ERROR ("Cannot open /proc/%d/mem of an already attached process", pid);
		(void)ptrace (PTRACE_DETACH, pid, 0, 0);
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static bool __close(RIODesc *fd) {
	int ret = ptrace (PTRACE_DETACH, RIOPROCPID_PID (fd), 0, 0);
	R_FREE (fd->data);
	return ret == 0;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOProcpid *iop = (RIOProcpid*)fd->data;
	if (r_str_startswith (cmd, "pid")) {
		int pid = atoi (cmd + 3);
		if (pid > 0) {
			iop->pid = pid;
		}
		io->cb_printf ("%d\n", iop->pid);
	} else {
		R_LOG_ERROR ("Try: ':pid'");
	}
	return NULL;
}

RIOPlugin r_io_plugin_procpid = {
	.meta = {
		.name = "procpid",
		.author = "pancake",
		.desc = "Open /proc/[pid]/mem io",
		.license = "LGPL-3.0-only",
	},
	.uris = "procpid://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.write = __write,
};

#else
RIOPlugin r_io_plugin_procpid = {
	.meta = {
		.name = NULL
	},
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_procpid,
	.version = R2_VERSION
};
#endif
