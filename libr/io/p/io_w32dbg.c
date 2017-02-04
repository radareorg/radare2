/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_util.h>

#if __WINDOWS__

#include <windows.h>
#include <tlhelp32.h>

typedef struct {
	int pid;
	int tid;
	PROCESS_INFORMATION pi;
} RIOW32Dbg;
#define RIOW32DBG_PID(x) (((RIOW32Dbg*)x->data)->pid)

#undef R_IO_NFDS
#define R_IO_NFDS 2

static int debug_os_read_at(RIOW32Dbg *dbg, void *buf, int len, ut64 addr) {
	DWORD ret;
        ReadProcessMemory (dbg->pi.hProcess, (void*)(size_t)addr, buf, len, &ret);
//	if (len != ret)
//		eprintf ("Cannot read 0x%08llx\n", addr);
	return len; // XXX: Handle read correctly and not break r2 shell
	//return (int)ret; //(int)len; //ret;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
	memset (buf, '\xff', len); // TODO: only memset the non-readed bytes
	return debug_os_read_at (fd->data, buf, len, io->off);
}

static int w32dbg_write_at(RIOW32Dbg *dbg, const ut8 *buf, int len, ut64 addr) {
	DWORD ret;
	return 0 != WriteProcessMemory (dbg->pi.hProcess, (void *)(size_t)addr, buf, len, &ret)? len: 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return w32dbg_write_at (fd->data, buf, len, io->off);
}

static int __plugin_open(RIO *io, const char *file, ut8 many) {
	if (!strncmp (file, "attach://", 9)) {
		return true;
	}
	return !strncmp (file, "w32dbg://", 9);
}

static int __attach (RIOW32Dbg *dbg) {
	dbg->pi.hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (!dbg->pi.hProcess) {
		return -1;
	}
	return dbg->pid;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		char *pidpath;
		RIOW32Dbg *dbg = R_NEW0 (RIOW32Dbg);
		if (!dbg) {
			return NULL;
		}
		dbg->pid = atoi (file + 9);
		if (__attach (dbg) == -1) {
			free (dbg);
			return NULL;
		}
		pidpath = r_sys_pid_to_path (dbg->pid);
		return r_io_desc_new (io, &r_io_plugin_w32dbg,
				pidpath, rw | R_IO_EXEC, mode, dbg);
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return (!whence)
		? offset
		: (whence == 1)
			? io->off + offset
			: UT64_MAX;
}

static int __close(RIODesc *fd) {
	// TODO: detach
	return true;
}

static int __system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOW32Dbg *iop = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strncmp (cmd, "pid", 3)) {
		if (cmd[3] == ' ') {
			int pid = atoi (cmd + 3);
			if  (pid > 0 && pid != iop->pid) {
				iop->pi.hProcess = OpenProcess (PROCESS_ALL_ACCESS, false, pid);
				if (iop->pi.hProcess) {
					iop->pid = iop->tid = pid;
				} else {
					eprintf ("Cannot attach to %d\n", pid);
				}
			}
			/* TODO: Implement child attach */
			return -1;
		} else {
			io->cb_printf ("%d\n", iop->pid);
			return iop->pid;
		}
	} else {
		eprintf ("Try: '=!pid'\n");
	}
	return -1;
}

static int __getpid (RIODesc *fd) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (!iow)
		return -1;
	return iow->pid;
}

RIOPlugin r_io_plugin_w32dbg = {
	.name = "w32dbg",
        .desc = "w32dbg io",
	.license = "LGPL3",
        .open = __open,
        .close = __close,
	.read = __read,
        .check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.isdbg = true
};
#else
struct r_io_plugin_t r_io_plugin_w32dbg = {
	.name = NULL
};
#endif

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg,
	.version = R2_VERSION
};
#endif
