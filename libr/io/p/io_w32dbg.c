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
	ut64 winbase;
	PROCESS_INFORMATION pi;
} RIOW32Dbg;
#define RIOW32DBG_PID(x) (((RIOW32Dbg*)x->data)->pid)

#undef R_IO_NFDS
#define R_IO_NFDS 2

static int debug_os_read_at(RIOW32Dbg *dbg, void *buf, int len, ut64 addr) {
	SIZE_T ret;
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
	SIZE_T ret;
	return 0 != WriteProcessMemory (dbg->pi.hProcess, (void *)(size_t)addr, buf, len, &ret)? len: 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
	return w32dbg_write_at (fd->data, buf, len, io->off);
}

static bool __plugin_open(RIO *io, const char *file, bool many) {
	if (!strncmp (file, "attach://", 9)) {
		return true;
	}
	return !strncmp (file, "w32dbg://", 9);
}

// mingw32 toolchain doesnt have this symbol
static HANDLE (WINAPI *r2_OpenThread)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
) = NULL;

static int __w32_first_thread(int pid) {
	HANDLE th;
	HANDLE thid;
	THREADENTRY32 te32;
	te32.dwSize = sizeof (THREADENTRY32);

	th = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, pid);
	if (th == INVALID_HANDLE_VALUE) {
		return -1;
	}
	if (!Thread32First (th, &te32)) {
		CloseHandle (th);
		return -1;
	}
	do {
		/* get all threads of process */
		if (te32.th32OwnerProcessID == pid) {
#if __MINGW32__
			r2_OpenThread = r_lib_dl_sym (NULL, "OpenThread");
#else
			r2_OpenThread = OpenThread;
#endif
			thid = r2_OpenThread
			? r2_OpenThread (THREAD_ALL_ACCESS, 0, te32.th32ThreadID) : NULL;
			if (!thid) {
				r_sys_perror ("__w32_first_thread/OpenThread");
				goto err_first_th;
			}
			CloseHandle (th);
			return te32.th32ThreadID;
		}
	} while (Thread32Next (th, &te32));
err_first_th:
	eprintf ("Could not find an active thread for pid %d\n", pid);
	CloseHandle (th);
	return pid;
}

static int __open_proc (RIOW32Dbg *dbg, bool attach) {
	DEBUG_EVENT de;
	int ret = -1;
	HANDLE h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);

	if (!h_proc) {
		r_sys_perror ("__open_proc/OpenProcess");
		goto att_exit;
	}
	if (attach) {
		/* Attach to the process */
		if (!DebugActiveProcess(dbg->pid)) {
			r_sys_perror ("__open_proc/DebugActiveProcess");
			goto att_exit;
		}
		/* catch create process event */
		if (!WaitForDebugEvent (&de, 10000)) {
			r_sys_perror ("__open_proc/WaitForDebugEvent");
			goto att_exit;
		}
		if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
			eprintf ("exception code 0x%04x\n", (ut32)de.dwDebugEventCode);
			goto att_exit;
		}
		dbg->winbase = (ut64)de.u.CreateProcessInfo.lpBaseOfImage;
	}
	dbg->pi.hProcess = h_proc;
	dbg->tid = __w32_first_thread (dbg->pid);
	ret = dbg->pid;
att_exit:
	if (ret == -1 && h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		char *pidpath;
		RIODesc *ret;
		RIOW32Dbg *dbg = R_NEW0 (RIOW32Dbg);
		if (!dbg) {
			return NULL;
		}
		dbg->pid = atoi (file + 9);
		if (__open_proc (dbg, !strncmp (file, "attach://", 9)) == -1) {
			free (dbg);
			return NULL;
		}
		pidpath = r_sys_pid_to_path (dbg->pid);
		ret = r_io_desc_new (io, &r_io_plugin_w32dbg,
				file, rw | R_PERM_X, mode, dbg);
		ret->name = pidpath;
		return ret;
	}
	return NULL;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case 0: // abs
		io->off = offset;
		break;
	case 1: // cur
		io->off += (int)offset;
		break;
	case 2: // end
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int __close(RIODesc *fd) {
	// TODO: detach
	return true;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOW32Dbg *iop = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strncmp (cmd, "pid", 3)) {
		if (cmd[3] == ' ') {
			int pid = atoi (cmd + 3);
			if (pid > 0 && pid != iop->pid) {
				iop->pi.hProcess = OpenProcess (PROCESS_ALL_ACCESS, false, pid);
				if (iop->pi.hProcess) {
					iop->pid = iop->tid = pid;
				} else {
					eprintf ("Cannot attach to %d\n", pid);
				}
			}
			/* TODO: Implement child attach */
		}
		return r_str_newf ("%d", iop->pid);
	} else {
		eprintf ("Try: '=!pid'\n");
	}
	return NULL;
}

static int __getpid (RIODesc *fd) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (!iow) {
		return -1;
	}
	return iow->pid;
}

static int __gettid (RIODesc *fd) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	return iow? iow->tid: -1;
}

static bool __getbase (RIODesc *fd, ut64 *base) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (base && iow) {
		*base = iow->winbase;
		return true;
	}
	return false;
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
	.gettid = __gettid,
	.getbase = __getbase,
	.isdbg = true
};
#else
RIOPlugin r_io_plugin_w32dbg = {
	.name = NULL
};
#endif

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg,
	.version = R2_VERSION
};
#endif
