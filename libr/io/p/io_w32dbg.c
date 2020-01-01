/* radare - LGPL - Copyright 2008-2016 - pancake */

#include <r_userconf.h>

#include <r_io.h>
#include <r_lib.h>
#include <r_cons.h>
#include <r_util.h>

#if __WINDOWS__

#include <windows.h>
#include <tlhelp32.h>
#include <w32dbg_wrap.h>

#define RIOW32DBG_PID(x) (((RIOW32Dbg*)x->data)->pi.dwProcessId)

#undef R_IO_NFDS
#define R_IO_NFDS 2

static ut64 __find_next_valid_addr(HANDLE h, ut64 from, ut64 to) {
	// Align to next page and try to get to next valid addr
	const int page_size = 0x1000;
	from = ((from + page_size) / page_size) * page_size;
	ut8 buf;
	while (from < to && !ReadProcessMemory (h, (void *)from, &buf, 1, NULL)) {
		from += page_size;
	}
	return from < to ? from : UT64_MAX;
}

static int debug_os_read_at(RIOW32Dbg *dbg, ut8 *buf, int len, ut64 addr) {
	SIZE_T ret = 0;
	const int page_size = 0x1000;
	if (!ReadProcessMemory (dbg->pi.hProcess, (void*)(size_t)addr, buf, len, &ret)
		&& GetLastError () == ERROR_PARTIAL_COPY) {
		int skipped = 0;
		if (!ReadProcessMemory (dbg->pi.hProcess, (void *)(size_t)addr, buf, 1, &ret)) {
			// We are starting a read from invalid memory
			ut64 valid_addr = __find_next_valid_addr (dbg->pi.hProcess, addr, addr + len);
			if (valid_addr == UT64_MAX) {
				return len;
			}
			skipped = valid_addr - addr;
			memset (buf, '\xff', skipped);
			addr = valid_addr;
			buf += skipped;
		}
		// We are in a valid page now, try to read again
		int read_len = len - skipped;
		int totRead = skipped;
		while (totRead < len) {
			while (!ReadProcessMemory (dbg->pi.hProcess, (void *)(size_t)addr, buf, read_len, &ret)) {
				// Maybe read_len is too big, we are reaching invalid memory
				read_len /= 2;
				if (!read_len) {
					// Reached the end of valid memory, find another to continue reading if possible
					ut64 valid_addr = __find_next_valid_addr (dbg->pi.hProcess, addr, addr + len - totRead);
					if (valid_addr == UT64_MAX) {
						return len;
					}
					skipped = valid_addr - addr;
					addr = valid_addr;
					memset (buf, '\xff', skipped);
					buf += skipped;
					totRead += skipped;
					read_len = len - totRead;
				}
			}
			buf += ret;
			addr += ret;
			totRead += ret;
			read_len = R_MIN (read_len, len - totRead);
		}
	}
	return len;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
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
			r2_OpenThread = OpenThread;
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

static int __open_proc(RIO *io, RIOW32Dbg *dbg, bool attach) {
	DEBUG_EVENT de;
	int ret = -1;
	HANDLE h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pi.dwProcessId);

	if (!h_proc) {
		r_sys_perror ("__open_proc/OpenProcess");
		goto att_exit;
	}
	if (!io->w32dbg_wrap) {
		io->w32dbg_wrap = w32dbg_wrap_new ();
	}
	if (attach) {
		/* Attach to the process */
		w32dbg_wrap_instance *inst = io->w32dbg_wrap;
		inst->params->type = W32_ATTACH;
		inst->params->pid = dbg->pi.dwProcessId;
		w32dbg_wrap_wait_ret (inst);
		if (!w32dbgw_ret (inst)) {
			w32dbgw_err (inst);
			r_sys_perror ("__open_proc/DebugActiveProcess");
			goto att_exit;
		}
		/* catch create process event */
		inst->params->type = W32_WAIT;
		inst->params->wait.wait_time = 10000;
		inst->params->wait.de = &de;
		w32dbg_wrap_wait_ret (inst);
		if (!w32dbgw_ret (inst)) {
			w32dbgw_err (inst);
			r_sys_perror ("__open_proc/WaitForDebugEvent");
			goto att_exit;
		}
		if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
			eprintf ("exception code 0x%04x\n", (ut32)de.dwDebugEventCode);
			goto att_exit;
		}
		dbg->winbase = (ut64)de.u.CreateProcessInfo.lpBaseOfImage;
	}
	dbg->inst = io->w32dbg_wrap;
	dbg->pi.hProcess = h_proc;
	dbg->pi.dwProcessId = dbg->pi.dwProcessId;
	ret = dbg->pi.dwProcessId;
att_exit:
	if (ret == -1 && h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		RIODesc *ret;
		RIOW32Dbg *dbg = R_NEW0 (RIOW32Dbg);
		if (!dbg) {
			return NULL;
		}
		dbg->pi.dwProcessId = atoi (file + 9);
		if (__open_proc (io, dbg, !strncmp (file, "attach://", 9)) == -1) {
			free (dbg);
			return NULL;
		}
		dbg->pi.dwThreadId = __w32_first_thread (dbg->pi.dwProcessId);
		dbg->pi.hThread = OpenThread (THREAD_ALL_ACCESS, FALSE, dbg->pi.dwThreadId);
		ret = r_io_desc_new (io, &r_io_plugin_w32dbg,
				file, rw | R_PERM_X, mode, dbg);
		ret->name = r_sys_pid_to_path (dbg->pi.dwProcessId);
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
	RIOW32Dbg *iop = fd->data;
	iop->inst->params->type = W32_DETTACH;
	w32dbg_wrap_wait_ret (iop->inst);
	return false;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	RIOW32Dbg *iop = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "")) {
		// do nothing
	} else if (!strncmp (cmd, "pid", 3)) {
		if (cmd[3] == ' ') {
			int pid = atoi (cmd + 3);
			if (pid > 0 && pid != iop->pi.dwThreadId && pid != iop->pi.dwProcessId) {
				iop->pi.hThread = OpenThread (PROCESS_ALL_ACCESS, FALSE, pid);
				if (iop->pi.hThread) {
					iop->pi.dwThreadId = pid;
				} else {
					eprintf ("Cannot attach to %d\n", pid);
				}
			}
		}
		return r_str_newf ("%d", iop->pi.dwProcessId);
	} else {
		eprintf ("Try: '=!pid'\n");
	}
	return NULL;
}

static int __getpid(RIODesc *fd) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (!iow) {
		return -1;
	}
	return iow->pi.dwProcessId;
}

static int __gettid(RIODesc *fd) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	return iow? iow->pi.dwThreadId: -1;
}

static bool __getbase(RIODesc *fd, ut64 *base) {
	RIOW32Dbg *iow = (RIOW32Dbg *)(fd ? fd->data : NULL);
	if (base && iow) {
		*base = iow->winbase;
		return true;
	}
	return false;
}

RIOPlugin r_io_plugin_w32dbg = {
	.name = "w32dbg",
	.desc = "w32 debugger io plugin",
	.license = "LGPL3",
	.uris = "w32dbg://,attach://",
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_w32dbg,
	.version = R2_VERSION
};
#endif
