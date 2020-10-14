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

#define W32DbgWInst_PID(x) (((W32DbgWInst*)x->data)->pi.dwProcessId)

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

static int debug_os_read_at(W32DbgWInst *dbg, ut8 *buf, int len, ut64 addr) {
	SIZE_T ret = 0;
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

static int w32dbg_write_at(W32DbgWInst *dbg, const ut8 *buf, int len, ut64 addr) {
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

static int __open_proc(RIO *io, int pid, bool attach) {
	DEBUG_EVENT de;
	int ret = -1;
	if (!io->w32dbg_wrap) {
		io->w32dbg_wrap = (struct w32dbg_wrap_instance_t *)w32dbg_wrap_new ();
	}

	HANDLE h_proc = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);

	if (!h_proc) {
		r_sys_perror ("__open_proc/OpenProcess");
		goto att_exit;
	}
	W32DbgWInst *wrap = (W32DbgWInst *)io->w32dbg_wrap;
	wrap->pi.dwProcessId = pid;
	if (attach) {
		/* Attach to the process */	
		wrap->params.type = W32_ATTACH;
		w32dbg_wrap_wait_ret (wrap);
		if (!w32dbgw_ret (wrap)) {
			w32dbgw_err (wrap);
			r_sys_perror ("__open_proc/DebugActiveProcess");
			goto att_exit;
		}
		/* catch create process event */
		wrap->params.type = W32_WAIT;
		wrap->params.wait.wait_time = 10000;
		wrap->params.wait.de = &de;
		w32dbg_wrap_wait_ret (wrap);
		if (!w32dbgw_ret (wrap)) {
			w32dbgw_err (wrap);
			r_sys_perror ("__open_proc/WaitForDebugEvent");
			goto att_exit;
		}
		if (de.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT) {
			eprintf ("exception code 0x%04x\n", (ut32)de.dwDebugEventCode);
			goto att_exit;
		}
		wrap->winbase = (ut64)de.u.CreateProcessInfo.lpBaseOfImage;
		wrap->pi.dwThreadId = de.dwThreadId;
		wrap->pi.hThread = de.u.CreateProcessInfo.hThread;
	}
	wrap->pi.hProcess = h_proc;
	ret = wrap->pi.dwProcessId;
att_exit:
	if (ret == -1 && h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (__plugin_open (io, file, 0)) {
		RIODesc *ret;
		if (__open_proc (io, atoi (file + 9), !strncmp (file, "attach://", 9)) == -1) {
			return NULL;
		}
		W32DbgWInst *wrap = (W32DbgWInst *)io->w32dbg_wrap;
		if (!wrap->pi.dwThreadId) {
			wrap->pi.dwThreadId = __w32_first_thread (wrap->pi.dwProcessId);
		}
		if (!wrap->pi.hThread) {
			wrap->pi.hThread = OpenThread (THREAD_ALL_ACCESS, FALSE, wrap->pi.dwThreadId);
		}
		ret = r_io_desc_new (io, &r_io_plugin_w32dbg,
				file, rw | R_PERM_X, mode, wrap);
		ret->name = r_sys_pid_to_path (wrap->pi.dwProcessId);
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
	if (r_str_startswith (fd->uri, "attach://")) {
		W32DbgWInst *wrap = fd->data;
		wrap->params.type = W32_DETACH;
		w32dbg_wrap_wait_ret (wrap);
	}
	return false;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	W32DbgWInst *wrap = fd->data;
	//printf("w32dbg io command (%s)\n", cmd);
	/* XXX ugly hack for testing purposes */
	if (!strcmp (cmd, "")) {
		// do nothing
	} else if (!strncmp (cmd, "pid", 3)) {
		if (cmd[3] == ' ') {
			int pid = atoi (cmd + 3);
			if (pid > 0 && pid != wrap->pi.dwThreadId && pid != wrap->pi.dwProcessId) {
				wrap->pi.hThread = OpenThread (PROCESS_ALL_ACCESS, FALSE, pid);
				if (!wrap->pi.hThread) {
					eprintf ("Cannot attach to %d\n", pid);
				}
			}
		}
		return r_str_newf ("%d", wrap->pi.dwProcessId);
	} else {
		eprintf ("Try: '=!pid'\n");
	}
	return NULL;
}

static int __getpid(RIODesc *fd) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	if (!wrap) {
		return -1;
	}
	return wrap->pi.dwProcessId;
}

static int __gettid(RIODesc *fd) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	return wrap? wrap->pi.dwThreadId: -1;
}

static bool __getbase(RIODesc *fd, ut64 *base) {
	W32DbgWInst *wrap = (W32DbgWInst *)(fd ? fd->data : NULL);
	if (base && wrap) {
		*base = wrap->winbase;
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
