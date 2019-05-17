/* radare - LGPL - Copyright 2019 - MapleLeaf-X */
#include <windows.h>
#include <processthreadsapi.h> // OpenProess, OpenProcessToken
#include "windows_debug.h"

typedef struct {
	bool dbgpriv;
	HANDLE processHandle;
} RIOW32;

int w32_init(RDebug *dbg) {
	/*HANDLE token;
	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		return false;
	}*/
	dbg->user = R_NEW (RIOW32);
	if (!dbg->user) {
		eprintf ("w32_dbg_init: failed to allocate memory\n");
		return false;
	}
	dbg->user->dbgpriv = false;
	dbg->user->processHandle = (HANDLE)NULL;
	return true;
}

int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	// disabled for now
	/*
	#ifdef _MSC_VER
	CONTEXT ctx;
#else
	CONTEXT ctx __attribute__ ((aligned (16)));
#endif
	int showfpu = false;
	int pid = dbg->pid;
	int tid = dbg->tid;
	HANDLE hThread = NULL;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	hThread = w32_open_thread (pid, tid);
	memset(&ctx, 0, sizeof (CONTEXT));
	ctx.ContextFlags = CONTEXT_ALL ;
	if (GetThreadContext (hThread, &ctx) == TRUE) {
		// on windows we dont need check type alway read/write full arena
		//if (type == R_REG_TYPE_GPR) {
			if (size > sizeof (CONTEXT)) {
				size = sizeof (CONTEXT);
			}
			memcpy (buf, &ctx, size);
		//} else {
		//	size = 0;
		//}
	} else {
		r_sys_perror ("w32_reg_read/GetThreadContext");
		size = 0;
	}
	if (showfpu) {
		printwincontext (hThread, &ctx);
	}
	CloseHandle(hThread);
	return size;
	*/
	return 0;
}

int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	// disabled for now
	/*BOOL ret = false;
	HANDLE thread;
#if _MSC_VER
	CONTEXT ctx;
#else
	CONTEXT ctx __attribute__((aligned (16)));
#endif
	thread = w32_open_thread (dbg->pid, dbg->tid);
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext (thread, &ctx);
	// on windows we dont need check type alway read/write full arena
	//if (type == R_REG_TYPE_GPR) {
		if (size > sizeof (CONTEXT)) {
			size = sizeof (CONTEXT);
		}
		memcpy (&ctx, buf, size);
		ret = SetThreadContext (thread, &ctx)? true: false;
	//}
	CloseHandle (thread);
	return ret;*/
	return false;
}

int w32_attach(RDebug *dbg, int pid) { // intrusive
	int ret = -1;
	RIOW32 *rio = dbg->user;
	// 
	if (rio->dbgpriv) {
	}
	if (!rio->processHandle) {
		rio->processHandle = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
		if (rio->processHandle != (HANDLE)NULL) {
			if (DebugActiveProcess (pid)) {
			}
			// TODO: get main thread id
		}
	}
	return ret;

	/*
	HANDLE process = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (process != (HANDLE)NULL && DebugActiveProcess (pid)) {
		ret = w32_first_thread (pid);
	} else {
		ret = -1;
	}
	// XXX: What is this for?
	ret = w32_first_thread (pid);
	CloseHandle (process);
	return ret;
	*/
}

int w32_step(RDebug *dbg) {
	// disabled for now
	/* set TRAP flag */
	/*
#if _MSC_VER
	CONTEXT regs;
#else
	// might not be required for mingw64 but leaving this here for now
	CONTEXT regs __attribute__ ((aligned (16)));
#endif
	r_debug_native_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof (regs));
	regs.EFlags |= 0x100;
	r_debug_native_reg_write (dbg, R_REG_TYPE_GPR, (ut8 *)&regs, sizeof (regs));
	r_debug_native_continue (dbg, dbg->pid, dbg->tid, dbg->reason.signum);
	(void)r_debug_handle_signals (dbg);
	return true;*/
	return false;
}

int w32_continue(RDebug *dbg, int pid, int tid, int sig) {
	// disabled for now
	/* Honor the Windows-specific signal that instructs threads to process exceptions */
	/*DWORD continue_status = (sig == DBG_EXCEPTION_NOT_HANDLED)
		? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
	if (ContinueDebugEvent (pid, tid, continue_status) == 0) {
		r_sys_perror ("r_debug_native_continue/ContinueDebugEvent");
		eprintf ("debug_contp: error\n");
		return false;
	}
	return tid;*/
	return false;
}

RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size) {
	// Disabling this for now
	/*RDebugMap *map = NULL;
	LPVOID base = NULL;
	HANDLE process = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (process == INVALID_HANDLE_VALUE) {
		return map;
	}
	base = VirtualAllocEx (process, (LPVOID)(size_t)addr,
	  			(SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	CloseHandle (process);
	if (!base) {
		eprintf ("Failed to allocate memory\n");
		return map;
	}
	r_debug_map_sync (dbg);
	map = r_debug_map_get (dbg, (ut64)(size_t)base);
	return map;*/
	return NULL;
}

int w32_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	// disabling this for now
	/*HANDLE process = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->tid);
	if (process == INVALID_HANDLE_VALUE) {
		return false;
	}
	int ret = true;
	if (!VirtualFreeEx (process, (LPVOID)(size_t)addr,
			  (SIZE_T)size, MEM_DECOMMIT)) {
		eprintf ("Failed to free memory\n");
		ret = false;
	}
	CloseHandle (process);
	return ret;*/
	return false;
}

static int io_perms_to_prot(int io_perms) {
	int prot_perms;

	if ((io_perms & R_PERM_RWX) == R_PERM_RWX) {
		prot_perms = PAGE_EXECUTE_READWRITE;
	} else if ((io_perms & (R_PERM_W | R_PERM_X)) == (R_PERM_W | R_PERM_X)) {
		prot_perms = PAGE_EXECUTE_READWRITE;
	} else if ((io_perms & (R_PERM_R | R_PERM_X)) == (R_PERM_R | R_PERM_X)) {
		prot_perms = PAGE_EXECUTE_READ;
	} else if ((io_perms & R_PERM_RW) == R_PERM_RW) {
		prot_perms = PAGE_READWRITE;
	} else if (io_perms & R_PERM_W) {
		prot_perms = PAGE_READWRITE;
	} else if (io_perms & R_PERM_X) {
		prot_perms = PAGE_EXECUTE;
	} else if (io_perms & R_PERM_R) {
		prot_perms = PAGE_READONLY;
	} else {
		prot_perms = PAGE_NOACCESS;
	}
	return prot_perms;
}

int w32_map_protect(RDebug *dbg, ut64 addr, int size, int perms) {
	// Disabling this for now
	/*DWORD old;
	BOOL ret = FALSE;
	HANDLE h_proc = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);

	if (h_proc) {
		ret = VirtualProtectEx (h_proc, (LPVOID)(size_t)addr,
			size, io_perms_to_prot (perms), &old);
		CloseHandle (h_proc);
	}
	return ret;*/
	return false;
}

RDebugInfo *w32_info(RDebug *dbg, const char *arg) {
	/*
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->lib = (void *) r_debug_get_lib_item();
	rdi->thread = (void *)r_debug_get_thread_item ();
	rdi->uid = -1;
	rdi->gid = -1;
	rdi->cwd = NULL;
	rdi->exe = NULL;
	rdi->cmdline = NULL;
	rdi->libname = NULL;
	w32_info_user (dbg, rdi);
	w32_info_exe (dbg, rdi);
	return rdi;*/
	return NULL;
}
