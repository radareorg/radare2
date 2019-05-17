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
	eprintf("w32_reg_read is disabled\n");
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
	eprintf("w32_reg_write is disabled\n");
	return false;
}

int w32_attach(RDebug *dbg, int pid) { // intrusive
	eprintf("w32_detach is disabled\n");
	return -1;
	/*int ret = -1;
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
	return ret;*/

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

int w32_detach(RDebug *dbg, int pid) {
	// disabled for now
	//return w32_DebugActiveProcessStop (pid)? 0 : -1;
	eprintf("w32_detach is disabled\n");
	return false;
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
	eprintf("w32_step is disabled\n");
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
	eprintf("w32_continue is disabled\n");
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
	eprintf("w32_map_alloc is disabled\n");
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
	eprintf("w32_map_dealloc is disabled\n");
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
	eprintf("w32_map_protect is disabled\n");
	return false;
}

/*
static void proc_mem_map(HANDLE h_proc, RList *map_list, MEMORY_BASIC_INFORMATION *mbi) {
	TCHAR f_name[MAX_PATH + 1];

	DWORD len = w32_GetMappedFileName (h_proc, mbi->BaseAddress, f_name, MAX_PATH);
	if (len > 0) {
		char *f_name_ = r_sys_conv_win_to_utf8 (f_name);
		add_map_reg (map_list, f_name_, mbi);
		free (f_name_);
	} else {
		add_map_reg (map_list, "", mbi);
	}
}
*/

RList *w32_dbg_maps(RDebug *dbg) {
	// disabled for now
	/*SYSTEM_INFO si = {0};
	LPVOID cur_addr;
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE h_proc;
	RWinModInfo mod_inf = {0};
	RList *map_list = r_list_new(), *mod_list = NULL;

	GetSystemInfo (&si);
	h_proc = w32_OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dbg->pid);
	if (!h_proc) {
		r_sys_perror ("w32_dbg_maps/w32_OpenProcess");
		goto err_w32_dbg_maps;
	}
	cur_addr = si.lpMinimumApplicationAddress;
	/* get process modules list * /
	mod_list = w32_dbg_modules (dbg);
	/* process memory map * /
	while (cur_addr < si.lpMaximumApplicationAddress &&
		VirtualQueryEx (h_proc, cur_addr, &mbi, sizeof (mbi)) != 0) {
		if (mbi.State != MEM_FREE) {
			switch (mbi.Type) {
			case MEM_IMAGE:
				proc_mem_img (h_proc, map_list, mod_list, &mod_inf, &si, &mbi);
				break;
			case MEM_MAPPED:
				proc_mem_map (h_proc, map_list, &mbi);
				break;
			default:
				add_map_reg (map_list, "", &mbi);
			}
		}
		cur_addr = (LPVOID)(size_t)((ut64)(size_t)mbi.BaseAddress + mbi.RegionSize);
	}
err_w32_dbg_maps:
	free (mod_inf.sect_hdr);
	r_list_free (mod_list);
	return map_list;*/
	eprintf("w32_dbg_maps is disabled\n");
	return NULL;
}

RList *w32_dbg_modules(RDebug *dbg) {
	// disabled for now
	/*MODULEENTRY32 me32;
	RDebugMap *mr;
	RList *list = r_list_new ();
	DWORD flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
	HANDLE h_mod_snap = w32_CreateToolhelp32Snapshot (flags, dbg->pid);

	if (!h_mod_snap) {
		r_sys_perror ("w32_dbg_modules/CreateToolhelp32Snapshot");
		goto err_w32_dbg_modules;
	}
	me32.dwSize = sizeof (MODULEENTRY32);
	if (!Module32First (h_mod_snap, &me32)) {
		goto err_w32_dbg_modules;
	}
	do {
		char *mod_name;
		ut64 baddr = (ut64)(size_t)me32.modBaseAddr;

		mod_name = r_sys_conv_win_to_utf8 (me32.szModule);
		mr = r_debug_map_new (mod_name, baddr, baddr + me32.modBaseSize, 0, 0);
		free (mod_name);
		if (mr) {
			mr->file = r_sys_conv_win_to_utf8 (me32.szExePath);
			if (mr->file) {
				r_list_append (list, mr);
			}
		}
	} while (Module32Next (h_mod_snap, &me32));
err_w32_dbg_modules:
	if (h_mod_snap) {
		CloseHandle (h_mod_snap);
	}
	return list;*/
	eprintf("w32_dbg_modules is disabled\n");
	return NULL;
}

RList *w32_thread_list(RDebug *dbg, int pid, RList *list) {
	// disabled for now
	/*
        HANDLE th;
        HANDLE thid;
        THREADENTRY32 te32;

        te32.dwSize = sizeof(THREADENTRY32);

	if (!w32_OpenThread) {
		eprintf("w32_thread_list: no w32_OpenThread?\n");
		return list;
	}
        th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if(th == INVALID_HANDLE_VALUE || !Thread32First (th, &te32))
                goto err_load_th;
        do {
                /* get all threads of process * /
                if (te32.th32OwnerProcessID == pid) {
			//te32.dwFlags);
                        /* open a new handler * /
			// XXX: fd leak?
#if 0
 75 typedef struct tagTHREADENTRY32 {
 76         DWORD dwSize;
 77         DWORD cntUsage;
 78         DWORD th32ThreadID;
 79         DWORD th32OwnerProcessID;
 80         LONG tpBasePri;
 81         LONG tpDeltaPri;
 82         DWORD dwFlags;
#endif
			thid = w32_OpenThread (THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (!thid) {
				r_sys_perror ("w32_thread_list/OpenThread");
                                goto err_load_th;
			}
			r_list_append (list, r_debug_pid_new ("???", te32.th32ThreadID, 0, 's', 0));
                }
        } while (Thread32Next (th, &te32));
err_load_th:
        if(th != INVALID_HANDLE_VALUE)
                CloseHandle (th);
	return list;*/
	eprintf("w32_thread_list is disabled\n");
	return NULL;
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
	eprintf("w32_info is disabled\n");
	return NULL;
}

RList *w32_pids(int pid, RList *list) {
	// disabled for now
	/*
	HANDLE process_snapshot;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof (PROCESSENTRY32);
	int show_all_pids = pid == 0;

	process_snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, pid);
	if (process_snapshot == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_pids/CreateToolhelp32Snapshot");
		return list;
	}
	if (!Process32First (process_snapshot, &pe)) {
		r_sys_perror ("w32_pids/Process32First");
		CloseHandle (process_snapshot);
		return list;
	}
	do {
		if (show_all_pids ||
			pe.th32ProcessID == pid ||
			pe.th32ParentProcessID == pid) {

			RDebugPid *debug_pid = build_debug_pid (&pe);
			if (debug_pid) {
				r_list_append (list, debug_pid);
			}
		}
	} while (Process32Next (process_snapshot, &pe));

	CloseHandle (process_snapshot);
	return list;*/
	eprintf("w32_pids is disabled\n");
	return NULL;
}
