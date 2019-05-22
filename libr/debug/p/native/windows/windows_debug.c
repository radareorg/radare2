/* radare - LGPL - Copyright 2019 - MapleLeaf-X */
#include <string.h>
#include "windows_debug.h"
#include <windows.h>
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName

typedef struct {
	// bool dbgpriv;
	HANDLE ph;
	bool debug;
	// int (*select)(int pid, int tid);
} RIOW32Dbg;

static RDebug *g_dbg = NULL;

bool setup_debug_privileges(bool b) {
	HANDLE tok;
	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
		return false;
	}
	bool ret = false;
	LUID luid;
	if (LookupPrivilegeValue (NULL, SE_DEBUG_NAME, &luid)) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = b ? SE_PRIVILEGE_ENABLED : 0;
		if (AdjustTokenPrivileges (tok, FALSE, &tp, 0, NULL, NULL)) {
			// TODO: handle ERROR_NOT_ALL_ASSIGNED
			ret = GetLastError () == ERROR_SUCCESS;
		}
	}
	CloseHandle (tok);
	return ret;
}

int w32_init(RDebug *dbg) {
	RIOW32Dbg *rio = dbg->user = R_NEW (RIOW32Dbg);
	if (!rio) {
		eprintf ("w32_init: failed to allocate memory\n");
		return false;
	}
	setup_debug_privileges (true);
	// rio->dbgpriv = setup_debug_privileges (true);
	rio->ph = (HANDLE)NULL;
	rio->debug = false;
	// rio->select = &w32_select;
	g_dbg = dbg;
	return true;
}

static int suspend_thread(HANDLE th, int bits) {
	bool ret;
	if (bits == 32) {
		if ((ret = SuspendThread (th)) == -1) {
			r_sys_perror ("suspend_thread/SuspendThread");
		}
	} else {
		if ((ret = Wow64SuspendThread (th)) == -1) {
			r_sys_perror ("suspend_thread/Wow64SuspendThread");
		}
	}
	return ret;
}

static int resume_thread(HANDLE th, int bits) {
	bool ret;
	if (bits == 32) {
		if ((ret = ResumeThread (th)) == -1) {
			r_sys_perror ("resume_thread/ResumeThread");
		}
	} else {
		if ((ret = ResumeThread (th)) == -1) {
			r_sys_perror ("resume_thread/Wow64ResumeThread");
		}
	}
	return ret;
}

static int set_thread_context(HANDLE th, const ut8 *buf, int size, int bits) {
	bool ret;
	if (bits == 32) {
		CONTEXT ctx = {0};
		if (size > sizeof (ctx)) {
			size = sizeof (ctx);
		}
		memcpy (&ctx, buf, size);
		if(!(ret = SetThreadContext (th, &ctx))) {
			r_sys_perror ("set_thread_context/SetThreadContext");
		}
	} else {
		WOW64_CONTEXT ctx = {0};
		if (size > sizeof (ctx)) {
			size = sizeof (ctx);
		}
		memcpy (&ctx, buf, size);
		if(!(ret = Wow64SetThreadContext (th, &ctx))) {
			r_sys_perror ("set_thread_context/Wow64SetThreadContext");
		}
	}
	return ret;
}

static int get_thread_context(HANDLE th, ut8 *buf, int size, int bits) {
	int ret = 0;
	if (bits == 32) {
		CONTEXT ctx = {0};
		// TODO: support various types?
		ctx.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext (th, &ctx)) {
			if (size > sizeof (ctx)) {
				size = sizeof (ctx);
			}
			memcpy (buf, &ctx, size);
			ret = size;
		} else {
			r_sys_perror ("get_thread_context/GetThreadContext");
		}
	} else {
		WOW64_CONTEXT ctx = {0};
		// TODO: support various types?
		ctx.ContextFlags = CONTEXT_ALL;
		if (Wow64GetThreadContext (th, &ctx)) {
			if (size > sizeof (ctx)) {
				size = sizeof (ctx);
			}
			memcpy (buf, &ctx, size);
			ret = size;
		} else {
			r_sys_perror ("get_thread_context/Wow64GetThreadContext");
		}
	}
	return ret;
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
	ctx.ContextFlags = CONTEXT_ALL;
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
	DWORD flags = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
	if (dbg->bits == 64) {
		flags |= THREAD_QUERY_INFORMATION;
	}
	HANDLE th = OpenThread (flags, FALSE, dbg->tid);
	if (th == (HANDLE)NULL) {
		r_sys_perror ("w32_reg_read/OpenThread");
		return 0;
	}
	// Always suspend
	if (suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return 0;
	}
	size = get_thread_context (th, buf, size, dbg->bits);
	// Always resume
	if (resume_thread (th, dbg->bits) == -1) {
		size = 0;
	}
	CloseHandle (th);
	//eprintf ("w32_reg_read is not implemented!\n");
	return size;
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
	DWORD flags = THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;
	if (dbg->bits == 64) {
		flags |= THREAD_QUERY_INFORMATION;
	}
	HANDLE th = OpenThread (flags, FALSE, dbg->tid);
	if (th == (HANDLE)NULL) {
		r_sys_perror ("w32_reg_write/OpenThread");
		return false;
	}
	// Always suspend
	if (suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return false;
	}
	bool ret = set_thread_context (th, buf, size, dbg->bits);
	// Always resume
	if (resume_thread (th, dbg->bits) == -1) {
		ret = false;
	}
	CloseHandle (th);
	return ret;
}

int w32_attach(RDebug *dbg, int pid) {
	RIOW32Dbg *rio = dbg->user;
	HANDLE ph = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (ph == (HANDLE)NULL) {
		return -1;
	}
	if (!DebugActiveProcess (pid)) {
		CloseHandle (ph);
		return -1;
	}
	rio->ph = ph;
	rio->debug = true;
	return 0;
	// rio->ph = ph;
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
	if (pid == -1) {
		return false;
	}
	if (dbg->pid == pid) {
		RIOW32Dbg *rio = dbg->user;
		bool ret;
		if (rio->debug) {
			ret = DebugActiveProcessStop (pid);
		}
		CloseHandle (rio->ph);
		rio->ph = NULL;
		rio->debug = false;
		return ret;
	}
	return false;
}

int w32_select(int pid, int tid) {
	RIOW32Dbg *rio = g_dbg->user;
	if (rio->ph != (HANDLE)NULL) {
		return true;
	}
	/*rio->ph = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (rio->ph == (HANDLE)NULL) {
		return false;
	}
	rio->debug = false;*/
	eprintf ("w32_select is not implemented!\n");
	return false;
}

int w32_kill(RDebug *dbg, int pid, int tid, int sig) {
	if (sig == 0) {
		return true;
	}
	RIOW32Dbg *rio = dbg->user;
	if (rio->debug) {
		DebugActiveProcessStop (pid);
	}
	bool ret = false;
	if (TerminateProcess (rio->ph, 1)) {
		if (WaitForSingleObject (rio->ph, 1000) != WAIT_OBJECT_0) {
			r_sys_perror ("w32_kill/WaitForSingleObject");
		} else {
			ret = true;
		}
	}
	CloseHandle (rio->ph);
	rio->ph = NULL;
	return ret;
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
	eprintf ("w32_step is not implemented!\n");
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
	eprintf ("w32_continue is not implemented!\n");
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
	eprintf ("w32_map_alloc is not implemented!\n");
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
	eprintf ("w32_map_dealloc is not implemented!\n");
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
	eprintf ("w32_map_protect is not implemented!\n");
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
	eprintf ("w32_dbg_maps is not implemented!\n");
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
	eprintf ("w32_dbg_modules is not implemented!\n");
	return NULL;
}

static const char *resolve_path(HANDLE ph) {
	// TODO: add maximum path length support
	const DWORD maxlength = MAX_PATH;
	TCHAR filename[MAX_PATH];
	DWORD length = GetModuleFileNameEx (ph, NULL, filename, maxlength);
	if (length > 0) {
		return r_sys_conv_win_to_utf8 (filename);
	}
	// Upon failure fallback to GetProcessImageFileName
	length = GetProcessImageFileName (ph, filename, maxlength);
	if (length == 0) {
		return NULL;
	}
	// Convert NT path to win32 path
	char *tmp = strchr (filename + 1, '\\');
	if (!tmp) {
		return NULL;
	}
	tmp = strchr (tmp + 1, '\\');
	if (!tmp) {
		return NULL;
	}
	length = tmp - filename;
	TCHAR device[MAX_PATH];
	const char *ret = NULL;
	for (TCHAR drv[] = TEXT("A:"); drv[0] <= TEXT('Z'); drv[0]++) {
		if (QueryDosDevice (drv, device, maxlength) > 0) {
			if (!strncmp (filename, device, length)) {
				TCHAR path[MAX_PATH];
				snprintf (path, maxlength, "%s%s", drv, &tmp[1]);
				ret = r_sys_conv_win_to_utf8 (path);
				break;
			}
		}
	}
	return ret;
}

RList *w32_thread_list(RDebug *dbg, int pid, RList *list) {
	// pid is not respected for TH32CS_SNAPTHREAD flag
	HANDLE th = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
	if(th == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_thread_list/CreateToolhelp32Snapshot");
		return list;
	}
	THREADENTRY32 te;
	te.dwSize = sizeof (te);
	if (Thread32First (th, &te)) {
		// TODO: export this code to its own function?
		HANDLE ph = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		char *path = NULL;
		int uid = -1;
		if (ph != (HANDLE)NULL) {
			path = resolve_path (ph);
			DWORD sid;
			if (ProcessIdToSessionId (pid, &sid)) {
				uid = sid;
			}
			CloseHandle (ph);
		}
		if (!path) {
			// TODO: enum processes to get binary's name
			path = strdup ("???");
		}
		do {
			if (te.th32OwnerProcessID == pid) {
				// TODO: add pc if process is debugged
				/*ut64 pc;
				if (dbg->pid == pid) {
					CONTEXT ctx = {0};
					w32_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&ctx, sizeof (ctx));
					pc = ctx->eip;
				}*/
				r_list_append (list, r_debug_pid_new (path, te.th32ThreadID, uid, 's', 0));
			}
		} while (Thread32Next (th, &te));
		free (path);
	} else {
		r_sys_perror ("w32_thread_list/Thread32First");
	}
	CloseHandle (th);
	return list;
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
	eprintf ("w32_info is not implemented!\n");
	return NULL;
}

static RDebugPid *build_debug_pid(int pid, HANDLE ph, const char* name) {
	char *path = NULL;
	int uid = -1;
	if (ph == (HANDLE)NULL) {
		ph = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (ph != (HANDLE)NULL) {
			path = resolve_path (ph);
			DWORD sid;
			if (ProcessIdToSessionId (pid, &sid)) {
				uid = sid;
			}
			CloseHandle (ph);
		} else {
			return NULL;
		}
	} else {
		path = resolve_path (ph);
		DWORD sid;
		if (ProcessIdToSessionId (pid, &sid)) {
			uid = sid;
		}
	}
	if (!path) {
		path = r_sys_conv_win_to_utf8 (name);
	}
	// it is possible to get pc for a non debugged process but the operation is expensive and might be risky
	return r_debug_pid_new (path, pid, uid, 's', 0);
}

RList *w32_pid_list(RDebug *dbg, int pid, RList *list) {
	HANDLE sh = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, pid);
	if (sh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_pid_list/CreateToolhelp32Snapshot");
		return list;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof (pe);
	if (Process32First (sh, &pe)) {
		RIOW32Dbg *rio = dbg->user;
		bool all = pid == 0, b = false;
		do {
			if (all || pe.th32ProcessID == pid || (b = pe.th32ParentProcessID == pid)) {
				// Returns NULL if process is inaccessible unless if its a child process of debugged process
				RDebugPid *dbg_pid = build_debug_pid (pe.th32ProcessID, b ? rio->ph : NULL, pe.szExeFile);
				if (dbg_pid) {
					r_list_append (list, dbg_pid);
				}/* else {
					eprintf ("w32_pid_list: failed to process pid %d\n", pe.th32ProcessID);
				}*/
			}
		} while (Process32Next (sh, &pe));
	} else {
		r_sys_perror ("w32_pid_list/Process32First");
	}
	CloseHandle (sh);
	return list;
}
