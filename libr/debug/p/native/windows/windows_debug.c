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
	return size;
}

int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
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
	RList *threads = r_list_new ();
	if (!threads) {
		CloseHandle (ph);
		return -1;
	}
	threads = w32_thread_list (dbg, pid, threads);
	if (threads->length == 0) {
		r_list_free (threads);
		CloseHandle (ph);
		return -1;
	}
	int tid = ((RDebugPid *)threads->head->data)->pid;
	r_list_free (threads);
	rio->ph = ph;
	rio->debug = true;
	return tid;
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
	// hack to support w32dbg:// and attach://
	if (g_dbg->pid != pid) {
		DEBUG_EVENT de;
		de.dwProcessId = pid;
		de.dwThreadId = tid;
		bool cont = true;
		do {
			if (!ContinueDebugEvent (de.dwProcessId, de.dwThreadId, DBG_CONTINUE)) {
				return false;
			}
			if (!WaitForDebugEvent (&de, 1000)) {
				return false;
			}
			switch (de.dwDebugEventCode) {
				//case CREATE_PROCESS_DEBUG_EVENT:
				//case CREATE_THREAD_DEBUG_EVENT:
				case LOAD_DLL_DEBUG_EVENT:
					{
						HANDLE hf = de.u.LoadDll.hFile;
						if (hf && hf != INVALID_HANDLE_VALUE) {
							CloseHandle (hf);
						}
					} break;
				case EXCEPTION_DEBUG_EVENT:
					cont = false;
					break;
				default:
					eprintf ("Unhandled debug event %d\n", de.dwDebugEventCode);
					break;
			}
		} while (cont);
	}
	rio->ph = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (rio->ph == (HANDLE)NULL) {
		return false;
	}
	rio->debug = true;
	return true;
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

void w32_break_process_wrapper(void *d) {
	w32_break_process (d);
}

void w32_break_process(RDebug *dbg) {
	RIOW32Dbg *rio = dbg->user;
	if (!DebugBreakProcess (rio->ph)) {
		r_sys_perror ("w32_break_process/DebugBreakProcess");
	}
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
	RIOW32Dbg *rio = dbg->user;
	LPVOID base = VirtualAllocEx (rio->ph, (LPVOID)(size_t)addr,
	  			(SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		eprintf ("Failed to allocate memory\n");
		return NULL;
	}
	r_debug_map_sync (dbg);
	return r_debug_map_get (dbg, (ut64)(size_t)base);
}

int w32_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	RIOW32Dbg *rio = dbg->user;
	bool ret = true;
	if (!VirtualFreeEx (rio->ph, (LPVOID)(size_t)addr,
			  (SIZE_T)size, MEM_DECOMMIT)) {
		eprintf ("Failed to free memory\n");
		ret = false;
	}
	return ret;
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
	DWORD old;
	RIOW32Dbg *rio = dbg->user;
	return VirtualProtectEx (rio->ph, (LPVOID)(size_t)addr,
		size, io_perms_to_prot (perms), &old);
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
	RDebugPid *ret = r_debug_pid_new (path, pid, uid, 's', 0);
	free (path);
	return ret;
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
