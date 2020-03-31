/* radare - LGPL - Copyright 2019 - MapleLeaf-X */
#include <string.h>
#include "windows_debug.h"
#include <w32dbg_wrap.h>

const DWORD wait_time = 1000;

#define w32_PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
#define w32_THREAD_ALL_ACCESS w32_PROCESS_ALL_ACCESS
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
	RIOW32Dbg *rio = dbg->user;
	if (!rio) {
		rio = R_NEW0 (RIOW32Dbg);
		if (rio) {
			rio->pi.dwProcessId = dbg->pid;
			rio->pi.dwThreadId = dbg->tid;
		} else {
			return false;
		}
		dbg->user = rio;
	}
	if (!rio->inst) {
		if (dbg->iob.io->w32dbg_wrap) {
			rio->inst = dbg->iob.io->w32dbg_wrap;
		} else {
			rio->inst = dbg->iob.io->w32dbg_wrap = w32dbg_wrap_new ();
		}
	}
	// escalate privs (required for win7/vista)
	setup_debug_privileges (true);

	HMODULE lib = GetModuleHandle (TEXT ("kernel32")); //Always loaded
	if (!lib) {
		return false;
	}
	// lookup function pointers for portability
	w32_DebugActiveProcessStop = (BOOL (WINAPI *) (DWORD))
		GetProcAddress (lib, "DebugActiveProcessStop");

	w32_OpenThread = (HANDLE (WINAPI *) (DWORD, BOOL, DWORD))
		GetProcAddress (lib, "OpenThread");

	w32_OpenProcess = (HANDLE (WINAPI *) (DWORD, BOOL, DWORD))
		GetProcAddress (lib, "OpenProcess");

	w32_DebugBreakProcess = (BOOL (WINAPI *) (HANDLE))
		GetProcAddress (lib, "DebugBreakProcess");

	w32_CreateToolhelp32Snapshot = (HANDLE (WINAPI *) (DWORD, DWORD))
		GetProcAddress (lib, "CreateToolhelp32Snapshot");

	// only windows vista :(
	w32_GetThreadId = (DWORD (WINAPI *) (HANDLE))
		GetProcAddress (lib, "GetThreadId");

	// from xp1
	w32_GetProcessId = (DWORD (WINAPI *) (HANDLE))
		GetProcAddress (lib, "GetProcessId");

	w32_QueryFullProcessImageName = (BOOL (WINAPI *) (HANDLE, DWORD, LPTSTR, PDWORD))
		GetProcAddress (lib, W32_TCALL ("QueryFullProcessImageName"));

	// api to retrieve YMM from w7 sp1
	w32_GetEnabledXStateFeatures = (ut64 (WINAPI *) ())
		GetProcAddress (lib, "GetEnabledXStateFeatures");

	w32_InitializeContext = (BOOL (WINAPI *) (PVOID, DWORD, PCONTEXT *, PDWORD))
		GetProcAddress (lib, "InitializeContext");

	w32_GetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, PDWORD64))
		GetProcAddress (lib, "GetXStateFeaturesMask");

	w32_LocateXStateFeature = (PVOID (WINAPI *) (PCONTEXT Context, DWORD, PDWORD))
		GetProcAddress (lib, "LocateXStateFeature");

	w32_SetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, DWORD64))
		GetProcAddress (lib, "SetXStateFeaturesMask");

	lib = LoadLibrary (TEXT ("psapi.dll"));
	if (!lib) {
		eprintf ("Cannot load psapi.dll. Aborting\n");
		return false;
	}
	w32_GetMappedFileName = (DWORD (WINAPI *) (HANDLE, LPVOID, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetMappedFileName"));

	w32_GetModuleBaseName = (DWORD (WINAPI *) (HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetModuleBaseName"));

	w32_GetModuleInformation = (BOOL (WINAPI *) (HANDLE, HMODULE, LPMODULEINFO, DWORD))
		GetProcAddress (lib, "GetModuleInformation");

	w32_GetModuleFileNameEx = (DWORD (WINAPI *) (HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetModuleFileNameEx"));

	lib = LoadLibrary (TEXT ("ntdll.dll"));
	if (!lib) {
		eprintf ("Cannot load ntdll.dll. Aborting\n");
		return false;
	}
	w32_NtQuerySystemInformation = (NTSTATUS (WINAPI *) (ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQuerySystemInformation");

	w32_NtDuplicateObject = (NTSTATUS (WINAPI *) (HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG))
		GetProcAddress (lib, "NtDuplicateObject");

	w32_NtQueryObject = (NTSTATUS (WINAPI *) (HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQueryObject");

	w32_NtQueryInformationThread = (NTSTATUS (WINAPI *) (HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQueryInformationThread");

	if (!w32_DebugActiveProcessStop || !w32_OpenThread || !w32_DebugBreakProcess ||
		!w32_GetModuleBaseName || !w32_GetModuleInformation) {
		// OOPS!
		eprintf ("debug_init_calls:\n"
			 "DebugActiveProcessStop: 0x%p\n"
			 "OpenThread: 0x%p\n"
			 "DebugBreakProcess: 0x%p\n"
			 "GetThreadId: 0x%p\n",
			w32_DebugActiveProcessStop, w32_OpenThread, w32_DebugBreakProcess, w32_GetThreadId);
		return false;
	}

	// rio->dbgpriv = setup_debug_privileges (true);
	return true;
}


static int __w32_findthread_cmp(int *tid, PTHREAD_ITEM th) {
	return (int)!(*tid == th->tid);
}

static inline PTHREAD_ITEM __find_thread(RDebug *dbg, int tid) {
	RListIter *it = r_list_find (dbg->threads, &tid, (RListComparator)__w32_findthread_cmp);
	return it ? it->data : NULL;
}

static PTHREAD_ITEM __r_debug_thread_add(RDebug *dbg, DWORD pid, DWORD tid, HANDLE hThread, LPVOID lpThreadLocalBase, LPVOID lpStartAddress, BOOL bFinished) {
	r_return_val_if_fail (dbg, NULL);
	if (!dbg->threads) {
		dbg->threads = r_list_newf (free);
	}
	if (!lpStartAddress) {
		w32_NtQueryInformationThread (hThread, 9, &lpStartAddress, sizeof (LPVOID), NULL);
	}
	THREAD_ITEM th = {
			pid,
			tid,
			bFinished,
			false,
			hThread,
			lpThreadLocalBase,
			lpStartAddress
	};
	PTHREAD_ITEM pthread = __find_thread (dbg, tid);
	if (pthread) {
		*pthread = th;
		return NULL;
	}
	pthread = R_NEW0 (THREAD_ITEM);
	if (!pthread) {
		R_LOG_ERROR ("__r_debug_thread_add: Memory allocation failed.\n");
		return NULL;
	}
	*pthread = th;
	r_list_append (dbg->threads, pthread);
	return pthread;
}

static int __suspend_thread(HANDLE th, int bits) {
	int ret;
	//if (bits == R_SYS_BITS_32) {
		if ((ret = SuspendThread (th)) == -1) {
			r_sys_perror ("__suspend_thread/SuspendThread");
		}
	/*} else {
		if ((ret = Wow64SuspendThread (th)) == -1) {
			r_sys_perror ("__suspend_thread/Wow64SuspendThread");
		}
	}*/
	return ret;
}

static int __resume_thread(HANDLE th, int bits) {
	int ret;
	//if (bits == R_SYS_BITS_32) {
		if ((ret = ResumeThread (th)) == -1) {
			r_sys_perror ("__resume_thread/ResumeThread");
		}
	/*} else {
		if ((ret = ResumeThread (th)) == -1) {
			r_sys_perror ("__resume_thread/Wow64ResumeThread");
		}
	}*/
	return ret;
}

static inline void __continue_thread(HANDLE th, int bits) {
	int ret;
	do {
		ret = __resume_thread (th, bits);
	} while (ret > 0);
}

static bool __is_thread_alive(RDebug *dbg, int tid) {
	PTHREAD_ITEM th = __find_thread (dbg, tid);
	if (!th) {
		return false;
	}
	if (!th->bFinished) {
		if (SuspendThread (th->hThread) != -1) {
			ResumeThread (th->hThread);
			return true;
		}
	}
	th->bFinished = true;
	return false;
}

static bool __is_proc_alive(HANDLE ph) {
	if (ph) {
		DWORD code;
		if (!GetExitCodeProcess (ph, &code)) {
			GetExitCodeThread (ph, &code);
		}
		return code == STILL_ACTIVE;
	}
	return false;
}

static int __set_thread_context(HANDLE th, const ut8 *buf, int size, int bits) {
	bool ret;
	CONTEXT ctx = {0};
	size = R_MIN (size, sizeof (ctx));
	memcpy (&ctx, buf, size);
	if(!(ret = SetThreadContext (th, &ctx))) {
		r_sys_perror ("__set_thread_context/SetThreadContext");
	}
	return ret;
}

static int __get_thread_context(HANDLE th, ut8 *buf, int size, int bits) {
	int ret = 0;
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
		if (__is_proc_alive (th)) {
			r_sys_perror ("__get_thread_context/GetThreadContext");
		}
	}
	return ret;
}

static int __get_avx(HANDLE th, ut128 xmm[16], ut128 ymm[16]) {
	int nregs = 0, index = 0;
	DWORD ctxsize = 0;
	DWORD featurelen = 0;
	ut64 featuremask = 0;
	ut128 *newxmm = NULL;
	ut128 *newymm = NULL;
	void *buffer = NULL;
	PCONTEXT ctx;
	if (!w32_GetEnabledXStateFeatures) {
		return 0;
	}
	// Check for AVX extension
	featuremask = w32_GetEnabledXStateFeatures ();
	if ((featuremask & XSTATE_MASK_AVX) == 0) {
		return 0;
	}
	if ((w32_InitializeContext (NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &ctxsize)) || (GetLastError () != ERROR_INSUFFICIENT_BUFFER)) {
		return 0;
	}
	buffer = malloc (ctxsize);
	if (!buffer) {
		return 0;
	}
	if (!w32_InitializeContext (buffer, CONTEXT_ALL | CONTEXT_XSTATE, &ctx, &ctxsize)) {
		goto err_get_avx;
	}
	if (!w32_SetXStateFeaturesMask (ctx, XSTATE_MASK_AVX)) {
		goto err_get_avx;
	}
	// TODO: Use __get_thread_context
	if (!GetThreadContext (th, ctx)) {
		goto err_get_avx;
	}
	if (w32_GetXStateFeaturesMask (ctx, &featuremask)) {
		goto err_get_avx;
	}
	newxmm = (ut128 *)w32_LocateXStateFeature (ctx, XSTATE_LEGACY_SSE, &featurelen);
		nregs = featurelen / sizeof(*newxmm);
	for (index = 0; index < nregs; index++) {
		ymm[index].High = 0;
		xmm[index].High = 0;
		ymm[index].Low = 0;
		xmm[index].Low = 0;
	}
	if (newxmm != NULL) {
		for (index = 0; index < nregs; index++) {
			xmm[index].High = newxmm[index].High;
			xmm[index].Low = newxmm[index].Low;
		}
	}
	if ((featuremask & XSTATE_MASK_AVX) != 0) {
		// check for AVX initialization and get the pointer.
		newymm = (ut128 *)w32_LocateXStateFeature (ctx, XSTATE_AVX, NULL);
		if (!newymm) {
			goto err_get_avx;
		}
		for (index = 0; index < nregs; index++) {
			ymm[index].High = newymm[index].High;
			ymm[index].Low = newymm[index].Low;
		}
	}
err_get_avx:
	free (buffer);
	return nregs;
}

static void __printwincontext(HANDLE th, CONTEXT *ctx) {
	ut128 xmm[16];
	ut128 ymm[16];
	ut80 st[8];
	ut64 mm[8];
	ut16 top = 0;
	int x, nxmm = 0, nymm = 0;
#if _WIN64
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", ctx->FltSave.ControlWord, ctx->FltSave.StatusWord);
	eprintf ("MxCsr         = %08lx TagWord      = %08x\n", ctx->MxCsr, ctx->FltSave.TagWord);
	eprintf ("ErrorOffset   = %08lx DataOffset   = %08lx\n", ctx->FltSave.ErrorOffset, ctx->FltSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", ctx->FltSave.ErrorSelector, ctx->FltSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].Low = ctx->FltSave.FloatRegisters[x].Low;
		st[x].High = (ut16)ctx->FltSave.FloatRegisters[x].High;
	}
	top = (ctx->FltSave.StatusWord & 0x3fff) >> 11;
	for (x = 0; x < 8; x++) {
		mm[top] = ctx->FltSave.FloatRegisters[x].Low;
		top++;
		if (top > 7) {
			top = 0;
		}
	}
	for (x = 0; x < 16; x++) {
		xmm[x].High = ctx->FltSave.XmmRegisters[x].High;
		xmm[x].Low = ctx->FltSave.XmmRegisters[x].Low;
	}
	nxmm = 16;
#else
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", (ut32)ctx->FloatSave.ControlWord, (ut32)ctx->FloatSave.StatusWord);
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", *(ut32 *)&ctx->ExtendedRegisters[24], (ut32)ctx->FloatSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", (ut32)ctx->FloatSave.ErrorOffset, (ut32)ctx->FloatSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", (ut32)ctx->FloatSave.ErrorSelector, (ut32)ctx->FloatSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].High = (ut16) *((ut16 *)(&ctx->FloatSave.RegisterArea[x * 10] + 8));
		st[x].Low = (ut64) *((ut64 *)&ctx->FloatSave.RegisterArea[x * 10]);
	}
	top = (ctx->FloatSave.StatusWord & 0x3fff) >> 11;
	for (x = 0; x < 8; x++) {
		mm[top] = *((ut64 *)&ctx->FloatSave.RegisterArea[x * 10]);
		top++;
		if (top>7) {
			top = 0;
		}
	}
	for (x = 0; x < 8; x++) {
		xmm[x] = *((ut128 *)&ctx->ExtendedRegisters[(10 + x) * 16]);
	}
	nxmm = 8;
#endif
	// show fpu,mm,xmm regs
	for (x = 0; x < 8; x++) {
		// the conversin from long double to double only work for compilers
		// with long double size >=10 bytes (also we lost 2 bytes of precision)
		//   in mingw long double is 12 bytes size
		//   in msvc long double is alias for double = 8 bytes size
		//   in gcc long double is 10 bytes (correct representation)
		eprintf ("ST%i %04x %016"PFMT64x" (%f)\n", x, st[x].High, st[x].Low, (double)(*((long double *)&st[x])));
	}
	for (x = 0; x < 8; x++) {
		eprintf ("MM%i %016"PFMT64x"\n", x, mm[x]);
	}
	for (x = 0; x < nxmm; x++) {
		eprintf ("XMM%i %016"PFMT64x" %016"PFMT64x"\n", x, xmm[x].High, xmm[x].Low);
	}
	// show Ymm regs
	nymm = __get_avx (th, xmm, ymm);
	if (nymm) {
		for (x = 0; x < nymm; x++) {
			eprintf ("Ymm%d: %016"PFMT64x" %016"PFMT64x" %016"PFMT64x" %016"PFMT64x"\n", x, ymm[x].High, ymm[x].Low, xmm[x].High, xmm[x].Low );
		}
	}
}

int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	bool showfpu = false;
	if (type < -1) {
		showfpu = true; // hack for debugging
		type = -type;
	}
	RIOW32Dbg *rio = dbg->user;

	bool alive = __is_thread_alive (dbg, dbg->tid);
	HANDLE th = rio->pi.dwThreadId == dbg->tid ? rio->pi.hThread : NULL;
	if (!th || th == INVALID_HANDLE_VALUE) {
		DWORD flags = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
		if (dbg->bits == R_SYS_BITS_64) {
				flags |= THREAD_QUERY_INFORMATION;
		}
		th = w32_OpenThread (flags, FALSE, dbg->tid);
		if (!th && alive) {
			r_sys_perror ("w32_reg_read/OpenThread");
		}
		if (!th) {
			return 0;
		}
	}
	// Always suspend
	if (alive && __suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return 0;
	}
	size = __get_thread_context (th, buf, size, dbg->bits);
	if (showfpu) {
		__printwincontext (th, (CONTEXT *)buf);
	}
	// Always resume
	if (alive && __resume_thread (th, dbg->bits) == -1) {
		size = 0;
	}
	if (th != rio->pi.hThread) {
		CloseHandle (th);
	}
	return size;
}

static void __transfer_drx(RDebug *dbg, const ut8 *buf) {
	CONTEXT cur_ctx;
	if (w32_reg_read (dbg, R_REG_TYPE_ALL, (ut8 *)&cur_ctx, sizeof (CONTEXT))) {
		CONTEXT *new_ctx = (CONTEXT *)buf;
		size_t drx_size = offsetof (CONTEXT, Dr7) - offsetof (CONTEXT, Dr0) + sizeof (new_ctx->Dr7);
		memcpy (&cur_ctx.Dr0, &new_ctx->Dr0, drx_size);
		*new_ctx = cur_ctx;
	}
}

int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	DWORD flags = THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;
	if (dbg->bits == R_SYS_BITS_64) {
		flags |= THREAD_QUERY_INFORMATION;
	}
	HANDLE th = w32_OpenThread (flags, FALSE, dbg->tid);
	if (!th) {
		r_sys_perror ("w32_reg_write/OpenThread");
		return false;
	}
	bool alive = __is_thread_alive (dbg, dbg->tid);
	// Always suspend
	if (alive && __suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return false;
	}
	if (type == R_REG_TYPE_DRX) {
		__transfer_drx (dbg, buf);
	}
	bool ret = __set_thread_context (th, buf, size, dbg->bits);
	// Always resume
	if (alive && __resume_thread (th, dbg->bits) == -1) {
		ret = false;
	}
	CloseHandle (th);
	return ret;
}

int w32_attach(RDebug *dbg, int pid) {
	RIOW32Dbg *rio = dbg->user;
	if (rio->pi.hProcess) {
		return rio->pi.dwThreadId;
	}
	HANDLE ph = w32_OpenProcess (w32_PROCESS_ALL_ACCESS, FALSE, pid);
	if (!ph) {
		return -1;
	}
	rio->inst->params->type = W32_ATTACH;
	rio->inst->params->pid = pid;
	w32dbg_wrap_wait_ret (rio->inst);
	if (!rio->inst->params->ret) {
		w32dbgw_err (rio->inst);
		r_sys_perror ("DebugActiveProcess");
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
	rio->pi.hProcess = ph;
	w32_dbg_wait (dbg, pid);

	return tid;
}

int w32_detach(RDebug *dbg, int pid) {
	if (pid == -1 || dbg->pid != pid) {
		return false;
	}
	RIOW32Dbg *rio = dbg->user;
	bool ret = false;
	if (rio->pi.hProcess) {
		rio->inst->params->type = W32_DETTACH;
		rio->inst->params->pid = pid;
		w32dbg_wrap_wait_ret (rio->inst);
		ret = rio->inst->params->ret;
	}
	if (rio->pi.hProcess) {
		CloseHandle (rio->pi.hProcess);
		rio->pi.hProcess = NULL;
	}
	return ret;
}

static char *__get_file_name_from_handle(HANDLE handle_file) {
	HANDLE handle_file_map = NULL;
	LPTSTR filename = NULL;
	DWORD file_size_high = 0;
	LPVOID map = NULL;
	DWORD file_size_low = GetFileSize (handle_file, &file_size_high);

	if (file_size_low == 0 && file_size_high == 0) {
		return NULL;
	}
	handle_file_map = CreateFileMapping (handle_file, NULL, PAGE_READONLY, 0, 1, NULL);
	if (!handle_file_map) {
		goto err_get_file_name_from_handle;
	}
	filename = malloc ((MAX_PATH + 1) * sizeof (TCHAR));
	if (!filename) {
		goto err_get_file_name_from_handle;
	}
	/* Create a file mapping to get the file name. */
	map = MapViewOfFile (handle_file_map, FILE_MAP_READ, 0, 0, 1);
	if (!map || !GetMappedFileName (GetCurrentProcess (), map, filename, MAX_PATH)) {
		R_FREE (filename);
		goto err_get_file_name_from_handle;
	}
	TCHAR temp_buffer[512];
	/* Translate path with device name to drive letters. */
	if (!GetLogicalDriveStrings (_countof (temp_buffer) - 1, temp_buffer)) {
		goto err_get_file_name_from_handle;
	}
	TCHAR name[MAX_PATH];
	TCHAR drive[3] = TEXT (" :");
	LPTSTR cur_drive = temp_buffer;
	while (*cur_drive) {
		/* Look up each device name */
		*drive = *cur_drive;
		if (QueryDosDevice (drive, name, MAX_PATH)) {
			size_t name_length = _tcslen (name);

			if (name_length < MAX_PATH) {
				if (_tcsnicmp (filename, name, name_length) == 0
					&& *(filename + name_length) == TEXT ('\\')) {
					TCHAR temp_filename[MAX_PATH];
					_sntprintf_s (temp_filename, MAX_PATH, _TRUNCATE, TEXT ("%s%s"),
						drive, filename + name_length);
					_tcsncpy (filename, temp_filename,
						_tcslen (temp_filename) + 1);
					filename[MAX_PATH] = (TCHAR)'\0';
					break;
				}
			}
		}
		cur_drive++;
	} 
err_get_file_name_from_handle:
	if (map) {
		UnmapViewOfFile (map);
	}
	if (handle_file_map) {
		CloseHandle (handle_file_map);
	}
	if (filename) {
		char *ret = r_sys_conv_win_to_utf8 (filename);
		free (filename);
		return ret;
	}	
	return NULL;
}

static char *__resolve_path(HANDLE ph, HANDLE mh) {
	// TODO: add maximum path length support
	const DWORD maxlength = MAX_PATH;
	TCHAR filename[MAX_PATH];
	DWORD length = GetModuleFileNameEx (ph, mh, filename, maxlength);
	if (length > 0) {
		return r_sys_conv_win_to_utf8 (filename);
	}
	char *name = __get_file_name_from_handle (mh);
	if (name) {
		return name;
	}
	// Upon failure fallback to GetProcessImageFileName
	length = GetProcessImageFileName (mh, filename, maxlength);
	if (length == 0) {
		return NULL;
	}
	// Convert NT path to win32 path
	TCHAR *tmp = _tcschr (filename + 1, '\\');
	if (!tmp) {
		return NULL;
	}
	tmp = _tcschr (tmp + 1, '\\');
	if (!tmp) {
		return NULL;
	}
	length = tmp - filename;
	TCHAR device[MAX_PATH];
	char *ret = NULL;
	for (TCHAR drv[] = TEXT("A:"); drv[0] <= TEXT ('Z'); drv[0]++) {
		if (QueryDosDevice (drv, device, maxlength) > 0) {
			if (!_tcsncmp (filename, device, length)) {
				TCHAR path[MAX_PATH];
				_sntprintf (path, maxlength, TEXT ("%s%s"), drv, tmp);
				ret = r_sys_conv_win_to_utf8 (path);
				break;
			}
		}
	}
	return ret;
}

LPVOID lstLib = 0;
PLIB_ITEM lstLibPtr = 0;
static void *__r_debug_findlib(void *BaseOfDll) {
	PLIB_ITEM libPtr = NULL;
	if (lstLib) {
		libPtr = (PLIB_ITEM)lstLib;
		while (libPtr->hFile != NULL) {
			if (libPtr->hFile != INVALID_HANDLE_VALUE)
				if (libPtr->BaseOfDll == BaseOfDll)
					return ((void*)libPtr);
			libPtr = (PLIB_ITEM)((ULONG_PTR)libPtr + sizeof (LIB_ITEM));
		}
	}
	return NULL;
}

#define PLIB_MAX 512

static void __r_debug_lstLibAdd(DWORD pid, LPVOID lpBaseOfDll, HANDLE hFile, char *dllname) {
	if (lstLib == 0) {
		lstLib = VirtualAlloc (0, PLIB_MAX * sizeof (LIB_ITEM), MEM_COMMIT, PAGE_READWRITE);
	}
	lstLibPtr = (PLIB_ITEM)lstLib;
	if (!lstLibPtr) {
		R_LOG_ERROR ("Failed to allocate memory");
		return;
	}
	for (int x = 0; x < PLIB_MAX; x++) {
		if (lstLibPtr->hFile == hFile) {
			return;
		}
		if (!lstLibPtr->hFile) {
			lstLibPtr->pid = pid;
			lstLibPtr->hFile = hFile; //DBGEvent->u.LoadDll.hFile;
			lstLibPtr->BaseOfDll = lpBaseOfDll;//DBGEvent->u.LoadDll.lpBaseOfDll;
			strncpy (lstLibPtr->Path, dllname, MAX_PATH - 1);
			int i = strlen (dllname);
			int n = i;
			while (dllname[i] != '\\' && i >= 0) {
				i--;
			}
			strncpy (lstLibPtr->Name, dllname + i + 1, (size_t)n - i);
			return;
		}
		lstLibPtr++;
	}
	eprintf ("__r_debug_lstLibAdd: Cannot find slot\n");
}

static bool breaked = false;

int w32_attach_new_process(RDebug* dbg, int pid) {
	int tid = -1;

	if (!w32_detach(dbg, dbg->pid)) {
		eprintf ("Failed to detach from (%d)\n", dbg->pid);
		return -1;
	}

	if ((tid = w32_attach(dbg, pid)) < 0) {
		eprintf ("Failed to attach to (%d)\n", pid);
		return -1;
	}

	dbg->tid = tid;
	dbg->pid = pid;
	// Call select to sync the new pid's data
	r_debug_select(dbg, pid, tid);
	return dbg->tid;
}

int w32_select(RDebug* dbg, int pid, int tid) {
	RListIter *it;
	RIOW32Dbg *rio = dbg->user;

	// Re-attach to a different pid
	if (dbg->pid > -1 && dbg->pid != pid) {
		return w32_attach_new_process (dbg, pid);
	}

	if (!dbg->threads) {
		dbg->threads = r_list_newf (free);
	}

	PTHREAD_ITEM th = __find_thread (dbg, tid);

	if (tid && dbg->threads && !th) {
		th = __r_debug_thread_add (dbg, pid, tid, w32_OpenThread (w32_THREAD_ALL_ACCESS, FALSE, tid), 0, 0, FALSE);
	}

	int selected = 0;
	if (th && __is_thread_alive (dbg, th->tid)) {
		rio->pi.hThread = th->hThread;
		__continue_thread (th->hThread, dbg->bits);
		th->bSuspended = false;
		selected = tid;
	} else if (tid) {
		// If thread is dead, search for another one
		r_list_foreach (dbg->threads, it, th) {
			if (!__is_thread_alive (dbg, th->tid)) {
				continue;
			}
			__continue_thread (th->hThread, dbg->bits);
			rio->pi.hThread = th->hThread;
			th->bSuspended = false;
			selected = th->tid;
			break;
		}	
	}

	if (dbg->corebind.cfggeti (dbg->corebind.core, "dbg.threads")) {
		// Suspend all other threads
		r_list_foreach (dbg->threads, it, th) {
			if (!th->bFinished && !th->bSuspended && th->tid != selected) {
				__suspend_thread (th->hThread, dbg->bits);
				th->bSuspended = true;
			}
		}
	}

	return selected;
}

int w32_kill(RDebug *dbg, int pid, int tid, int sig) {
	RIOW32Dbg *rio = dbg->user;

	if (sig == 0) {
		if (!__is_proc_alive (rio->pi.hProcess)) {
			r_list_purge (dbg->threads);
			return false;
		}
		return true;
	}
	
	rio->inst->params->type = W32_DETTACH;
	rio->inst->params->pid = pid;
	w32dbg_wrap_wait_ret (rio->inst);
	
	bool ret = false;
	if (TerminateProcess (rio->pi.hProcess, 1)) {
		if (WaitForSingleObject (rio->pi.hProcess, wait_time) != WAIT_OBJECT_0) {
			r_sys_perror ("w32_kill/WaitForSingleObject");
		} else {
			ret = true;
		}
	}
	r_list_purge (dbg->threads);
	CloseHandle (rio->pi.hProcess);
	rio->pi.hProcess = NULL;
	return ret;
}

void w32_break_process(void *user) {
	RDebug *dbg = (RDebug *)user;
	RIOW32Dbg *rio = dbg->user;
	if (dbg->corebind.cfggeti (dbg->corebind.core, "dbg.threads")) {
		w32_select (dbg, rio->pi.dwProcessId, -1); // Suspend all threads
	} else {
		if (!w32_DebugBreakProcess (rio->pi.hProcess)) {
			r_sys_perror ("w32_break_process/DebugBreakProcess");
			eprintf("Could not interrupt program, attempt to press Ctrl-C in the program's console.\n");
		}
	}

	breaked = true;
}

static const char *__get_w32_excep_name(DWORD code) {
	switch (code) {
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
		return "access violation";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "array bounds exceeded";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "illegal instruction";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "divide by zero";
	case EXCEPTION_STACK_OVERFLOW:
		return "stack overflow";
	default:
		return "unknown";
	}
}

static int __debug_exception_event(DEBUG_EVENT *de) {
	unsigned long code = de->u.Exception.ExceptionRecord.ExceptionCode;
	switch (code) {
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
		eprintf ("(%d) Fatal exception (%s) in thread %d\n",
			(int)de->dwProcessId, 
			__get_w32_excep_name (code),
			(int)de->dwThreadId);
		break;
	/* MS_VC_EXCEPTION */
	case 0x406D1388:
		eprintf ("(%d) MS_VC_EXCEPTION (%x) in thread %d\n",
			(int)de->dwProcessId, (int)code, (int)de->dwThreadId);
		return 1;
	default:
		eprintf ("(%d) Unknown exception %x in thread %d\n",
			(int)de->dwProcessId, (int)code, (int)de->dwThreadId);
		break;
	}
	return 0;
}

#if 0
static char *__r_debug_get_dll() {
	return lstLibPtr->Path;
}
#endif

static PLIB_ITEM __r_debug_get_lib_item() {
	return lstLibPtr;
}

int w32_dbg_wait(RDebug *dbg, int pid) {
	RIOW32Dbg* rio = dbg->user;
	DEBUG_EVENT de;
	int tid, next_event = 0;
	char *dllname = NULL;
	int ret = R_DEBUG_REASON_UNKNOWN;
	static int exited_already = 0;

	r_cons_break_push (w32_break_process, dbg);

	/* handle debug events */
	do {
		/* do not continue when already exited but still open for examination */
		if (exited_already == pid) {
			return R_DEBUG_REASON_DEAD;
		}
		memset (&de, 0, sizeof (DEBUG_EVENT));
		w32dbg_wrap_instance *inst = rio->inst;
		do {
			inst->params->type = W32_WAIT;
			inst->params->wait.de = &de;
			inst->params->wait.wait_time = wait_time;
			void *bed = r_cons_sleep_begin ();
			w32dbg_wrap_wait_ret (rio->inst);
			r_cons_sleep_end (bed);
			if (!w32dbgw_ret (inst)) {
				if (w32dbgw_err (inst) != ERROR_SEM_TIMEOUT) {
					r_sys_perror ("w32_dbg_wait/WaitForDebugEvent");
					ret = -1;
					goto end;
				}
				if (!__is_thread_alive (dbg, dbg->tid)) {
					ret = w32_select (dbg, dbg->pid, dbg->tid);
					if (ret == -1) {
						ret = R_DEBUG_REASON_DEAD;
						goto end;
					}
				}
			} else {
				break;
			}
		} while (!breaked);

		if (breaked) {
			ret = R_DEBUG_REASON_USERSUSP;
			breaked = false;
		}

		tid = de.dwThreadId;
		pid = de.dwProcessId;
		dbg->tid = rio->pi.dwThreadId = tid;
		dbg->pid = rio->pi.dwProcessId = pid;

		/* TODO: DEBUG_CONTROL_C */
		switch (de.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			__r_debug_thread_add (dbg, pid, tid, de.u.CreateProcessInfo.hThread, de.u.CreateProcessInfo.lpThreadLocalBase, de.u.CreateProcessInfo.lpStartAddress, FALSE);
			rio->pi.hProcess = de.u.CreateProcessInfo.hProcess;
			rio->pi.hThread = de.u.CreateProcessInfo.hThread;
			rio->pi.dwProcessId = pid;
			rio->winbase = (ULONG_PTR)de.u.CreateProcessInfo.lpBaseOfImage;
			ret = R_DEBUG_REASON_NEW_PID;
			next_event = 0;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			__r_debug_thread_add (dbg, pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, FALSE);
			if (ret != R_DEBUG_REASON_USERSUSP) {
				ret = R_DEBUG_REASON_NEW_TID;
			}
			next_event = 0;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
		case EXIT_THREAD_DEBUG_EVENT:
		{
			PTHREAD_ITEM th = __find_thread (dbg, tid);
			if (th) {
				th->bFinished = TRUE;
				th->hThread = INVALID_HANDLE_VALUE;
				th->dwExitCode = de.u.ExitThread.dwExitCode;
			} else {
				__r_debug_thread_add (dbg, pid, tid, INVALID_HANDLE_VALUE, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, TRUE);
			}
			if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
				exited_already = pid;
				w32_continue (dbg, pid, tid, DBG_CONTINUE);
				ret = pid == dbg->main_pid ? R_DEBUG_REASON_DEAD : R_DEBUG_REASON_EXIT_PID;
			} else {
				ret = R_DEBUG_REASON_EXIT_TID;
			}
			next_event = 0;
			break;
		}
		case LOAD_DLL_DEBUG_EVENT:
			dllname = __resolve_path (((RIOW32Dbg *)dbg->user)->pi.hProcess, de.u.LoadDll.hFile); //__get_file_name_from_handle
			if (dllname) {
				__r_debug_lstLibAdd (pid,de.u.LoadDll.lpBaseOfDll, de.u.LoadDll.hFile, dllname);
				free (dllname);
			}
			ret = R_DEBUG_REASON_NEW_LIB;
			next_event = 0;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			lstLibPtr = (PLIB_ITEM)__r_debug_findlib (de.u.UnloadDll.lpBaseOfDll);
			if (lstLibPtr != NULL) {
				lstLibPtr->hFile = INVALID_HANDLE_VALUE;
			} else {
				__r_debug_lstLibAdd (pid, de.u.UnloadDll.lpBaseOfDll, INVALID_HANDLE_VALUE, "not cached");
				if (dllname)
					free (dllname);
			}
			ret = R_DEBUG_REASON_EXIT_LIB;
			next_event = 0;
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			char *str = calloc (de.u.DebugString.nDebugStringLength, sizeof (TCHAR));
			ReadProcessMemory (rio->pi.hProcess, de.u.DebugString.lpDebugStringData, str, de.u.DebugString.nDebugStringLength, NULL);
			char *tmp = de.u.DebugString.fUnicode
					? r_utf16_to_utf8 ((wchar_t *)str)
					: r_acp_to_utf8 (str);
			if (tmp) {
					free (str);
					str = tmp;
			}
			eprintf ("(%d) Debug string: %s\n", pid, str);
			free (str);
			w32_continue (dbg, pid, tid, DBG_EXCEPTION_NOT_HANDLED);
			next_event = 1;
			break;
		}
		case RIP_EVENT:
			eprintf ("(%d) RIP event\n", pid);
			w32_continue (dbg, pid, tid, -1);
			next_event = 1;
			// XXX unknown ret = R_DEBUG_REASON_TRAP;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
			case DBG_CONTROL_C:
				eprintf ("Received CTRL+C, suspending execution\n");
				w32_continue (dbg, pid, tid, DBG_EXCEPTION_NOT_HANDLED);
				next_event = 0;
				break;
#if _WIN64
			case 0x4000001f: /* STATUS_WX86_BREAKPOINT */
#endif
			case EXCEPTION_BREAKPOINT:
				ret = R_DEBUG_REASON_BREAKPOINT;
				next_event = 0;
				break;
#if _WIN64
			case 0x4000001e: /* STATUS_WX86_SINGLE_STEP */
#endif
			case EXCEPTION_SINGLE_STEP:
				ret = R_DEBUG_REASON_STEP;
				next_event = 0;
				break;
			default:
				if (!__debug_exception_event (&de)) {
					ret = R_DEBUG_REASON_TRAP;
					next_event = 0;
				} else {
					next_event = 1;
					w32_continue (dbg, pid, tid, DBG_EXCEPTION_NOT_HANDLED);
				}
			}
			dbg->reason.signum = de.u.Exception.ExceptionRecord.ExceptionCode;
			break;
		default:
			// This case might be reached if break doesn't trigger an event
			if (ret != R_DEBUG_REASON_USERSUSP) {
				eprintf ("(%d) unknown event: %lu\n", pid, de.dwDebugEventCode);
				ret = -1;
			}
			goto end;
		}
	} while (next_event);

	PTHREAD_ITEM th = __find_thread (dbg, tid);
	if (th) {
		rio->pi.hThread = th->hThread;
	} else {
		HANDLE th = w32_OpenThread (w32_THREAD_ALL_ACCESS, FALSE, tid);
		rio->pi.hThread = th;
		__r_debug_thread_add (dbg, pid, tid, th, 0, 0, __is_thread_alive (dbg, tid));
	}

end:
	r_cons_break_pop ();
	return ret;
}

int w32_step(RDebug *dbg) {
	/* set TRAP flag */
	CONTEXT ctx;
	if (!w32_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&ctx, sizeof (ctx))) {
		return false;
	}
	ctx.EFlags |= 0x100;
	if (!w32_reg_write (dbg, R_REG_TYPE_GPR, (ut8 *)&ctx, sizeof (ctx))) {
		return false;
	}
	return w32_continue (dbg, dbg->pid, dbg->tid, dbg->reason.signum);
	// (void)r_debug_handle_signals (dbg);
}

int w32_continue(RDebug *dbg, int pid, int tid, int sig) {
	/* Honor the Windows-specific signal that instructs threads to process exceptions */
	RIOW32Dbg *rio = dbg->user;
	DWORD continue_status = (sig == DBG_EXCEPTION_NOT_HANDLED)
		? DBG_EXCEPTION_NOT_HANDLED : DBG_EXCEPTION_HANDLED;
	dbg->tid = w32_select (dbg, pid, tid);
	r_io_system (dbg->iob.io, sdb_fmt ("pid %d", dbg->tid));

	// Don't continue with a thread that wasn't requested
	if (dbg->tid != tid) {
		return -1;
	}

	if (breaked) {
		breaked = false;
		return -1;
	}
	w32dbg_wrap_instance *inst = rio->inst;
	inst->params->type = W32_CONTINUE;
	inst->params->pid = rio->pi.dwProcessId;
	inst->params->tid = rio->pi.dwThreadId;
	inst->params->continue_status = continue_status;
	w32dbg_wrap_wait_ret (inst);
	if (!w32dbgw_ret (inst)) {
		w32dbgw_err (inst);
		r_sys_perror ("w32_continue/ContinueDebugEvent");
		return -1;
	}

	return tid;
}

RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size) {
	RIOW32Dbg *rio = dbg->user;
	LPVOID base = VirtualAllocEx (rio->pi.hProcess, (LPVOID)addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		r_sys_perror ("w32_map_alloc/VirtualAllocEx");
		return NULL;
	}
	r_debug_map_sync (dbg);
	return r_debug_map_get (dbg, (ut64)base);
}

int w32_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	RIOW32Dbg *rio = dbg->user;
	if (!VirtualFreeEx (rio->pi.hProcess, (LPVOID)addr, 0, MEM_RELEASE)) {
		r_sys_perror ("w32_map_dealloc/VirtualFreeEx");
		return false;
	}
	return true;
}

static int __io_perms_to_prot(int io_perms) {
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
	return VirtualProtectEx (rio->pi.hProcess, (LPVOID)(size_t)addr,
		size, __io_perms_to_prot (perms), &old);
}

RList *w32_thread_list(RDebug *dbg, int pid, RList *list) {
	// pid is not respected for TH32CS_SNAPTHREAD flag
	HANDLE th = w32_CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, 0);
	if (th == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_thread_list/CreateToolhelp32Snapshot");
		return list;
	}
	THREADENTRY32 te;
	te.dwSize = sizeof (te);
	HANDLE ph = w32_OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (Thread32First (th, &te)) {
		// TODO: export this code to its own function?
		char *path = NULL;
		int uid = -1;
		if (!te.th32ThreadID) {
			path = __resolve_path (ph, NULL);
			DWORD sid;
			if (ProcessIdToSessionId (pid, &sid)) {
				uid = sid;
			}
		}
		if (!path) {
			// TODO: enum processes to get binary's name
			path = strdup ("???");
		}
		int saved_tid = dbg->tid;
		do {
			char status = R_DBG_PROC_SLEEP;
			if (te.th32OwnerProcessID == pid) {
				ut64 pc = 0;
				if (dbg->pid == pid) {
					CONTEXT ctx = {0};
					dbg->tid = te.th32ThreadID;
					w32_reg_read (dbg, R_REG_TYPE_GPR, (ut8 *)&ctx, sizeof (ctx));
					// TODO: is needed check context for x32 and x64??
#if _WIN64
					pc = ctx.Rip;
#else
					pc = ctx.Eip;
#endif
					PTHREAD_ITEM pthread = __find_thread (dbg, te.th32ThreadID);
					if (pthread) {
						if (pthread->bFinished) {
							status = R_DBG_PROC_DEAD;
						} else if (pthread->bSuspended) {
							status = R_DBG_PROC_SLEEP;
						} else {
							status = R_DBG_PROC_RUN; // TODO: Get more precise thread status
						}
					}
				}
				r_list_append (list, r_debug_pid_new (path, te.th32ThreadID, uid, status, pc));
			}
		} while (Thread32Next (th, &te));
		dbg->tid = saved_tid;
		free (path);
	} else {
		r_sys_perror ("w32_thread_list/Thread32First");
	}
	CloseHandle (th);
	return list;
}

static void __w32_info_user(RDebug *dbg, RDebugInfo *rdi) {
	HANDLE h_tok = NULL;
	DWORD tok_len = 0;
	PTOKEN_USER tok_usr = NULL;
	LPTSTR usr = NULL, usr_dom = NULL;
	DWORD usr_len = 512;
	DWORD usr_dom_len = 512;
	SID_NAME_USE snu = {0};
	RIOW32Dbg *rio = dbg->user;

	if (!OpenProcessToken (rio->pi.hProcess, TOKEN_QUERY, &h_tok)) {
		r_sys_perror ("__w32_info_user/OpenProcessToken");
		goto err___w32_info_user;
	}
	if (!GetTokenInformation (h_tok, TokenUser, (LPVOID)&tok_usr, 0, &tok_len) && GetLastError () != ERROR_INSUFFICIENT_BUFFER) {
		r_sys_perror ("__w32_info_user/GetTokenInformation");
		goto err___w32_info_user;
	}
	tok_usr = (PTOKEN_USER)malloc (tok_len);
	if (!tok_usr) {
		perror ("__w32_info_user/malloc tok_usr");
		goto err___w32_info_user;
	}
	if (!GetTokenInformation (h_tok, TokenUser, (LPVOID)tok_usr, tok_len, &tok_len)) {
		r_sys_perror ("__w32_info_user/GetTokenInformation");
		goto err___w32_info_user;
	}
	usr = (LPTSTR)malloc (usr_len * sizeof (TCHAR));
	if (!usr) {
		perror ("__w32_info_user/malloc usr");
		goto err___w32_info_user;
	}
	*usr = '\0';
	usr_dom = (LPTSTR)malloc (usr_dom_len * sizeof (TCHAR));
	if (!usr_dom) {
		perror ("__w32_info_user/malloc usr_dom");
		goto err___w32_info_user;
	}
	*usr_dom = '\0';
	if (!LookupAccountSid (NULL, tok_usr->User.Sid, usr, &usr_len, usr_dom, &usr_dom_len, &snu)) {
		r_sys_perror ("__w32_info_user/LookupAccountSid");
		goto err___w32_info_user;
	}
	if (*usr_dom) {
		rdi->usr = r_str_newf (W32_TCHAR_FSTR"\\"W32_TCHAR_FSTR, usr_dom, usr);		
	} else {
		rdi->usr = r_sys_conv_win_to_utf8 (usr);
	}
err___w32_info_user:
	if (h_tok) {
		CloseHandle (h_tok);
	}
	free (usr);
	free (usr_dom);
	free (tok_usr);
}

static void __w32_info_exe(RDebug *dbg, RDebugInfo *rdi) {
	RIOW32Dbg *rio = dbg->user;
	rdi->exe = __resolve_path (rio->pi.hProcess, NULL);
}

RDebugInfo *w32_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->lib = (void *) __r_debug_get_lib_item ();
	rdi->thread = __find_thread (dbg, dbg->tid);
	rdi->uid = -1;
	rdi->gid = -1;
	rdi->cwd = NULL;
	rdi->exe = NULL;
	rdi->cmdline = NULL;
	rdi->libname = NULL;
	__w32_info_user (dbg, rdi);
	__w32_info_exe (dbg, rdi);
	return rdi;
}

static RDebugPid *__build_debug_pid(int pid, int ppid, HANDLE ph, const TCHAR* name) {
	char *path = NULL;
	int uid = -1;
	if (!ph) {
		ph = w32_OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (ph) {
			path = __resolve_path (ph, NULL);
			DWORD sid;
			if (ProcessIdToSessionId (pid, &sid)) {
				uid = sid;
			}
			CloseHandle (ph);
		} else {
			return NULL;
		}
	} else {
		path = __resolve_path (ph, NULL);
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
	ret->ppid = ppid;
	free (path);
	return ret;
}

RList *w32_pid_list(RDebug *dbg, int pid, RList *list) {
	HANDLE sh = w32_CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, pid);
	if (sh == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_pid_list/CreateToolhelp32Snapshot");
		return list;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof (pe);
	if (Process32First (sh, &pe)) {
		RIOW32Dbg *rio = dbg->user;
		bool all = pid == 0;
		do {
			if (all || pe.th32ProcessID == pid || pe.th32ParentProcessID == pid) {
				// Returns NULL if process is inaccessible unless if its a child process of debugged process
				RDebugPid *dbg_pid = __build_debug_pid (pe.th32ProcessID, pe.th32ParentProcessID,
					dbg->pid == pe.th32ProcessID ? rio->pi.hProcess : NULL, pe.szExeFile);
				if (dbg_pid) {
					r_list_append (list, dbg_pid);
				}
#if 0
				else {
					eprintf ("w32_pid_list: failed to process pid %d\n", pe.th32ProcessID);
				}
#endif
			}
		} while (Process32Next (sh, &pe));
	} else {
		r_sys_perror ("w32_pid_list/Process32First");
	}
	CloseHandle (sh);
	return list;
}

RList *w32_desc_list(int pid) {
	RDebugDesc *desc;
	RList *ret = r_list_newf (free);
	int i;
	HANDLE ph;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	LPVOID buff;
	if (!ret) {
		perror ("win_desc_list/r_list_new");
		return NULL;
	}
	if (!(ph = w32_OpenProcess (PROCESS_DUP_HANDLE, FALSE, pid))) {
		r_sys_perror ("win_desc_list/OpenProcess");
		r_list_free (ret);
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc (handleInfoSize);
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	#define SystemHandleInformation 16
	while ((status = w32_NtQuerySystemInformation (SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		handleInfoSize *= 2;
		void *tmp = realloc (handleInfo, (size_t)handleInfoSize);
		if (tmp) {
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)tmp;
		}
	}
	if (status) {
		r_sys_perror ("win_desc_list/NtQuerySystemInformation");
		CloseHandle (ph);
		r_list_free (ret);
		return NULL;
	}
	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		if (handle.ProcessId != pid) {
			continue;
		}
		if (handle.ObjectTypeNumber != 0x1c) {
			continue;
		}
		if (w32_NtDuplicateObject (ph, &handle.Handle, GetCurrentProcess (), &dupHandle, 0, 0, 0)) {
			continue;
		}
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc (0x1000);
		if (w32_NtQueryObject (dupHandle, 2, objectTypeInfo, 0x1000, NULL)) {
			CloseHandle (dupHandle);
			continue;
		}
		objectNameInfo = malloc (0x1000);
		if (!objectNameInfo) {
			break;
		}
		if (w32_NtQueryObject (dupHandle, 1, objectNameInfo, 0x1000, &returnLength)) {
			void *tmp = realloc (objectNameInfo, returnLength);
			if (tmp) {
				objectNameInfo = tmp;
			}
			if (w32_NtQueryObject (dupHandle, 1, objectNameInfo, returnLength, NULL)) {
				free (objectTypeInfo);
				free (objectNameInfo);
				CloseHandle (dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length) {
			//objectTypeInfo->Name.Length ,objectTypeInfo->Name.Buffer, objectName.Length / 2, objectName.Buffer
			buff = malloc ((size_t)(objectName.Length / 2) + 1);
			wcstombs (buff, objectName.Buffer, objectName.Length / 2);
			desc = r_debug_desc_new (handle.Handle, buff, 0, '?', 0);
			if (!desc) {
				free (buff);
				break;
			}
			r_list_append (ret, desc);
			free (buff);
		} else {
			buff = malloc ((size_t)(objectTypeInfo->Name.Length / 2) + 1);
			wcstombs (buff, objectTypeInfo->Name.Buffer, objectTypeInfo->Name.Length);
			desc = r_debug_desc_new (handle.Handle, buff, 0, '?', 0);
			if (!desc) {
				free (buff);
				break;
			}
			r_list_append (ret, desc);
			free (buff);
		}
		free (objectTypeInfo);
		free (objectNameInfo);
		CloseHandle (dupHandle);
	}
	free (handleInfo);
	CloseHandle (ph);
	return ret;
}
