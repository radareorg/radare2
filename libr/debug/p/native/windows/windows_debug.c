/* radare - LGPL - Copyright 2019 - MapleLeaf-X */

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include "windows_debug.h"
#include <w32dbg_wrap.h>
#undef WIN32_NO_STATUS

const DWORD wait_time = 1000;
static RList *lib_list = NULL;
static PLIB_ITEM last_lib = NULL;

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
	W32DbgWInst *wrap = dbg->user;
	if (!wrap) {
		if (dbg->iob.io->w32dbg_wrap) {
			dbg->user = (W32DbgWInst *)dbg->iob.io->w32dbg_wrap;
		} else {
			return 0;
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

	return true;
}


static int __w32_findthread_cmp(int *tid, PTHREAD_ITEM th) {
	return (int)!(*tid == th->tid);
}

static inline PTHREAD_ITEM __find_thread(RDebug *dbg, int tid) {
	if (!dbg->threads) {
		return NULL;
	}
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
	W32DbgWInst *wrap = dbg->user;

	bool alive = __is_thread_alive (dbg, dbg->tid);
	HANDLE th = wrap->pi.dwThreadId == dbg->tid ? wrap->pi.hThread : NULL;
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
	if (th != wrap->pi.hThread) {
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
	W32DbgWInst *wrap = dbg->user;
	if (wrap->pi.hProcess) {
		return wrap->pi.dwThreadId;
	}
	HANDLE ph = w32_OpenProcess (w32_PROCESS_ALL_ACCESS, FALSE, pid);
	if (!ph) {
		return -1;
	}
	wrap->pi.hProcess = ph;
	wrap->pi.dwProcessId = pid;
	wrap->params.type = W32_ATTACH;
	w32dbg_wrap_wait_ret (wrap);
	if (!wrap->params.ret) {
		w32dbgw_err (wrap);
		r_sys_perror ("DebugActiveProcess");
		CloseHandle (ph);
		return -1;
	}
	w32_dbg_wait (dbg, pid);
	return wrap->pi.dwThreadId;
}

int w32_detach(RDebug *dbg, int pid) {
	if (pid == -1 || dbg->pid != pid) {
		return false;
	}

	DebugSetProcessKillOnExit (FALSE);
	W32DbgWInst *wrap = dbg->user;
	bool ret = false;
	wrap->pi.dwProcessId = pid;
	wrap->params.type = W32_DETACH;
	w32dbg_wrap_wait_ret (wrap);
	ret = wrap->params.ret;
	if (wrap->pi.hProcess) {
		CloseHandle (wrap->pi.hProcess);
		memset (&wrap->pi, 0, sizeof (wrap->pi));
	}
	DebugSetProcessKillOnExit (TRUE);
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

static void libfree(void* lib) {
	PLIB_ITEM lib_item = (PLIB_ITEM)lib;
	free (lib_item->Name);
	free (lib_item->Path);
	if (lib_item->hFile && lib_item->hFile != INVALID_HANDLE_VALUE) {
		CloseHandle (lib_item->hFile);
	}
	free (lib_item);
}

static int findlibcmp(void *BaseOfDll, void *lib) {
	PLIB_ITEM lib_item = (PLIB_ITEM)lib;
	return !lib_item->hFile || lib_item->hFile == INVALID_HANDLE_VALUE || lib_item->BaseOfDll != BaseOfDll;
}

static void *findlib(void *BaseOfDll) {
	RListIter *it = r_list_find (lib_list, BaseOfDll, (RListComparator)findlibcmp);
	return it ? it->data : NULL;
}

static PLIB_ITEM lib_list_add(DWORD pid, LPVOID lpBaseOfDll, HANDLE hFile, char *dllname) {
	if (lib_list == NULL) {
		lib_list = r_list_newf ((RListFree)libfree);
		if (!lib_list) {
			R_LOG_ERROR ("Failed to allocate memory");
			return NULL;
		}
	}
	RListIter *it;
	PLIB_ITEM lib;
	r_list_foreach (lib_list, it, lib) {
		if (lib->hFile == hFile && lib->BaseOfDll == lpBaseOfDll) {
			return lib;
		}
	}
	lib = R_NEW0 (LIB_ITEM);
	if (!lib) {
		R_LOG_ERROR ("Failed to allocate memory");
		return NULL;
	}
	lib->pid = pid;
	lib->hFile = hFile;
	lib->BaseOfDll = lpBaseOfDll;
	lib->Path = strdup (dllname);
	lib->Name = strdup (r_file_basename (dllname));

	(void)r_list_append (lib_list, lib);
	return lib;
}

static bool breaked = false;

int w32_attach_new_process(RDebug* dbg, int pid) {
	int tid = -1;

	if (!w32_detach (dbg, dbg->pid)) {
		eprintf ("Failed to detach from (%d)\n", dbg->pid);
		return -1;
	}

	if ((tid = w32_attach (dbg, pid)) < 0) {
		eprintf ("Failed to attach to (%d)\n", pid);
		return -1;
	}

	dbg->tid = tid;
	dbg->pid = pid;
	// Call select to sync the new pid's data
	r_debug_select (dbg, pid, tid);
	return dbg->tid;
}

int w32_select(RDebug *dbg, int pid, int tid) {
	RListIter *it;
	W32DbgWInst *wrap = dbg->user;

	// Re-attach to a different pid
	if (dbg->pid > -1 && dbg->pid != pid) {
		return w32_attach_new_process (dbg, pid);
	}

	if (dbg->tid == -1) {
		return tid;
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
		wrap->pi.hThread = th->hThread;
		selected = tid;
	} else if (tid) {
		// If thread is dead, search for another one
		r_list_foreach (dbg->threads, it, th) {
			if (!__is_thread_alive (dbg, th->tid)) {
				continue;
			}
			wrap->pi.hThread = th->hThread;
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
	W32DbgWInst *wrap = dbg->user;

	if (sig == 0) {
		if (r_list_empty (dbg->threads) || (dbg->reason.tid == pid && dbg->reason.signum == EXIT_PROCESS_DEBUG_EVENT)) {
			if (dbg->threads) {
				r_list_purge (dbg->threads);
			}
			if (lib_list) {
				r_list_purge (lib_list);
			}
			return false;
		}
		return true;
	}
	
	bool ret = false;
	if (TerminateProcess (wrap->pi.hProcess, 1)) {
		ret = true;
	}
	CloseHandle (wrap->pi.hProcess);
	wrap->pi.hProcess = NULL;
	wrap->pi.hThread = NULL;
	return ret;
}

void w32_break_process(void *user) {
	RDebug *dbg = (RDebug *)user;
	W32DbgWInst *wrap = dbg->user;
	if (dbg->corebind.cfggeti (dbg->corebind.core, "dbg.threads")) {
		w32_select (dbg, wrap->pi.dwProcessId, -1); // Suspend all threads
	} else {
		if (!w32_DebugBreakProcess (wrap->pi.hProcess)) {
			r_sys_perror ("w32_break_process/DebugBreakProcess");
			eprintf("Could not interrupt program, attempt to press Ctrl-C in the program's console.\n");
		}
	}

	breaked = true;
}

static RDebugReasonType exception_to_reason (DWORD ExceptionCode) {
	switch (ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_GUARD_PAGE:
		return R_DEBUG_REASON_SEGFAULT;
	case EXCEPTION_BREAKPOINT:
		return R_DEBUG_REASON_BREAKPOINT;
	case EXCEPTION_FLT_DENORMAL_OPERAND:
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case EXCEPTION_FLT_INEXACT_RESULT:
	case EXCEPTION_FLT_INVALID_OPERATION:
	case EXCEPTION_FLT_OVERFLOW:
	case EXCEPTION_FLT_STACK_CHECK:
	case EXCEPTION_FLT_UNDERFLOW:
		return R_DEBUG_REASON_FPU;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return R_DEBUG_REASON_ILLEGAL;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return R_DEBUG_REASON_DIVBYZERO;
	case EXCEPTION_SINGLE_STEP:
		return R_DEBUG_REASON_STEP;
	default:
		return R_DEBUG_REASON_TRAP;
	}
}

static const char *get_exception_name(DWORD ExceptionCode) {
#define EXCEPTION_STR(x) case x: return #x
	switch (ExceptionCode) {
	EXCEPTION_STR (EXCEPTION_ACCESS_VIOLATION);
	EXCEPTION_STR (EXCEPTION_ARRAY_BOUNDS_EXCEEDED);
	EXCEPTION_STR (EXCEPTION_BREAKPOINT);
	EXCEPTION_STR (EXCEPTION_DATATYPE_MISALIGNMENT);
	EXCEPTION_STR (EXCEPTION_FLT_DENORMAL_OPERAND);
	EXCEPTION_STR (EXCEPTION_FLT_DIVIDE_BY_ZERO);
	EXCEPTION_STR (EXCEPTION_FLT_INEXACT_RESULT);
	EXCEPTION_STR (EXCEPTION_FLT_INVALID_OPERATION);
	EXCEPTION_STR (EXCEPTION_FLT_OVERFLOW);
	EXCEPTION_STR (EXCEPTION_FLT_STACK_CHECK);
	EXCEPTION_STR (EXCEPTION_FLT_UNDERFLOW);
	EXCEPTION_STR (EXCEPTION_GUARD_PAGE);
	EXCEPTION_STR (EXCEPTION_ILLEGAL_INSTRUCTION);
	EXCEPTION_STR (EXCEPTION_IN_PAGE_ERROR);
	EXCEPTION_STR (EXCEPTION_INT_DIVIDE_BY_ZERO);
	EXCEPTION_STR (EXCEPTION_INT_OVERFLOW);
	EXCEPTION_STR (EXCEPTION_INVALID_DISPOSITION);
	EXCEPTION_STR (EXCEPTION_INVALID_HANDLE);
	EXCEPTION_STR (EXCEPTION_NONCONTINUABLE_EXCEPTION);
	EXCEPTION_STR (EXCEPTION_PRIV_INSTRUCTION);
	EXCEPTION_STR (EXCEPTION_SINGLE_STEP);
	EXCEPTION_STR (EXCEPTION_STACK_OVERFLOW);
	EXCEPTION_STR (STATUS_UNWIND_CONSOLIDATE);
	EXCEPTION_STR (EXCEPTION_POSSIBLE_DEADLOCK);
	EXCEPTION_STR (DBG_CONTROL_BREAK);
	EXCEPTION_STR (CONTROL_C_EXIT);
	case 0x6ba: return "FILE_DIALOG_EXCEPTION";
	case 0x406D1388: return "MS_VC_EXCEPTION";
	default:
		return "Unknown";
	}
#undef EXCEPTION_STR
}

static bool is_exception_fatal(DWORD ExceptionCode) {
	switch (ExceptionCode) {
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
	case EXCEPTION_GUARD_PAGE:
	case EXCEPTION_PRIV_INSTRUCTION:
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
	case EXCEPTION_FLT_STACK_CHECK:
	case EXCEPTION_IN_PAGE_ERROR:
		return true;
	default:
		return false;
	}
}

static void print_exception_event(DEBUG_EVENT *de) {
	unsigned long code = de->u.Exception.ExceptionRecord.ExceptionCode;
	bool is_fatal = is_exception_fatal (code);
	eprintf ("(%d) %s Exception %04X (%s) in thread %d\n",
		(int)de->dwProcessId,
		is_fatal ? "Fatal" : "Non-fatal",
		(ut32)code, get_exception_name (code),
		(int)de->dwThreadId);
	if (is_fatal && de->u.Exception.dwFirstChance) {
		eprintf ("Hint: Use 'dce' continue into exception handler\n");
	} else if (is_fatal) {
		eprintf ("Second-chance exception!!!\n");
	}
}

#if 0
static char *__r_debug_get_dll(void) {
	return lstLibPtr->Path;
}
#endif

int w32_dbg_wait(RDebug *dbg, int pid) {
	W32DbgWInst *wrap = dbg->user;
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
		do {
			wrap->params.type = W32_WAIT;
			wrap->params.wait.de = &de;
			wrap->params.wait.wait_time = wait_time;
			void *bed = r_cons_sleep_begin ();
			w32dbg_wrap_wait_ret (wrap);
			r_cons_sleep_end (bed);
			if (!w32dbgw_ret (wrap)) {
				if (w32dbgw_err (wrap) != ERROR_SEM_TIMEOUT) {
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

		dbg->tid = tid = de.dwThreadId;
		dbg->pid = pid = de.dwProcessId;

		/* TODO: DEBUG_CONTROL_C */
		switch (de.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			CloseHandle (de.u.CreateProcessInfo.hFile);
			__r_debug_thread_add (dbg, pid, tid, de.u.CreateProcessInfo.hThread, de.u.CreateProcessInfo.lpThreadLocalBase, de.u.CreateProcessInfo.lpStartAddress, FALSE);
			wrap->pi.hProcess = de.u.CreateProcessInfo.hProcess;
			wrap->pi.hThread = de.u.CreateProcessInfo.hThread;
			wrap->winbase = (ULONG_PTR)de.u.CreateProcessInfo.lpBaseOfImage;
			ret = R_DEBUG_REASON_NEW_PID;
			next_event = 0;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			__r_debug_thread_add (dbg, pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, FALSE);
			if (ret != R_DEBUG_REASON_USERSUSP) {
				ret = R_DEBUG_REASON_NEW_TID;
			}
			dbg->corebind.cmdf (dbg->corebind.core, "f teb.%d @ 0x%p", tid, de.u.CreateThread.lpThreadLocalBase);
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
			dbg->corebind.cmdf (dbg->corebind.core, "f- teb.%d", tid);
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
			dllname = __resolve_path (((W32DbgWInst *)dbg->user)->pi.hProcess, de.u.LoadDll.hFile); //__get_file_name_from_handle
			if (dllname) {
				last_lib = lib_list_add (pid, de.u.LoadDll.lpBaseOfDll, de.u.LoadDll.hFile, dllname);
				free (dllname);
			}
			ret = R_DEBUG_REASON_NEW_LIB;
			next_event = 0;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			PLIB_ITEM lib = (PLIB_ITEM)findlib (de.u.UnloadDll.lpBaseOfDll);
			if (lib) {
				CloseHandle (lib->hFile);
				lib->hFile = INVALID_HANDLE_VALUE;
			}
			last_lib = lib;
			ret = R_DEBUG_REASON_EXIT_LIB;
			next_event = 0;
			break;
		}
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			char *str = calloc (de.u.DebugString.nDebugStringLength, sizeof (TCHAR));
			ReadProcessMemory (wrap->pi.hProcess, de.u.DebugString.lpDebugStringData, str, de.u.DebugString.nDebugStringLength, NULL);
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
				ret = R_DEBUG_REASON_SIGNAL;
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
				print_exception_event (&de);
				if (is_exception_fatal (de.u.Exception.ExceptionRecord.ExceptionCode)) {				
					next_event = 0;
					dbg->reason.type = exception_to_reason (de.u.Exception.ExceptionRecord.ExceptionCode);
					dbg->reason.tid = de.dwThreadId;
					dbg->reason.addr = (size_t)de.u.Exception.ExceptionRecord.ExceptionAddress;
					dbg->reason.timestamp = r_time_now ();
					ret = dbg->reason.type;
				} else {
					w32_continue (dbg, pid, tid, DBG_EXCEPTION_NOT_HANDLED);
					next_event = 1;
				}
			}
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
		wrap->pi.hThread = th->hThread;
	} else {
		HANDLE th = w32_OpenThread (w32_THREAD_ALL_ACCESS, FALSE, tid);
		wrap->pi.hThread = th;
		__r_debug_thread_add (dbg, pid, tid, th, 0, 0, __is_thread_alive (dbg, tid));
	}

end:
	if (ret == R_DEBUG_REASON_DEAD) {
		w32_detach (dbg, dbg->pid);
		r_list_purge (dbg->threads);
		r_list_purge (lib_list);
	}
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
	if (tid != dbg->tid) {
		dbg->tid = w32_select (dbg, pid, tid);
		r_io_system (dbg->iob.io, sdb_fmt ("pid %d", dbg->tid));
	}
	// Don't continue with a thread that wasn't requested
	if (dbg->tid != tid) {
		return -1;
	}

	if (breaked) {
		breaked = false;
		return -1;
	}

	PTHREAD_ITEM th = __find_thread (dbg, tid);
	if (th && th->hThread != INVALID_HANDLE_VALUE) {
		__continue_thread (th->hThread, dbg->bits);
		th->bSuspended = false;
	}

	W32DbgWInst *wrap = dbg->user;
	wrap->params.type = W32_CONTINUE;

	/* Honor the Windows-specific signal that instructs threads to process exceptions */
	wrap->params.continue_status = (sig == DBG_EXCEPTION_NOT_HANDLED)
		? DBG_EXCEPTION_NOT_HANDLED
		: DBG_EXCEPTION_HANDLED;

	w32dbg_wrap_wait_ret (wrap);
	if (!w32dbgw_ret (wrap)) {
		w32dbgw_err (wrap);
		r_sys_perror ("w32_continue/ContinueDebugEvent");
		return -1;
	}

	return tid;
}

RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size) {
	W32DbgWInst *wrap = dbg->user;
	LPVOID base = VirtualAllocEx (wrap->pi.hProcess, (LPVOID)addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		r_sys_perror ("w32_map_alloc/VirtualAllocEx");
		return NULL;
	}
	r_debug_map_sync (dbg);
	return r_debug_map_get (dbg, (ut64)base);
}

int w32_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	W32DbgWInst *wrap = dbg->user;
	if (!VirtualFreeEx (wrap->pi.hProcess, (LPVOID)addr, 0, MEM_RELEASE)) {
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
	W32DbgWInst *wrap = dbg->user;
	return VirtualProtectEx (wrap->pi.hProcess, (LPVOID)(size_t)addr,
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
	W32DbgWInst *wrap = dbg->user;

	if (!wrap->pi.hProcess) {
		return;
	}

	if (!OpenProcessToken (wrap->pi.hProcess, TOKEN_QUERY, &h_tok)) {
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
	W32DbgWInst *wrap = dbg->user;
	rdi->exe = __resolve_path (wrap->pi.hProcess, NULL);
}

RDebugInfo *w32_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	if (!rdi) {
		return NULL;
	}
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->lib = last_lib;
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
		W32DbgWInst *wrap = dbg->user;
		bool all = pid == 0;
		do {
			if (all || pe.th32ProcessID == pid || pe.th32ParentProcessID == pid) {
				// Returns NULL if process is inaccessible unless if its a child process of debugged process
				RDebugPid *dbg_pid = __build_debug_pid (pe.th32ProcessID, pe.th32ParentProcessID,
					dbg->pid == pe.th32ProcessID ? wrap->pi.hProcess : NULL, pe.szExeFile);
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
	int i;
	HANDLE ph;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	POBJECT_TYPE_INFORMATION objectTypeInfo = malloc (0x1000);
	RList *ret = r_list_newf ((RListFree)r_debug_desc_free);
	if (!ret) {
		return NULL;
	}
	if (!(ph = w32_OpenProcess (PROCESS_DUP_HANDLE, FALSE, pid))) {
		r_sys_perror ("win_desc_list/OpenProcess");
		r_list_free (ret);
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc (handleInfoSize);
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
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		int perms = 0;
		if (handle.ProcessId != pid) {
			continue;
		}
		if (w32_NtDuplicateObject (ph, (HANDLE)handle.Handle, GetCurrentProcess (), &dupHandle, 0, 0, 0)) {
			continue;
		}
		if (w32_NtQueryObject (dupHandle, 2, objectTypeInfo, 0x1000, NULL)) {
			CloseHandle (dupHandle);
			continue;
		}
		if (wcscmp (objectTypeInfo->Name.Buffer, L"File")) {
			CloseHandle (dupHandle);
			continue;
		}
		GENERIC_MAPPING *gm = &objectTypeInfo->GenericMapping;
		if ((handle.GrantedAccess & gm->GenericRead) == gm->GenericRead) {
			perms |= R_PERM_R;
		}
		if ((handle.GrantedAccess & gm->GenericWrite) == gm->GenericWrite) {
			perms |= R_PERM_W;
		}
		if ((handle.GrantedAccess & gm->GenericExecute) == gm->GenericExecute) {
			perms |= R_PERM_X;
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
				free (objectNameInfo);
				CloseHandle (dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length) {
			char *name = r_utf16_to_utf8_l (objectName.Buffer, objectName.Length / 2);
			desc = r_debug_desc_new (handle.Handle, name, perms, '?', 0);
			if (!desc) {
				free (name);
				break;
			}
			r_list_append (ret, desc);
			free (name);
		} else {
			char *name = r_utf16_to_utf8_l (objectTypeInfo->Name.Buffer, objectTypeInfo->Name.Length / 2);
			desc = r_debug_desc_new (handle.Handle, name, perms, '?', 0);
			if (!desc) {
				free (name);
				break;
			}
			r_list_append (ret, desc);
			free (name);
		}
		free (objectNameInfo);
		CloseHandle (dupHandle);
	}
	free (objectTypeInfo);
	free (handleInfo);
	CloseHandle (ph);
	return ret;
}
