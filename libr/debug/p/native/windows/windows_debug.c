/* radare - LGPL - Copyright 2019 - MapleLeaf-X */
#include <string.h>
#include "windows_debug.h"
#include <windows.h>
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName
#include <tchar.h>

#ifndef XSTATE_GSSE
#define XSTATE_GSSE 2
#endif

#ifndef XSTATE_LEGACY_SSE
#define XSTATE_LEGACY_SSE 1
#endif

#if !defined(XSTATE_MASK_GSSE)
#define XSTATE_MASK_GSSE (1LLU << (XSTATE_GSSE))
#endif

#undef CONTEXT_XSTATE
#if defined(_M_X64)
#define CONTEXT_XSTATE                      (0x00100040)
#else
#define CONTEXT_XSTATE                      (0x00010040)
#endif
#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)
#ifndef CONTEXT_ALL
#define CONTEXT_ALL 1048607
#endif

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct {
	// bool dbgpriv;
	HANDLE ph;
	bool debug;
} RIOW32Dbg;

static ut64 (WINAPI *w32_GetEnabledXStateFeatures)() = NULL;
static BOOL (WINAPI *w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
static BOOL (WINAPI *w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64) = NULL;
static PVOID(WINAPI *w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD) = NULL;
static BOOL (WINAPI *w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64) = NULL;

static NTSTATUS (WINAPI *w32_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = NULL;
static NTSTATUS (WINAPI *w32_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;

const DWORD wait_time = 1000;

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

	HMODULE lib = GetModuleHandle (TEXT ("kernel32")); //Always loaded
	if (!lib) {
		return false;
	}
	w32_GetEnabledXStateFeatures = GetProcAddress (lib, "GetEnabledXStateFeatures");
	w32_InitializeContext = GetProcAddress (lib, "InitializeContext");
	w32_GetXStateFeaturesMask = GetProcAddress (lib, "GetXStateFeaturesMask");
	w32_LocateXStateFeature = GetProcAddress (lib, "LocateXStateFeature");
	w32_SetXStateFeaturesMask = GetProcAddress (lib, "SetXStateFeaturesMask");

	lib = GetModuleHandle (TEXT ("ntdll")); //Always loaded
	if (!lib) {
		return false;
	}
	w32_NtQueryInformationThread = GetProcAddress (lib, "NtQueryInformationThread");
	w32_NtQuerySystemInformation = GetProcAddress (lib, "NtQuerySystemInformation");
	w32_NtDuplicateObject = GetProcAddress (lib, "NtDuplicateObject");
	w32_NtQueryObject = GetProcAddress (lib, "NtQueryObject");

	setup_debug_privileges (true);
	// rio->dbgpriv = setup_debug_privileges (true);
	rio->ph = (HANDLE)NULL;
	rio->debug = false;
	return true;
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

static int __set_thread_context(HANDLE th, const ut8 *buf, int size, int bits) {
	bool ret;
#if 0
	if (bits == R_SYS_BITS_32) {
#endif
		CONTEXT ctx = {0};
		size = R_MIN (size, sizeof (ctx));
		memcpy (&ctx, buf, size);
		if(!(ret = SetThreadContext (th, &ctx))) {
			r_sys_perror ("__set_thread_context/SetThreadContext");
		}
#if 0
	} else {
		WOW64_CONTEXT ctx = {0};
		if (size > sizeof (ctx)) {
			size = sizeof (ctx);
		}
		memcpy (&ctx, buf, size);
		if(!(ret = Wow64SetThreadContext (th, &ctx))) {
			r_sys_perror ("__set_thread_context/Wow64SetThreadContext");
		}
	}
#endif
	return ret;
}

static int __get_thread_context(HANDLE th, ut8 *buf, int size, int bits) {
	int ret = 0;
#if 0
	if (bits == R_SYS_BITS_32) {
#endif
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
			r_sys_perror ("__get_thread_context/GetThreadContext");
		}
#if 0
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
			r_sys_perror ("__get_thread_context/Wow64GetThreadContext");
		}
	}
#endif
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
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", ctx->MxCsr, ctx->FltSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", ctx->FltSave.ErrorOffset, ctx->FltSave.DataOffset);
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
	DWORD flags = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
	if (dbg->bits == R_SYS_BITS_64) {
		flags |= THREAD_QUERY_INFORMATION;
	}
	HANDLE th = OpenThread (flags, FALSE, dbg->tid);
	if (!th) {
		r_sys_perror ("w32_reg_read/OpenThread");
		return 0;
	}
	// Always suspend
	if (__suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return 0;
	}
	size = __get_thread_context (th, buf, size, dbg->bits);
	if (showfpu) {
		__printwincontext (th, (CONTEXT *)buf);
	}
	// Always resume
	if (__resume_thread (th, dbg->bits) == -1) {
		size = 0;
	}
	CloseHandle (th);
	return size;
}

int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	DWORD flags = THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT;
	if (dbg->bits == R_SYS_BITS_64) {
		flags |= THREAD_QUERY_INFORMATION;
	}
	HANDLE th = OpenThread (flags, FALSE, dbg->tid);
	if (!th) {
		r_sys_perror ("w32_reg_write/OpenThread");
		return false;
	}
	// Always suspend
	if (__suspend_thread (th, dbg->bits) == -1) {
		CloseHandle (th);
		return false;
	}
	bool ret = __set_thread_context (th, buf, size, dbg->bits);
	// Always resume
	if (__resume_thread (th, dbg->bits) == -1) {
		ret = false;
	}
	CloseHandle (th);
	return ret;
}

int w32_attach(RDebug *dbg, int pid) {
	RIOW32Dbg *rio = dbg->user;
	HANDLE ph = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (!ph) {
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
}

int w32_detach(RDebug *dbg, int pid) {
	if (pid == -1 || dbg->pid != pid) {
		return false;
	}
	RIOW32Dbg *rio = dbg->user;
	bool ret = false;
	if (rio->debug) {
		ret = DebugActiveProcessStop (pid);
	}
	CloseHandle (rio->ph);
	rio->ph = NULL;
	rio->debug = false;
	return ret;
}

int w32_select(RDebug *dbg, int pid, int tid) {
	RIOW32Dbg *rio = dbg->user;
	if (rio->ph) {
		return true;
	}
	// hack to support w32dbg:// and attach://
	DEBUG_EVENT de;
	de.dwProcessId = pid;
	de.dwThreadId = tid;
	bool cont = true;
	do {
		if ((cont = ContinueDebugEvent (de.dwProcessId, de.dwThreadId, DBG_CONTINUE))) {
			if ((cont = WaitForDebugEvent (&de, wait_time))) {
				switch (de.dwDebugEventCode) {
				//case CREATE_PROCESS_DEBUG_EVENT:
				case CREATE_THREAD_DEBUG_EVENT:
					cont = false;
					break;
				case LOAD_DLL_DEBUG_EVENT:
					{
						HANDLE hf = de.u.LoadDll.hFile;
						if (hf && hf != INVALID_HANDLE_VALUE) {
							CloseHandle (hf);
						}
					} break;
#if 0
				case EXCEPTION_DEBUG_EVENT:
					// TODO: check for the type of exception?
					cont = false;
					break;
#endif
				default:
					eprintf ("w32_select/Unhandled debug event %d\n", de.dwDebugEventCode);
					break;
				}
			}
		}
	} while (cont);
	rio->ph = OpenProcess (PROCESS_ALL_ACCESS, FALSE, pid);
	if (!rio->ph) {
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
		if (WaitForSingleObject (rio->ph, wait_time) != WAIT_OBJECT_0) {
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
			__get_w32_excep_name(code),
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
		goto err_get_file_name_from_handle;
	}
	TCHAR temp_buffer[512];
	/* Translate path with device name to drive letters. */
	if (!GetLogicalDriveStrings (sizeof (temp_buffer) - 1, temp_buffer)) {
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
					_sntprintf (temp_filename, MAX_PATH, TEXT ("%s%s"),
						drive, filename + name_length);
					_tcsncpy (filename, temp_filename,
						_tcslen (temp_filename) + 1);
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

LPVOID lstLib = 0;
PLIB_ITEM lstLibPtr = 0;

#if 0
static char *__r_debug_get_dll() {
	return lstLibPtr->Path;
}
#endif

static PLIB_ITEM __r_debug_get_lib_item() {
	return lstLibPtr;
}

#define PLIB_MAX 512

static void __r_debug_lstLibAdd(DWORD pid, LPVOID lpBaseOfDll, HANDLE hFile, char *dllname) {
	if (lstLib == 0) {
		lstLib = VirtualAlloc (0, PLIB_MAX * sizeof (LIB_ITEM), MEM_COMMIT, PAGE_READWRITE);
	}
	lstLibPtr = (PLIB_ITEM)lstLib;
	for (int x = 0; x < PLIB_MAX; x++) {
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
			strncpy (lstLibPtr->Name, dllname + i + 1, n - i);
			return;
		}
		lstLibPtr++;
	}
	eprintf ("__r_debug_lstLibAdd: Cannot find slot\n");
}

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

LPVOID lstThread = 0;
PTHREAD_ITEM lstThreadPtr = 0;
static PTHREAD_ITEM __r_debug_get_thread_item() {
	return lstThreadPtr;
}

#define PTHREAD_MAX 1024

static void __r_debug_lstThreadAdd(DWORD pid, DWORD tid, HANDLE hThread, LPVOID lpThreadLocalBase, LPVOID lpStartAddress, BOOL bFinished) {
	PVOID startAddress = 0;
	if (lstThread == 0) {
		lstThread = VirtualAlloc (0, PTHREAD_MAX * sizeof (THREAD_ITEM), MEM_COMMIT, PAGE_READWRITE);
	}
	lstThreadPtr = (PTHREAD_ITEM)lstThread;
	for (int x = 0; x < PTHREAD_MAX; x++) {
		if (!lstThreadPtr->tid) {
			lstThreadPtr->pid = pid;
			lstThreadPtr->tid = tid;
			lstThreadPtr->bFinished = bFinished;
			lstThreadPtr->hThread = hThread;
			lstThreadPtr->lpThreadLocalBase = lpThreadLocalBase;
			lstThreadPtr->lpStartAddress = lpStartAddress;
			if (w32_NtQueryInformationThread (hThread, 0x9 /*ThreadQuerySetWin32StartAddress*/, &startAddress, sizeof (PVOID), NULL) == 0) {
				lstThreadPtr->lpThreadEntryPoint = startAddress;
			}
			return;
		}
		lstThreadPtr++;
	}
	eprintf ("__r_debug_lstThreadAdd: Cannot find slot\n");
}

static void *__r_debug_findthread(int pid, int tid) {
	PTHREAD_ITEM threadPtr = NULL;
	if (lstThread) {
		threadPtr = (PTHREAD_ITEM)lstThread;
		while (threadPtr->tid != 0) {
			if (threadPtr->pid == pid) {
				if (threadPtr->tid == tid) {
					return ((void*)threadPtr);
				}
			}
			threadPtr = (PTHREAD_ITEM)((ULONG_PTR)threadPtr + sizeof (THREAD_ITEM));
		}
	}
	return NULL;
}

int w32_dbg_wait(RDebug *dbg, int pid) {
	DEBUG_EVENT de;
	int tid, next_event = 0;
	char *dllname = NULL;
	int ret = R_DEBUG_REASON_UNKNOWN;
	static int exited_already = 0;
	/* handle debug events */
	do {
		/* do not continue when already exited but still open for examination */
		if (exited_already == pid) {
			return -1;
		}
		memset (&de, 0, sizeof (DEBUG_EVENT));
		if (!WaitForDebugEvent (&de, INFINITE)) {
			r_sys_perror ("w32_dbg_wait/WaitForDebugEvent");
			return -1;
		}
		tid = de.dwThreadId;
		pid = de.dwProcessId;
		dbg->tid = tid;
		dbg->pid = pid;
		/* TODO: DEBUG_CONTROL_C */
		switch (de.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			//TODO: replace w32_h2t calls to w32_thread_list to get tid
			/*eprintf ("(%d) created process (%d:%p)\n",
				pid, w32_h2t (de.u.CreateProcessInfo.hProcess),
				de.u.CreateProcessInfo.lpStartAddress);*/
			w32_continue (dbg, pid, tid, -1);
			next_event = 1;
			ret = R_DEBUG_REASON_NEW_PID;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) Process %d exited with exit code %d\n", (int)de.dwProcessId, (int)de.dwProcessId,
				(int)de.u.ExitProcess.dwExitCode);
			//debug_load();
			next_event = 0;
			exited_already = pid;
			ret = R_DEBUG_REASON_EXIT_PID;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			//eprintf ("(%d) Created thread %d (start @ %p)\n", pid, tid, de.u.CreateThread.lpStartAddress);
			__r_debug_lstThreadAdd (pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, FALSE);
			//w32_continue (dbg, pid, tid, -1);
			ret = R_DEBUG_REASON_NEW_TID;
			next_event = 0;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//eprintf ("(%d) Finished thread %d\n", pid, tid);
			lstThreadPtr = (PTHREAD_ITEM)__r_debug_findthread (pid, tid);
			if (lstThreadPtr) {
				lstThreadPtr->bFinished = TRUE;
				lstThreadPtr->dwExitCode = de.u.ExitThread.dwExitCode;
			} else {
				__r_debug_lstThreadAdd (pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, TRUE);
			}
			//w32_continue (dbg, pid, tid, -1);
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_TID;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			dllname = __get_file_name_from_handle (de.u.LoadDll.hFile);
			//eprintf ("(%d) Loading library at %p (%s)\n",pid, de.u.LoadDll.lpBaseOfDll, dllname ? dllname : "no name");
			__r_debug_lstLibAdd (pid,de.u.LoadDll.lpBaseOfDll, de.u.LoadDll.hFile, dllname);
			if (dllname) {
				free (dllname);
			}
			next_event = 0;
			ret = R_DEBUG_REASON_NEW_LIB;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//eprintf ("(%d) Unloading library at %p\n", pid, de.u.UnloadDll.lpBaseOfDll);
			lstLibPtr = (PLIB_ITEM)__r_debug_findlib (de.u.UnloadDll.lpBaseOfDll);
			if (lstLibPtr != NULL) {
				lstLibPtr->hFile = INVALID_HANDLE_VALUE;
			} else {
				__r_debug_lstLibAdd (pid, de.u.UnloadDll.lpBaseOfDll, INVALID_HANDLE_VALUE, "not cached");
				if (dllname)
					free (dllname);
			}
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_LIB;
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			eprintf ("(%d) Debug string\n", pid);

			w32_continue (dbg, pid, tid, -1);
			next_event = 1;
			break;
		case RIP_EVENT:
			eprintf ("(%d) RIP event\n", pid);
			w32_continue (dbg, pid, tid, -1);
			next_event = 1;
			// XXX unknown ret = R_DEBUG_REASON_TRAP;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
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
					w32_continue (dbg, pid, tid, -1);
				}
			}
			break;
		default:
			eprintf ("(%d) unknown event: %d\n", pid, de.dwDebugEventCode);
			return -1;
		}
	} while (next_event);
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
	DWORD continue_status = (sig == DBG_EXCEPTION_NOT_HANDLED)
		? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
	if (!ContinueDebugEvent (pid, tid, continue_status)) {
		r_sys_perror ("w32_continue/ContinueDebugEvent");
		return false;
	}
	return tid;
}

RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size) {
	RIOW32Dbg *rio = dbg->user;
	LPVOID base = VirtualAllocEx (rio->ph, (LPVOID)addr, (SIZE_T)size, MEM_COMMIT, PAGE_READWRITE);
	if (!base) {
		r_sys_perror ("w32_map_alloc/VirtualAllocEx\n");
		return NULL;
	}
	r_debug_map_sync (dbg);
	return r_debug_map_get (dbg, (ut64)base);
}

int w32_map_dealloc(RDebug *dbg, ut64 addr, int size) {
	RIOW32Dbg *rio = dbg->user;
	if (!VirtualFreeEx (rio->ph, (LPVOID)addr, (SIZE_T)size, MEM_DECOMMIT)) {
		r_sys_perror ("w32_map_dealloc/VirtualFreeEx\n");
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
	return VirtualProtectEx (rio->ph, (LPVOID)(size_t)addr,
		size, __io_perms_to_prot (perms), &old);
}

static const char *__resolve_path(HANDLE ph) {
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
	if (th == INVALID_HANDLE_VALUE) {
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
		if (!ph) {
			path = __resolve_path (ph);
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

static void __w32_info_user(RDebug *dbg, RDebugInfo *rdi) {
	HANDLE h_tok = NULL;
	DWORD tok_len = 0;
	PTOKEN_USER tok_usr = NULL;
	LPTSTR usr = NULL, usr_dom = NULL;
	DWORD usr_len = 512;
	DWORD usr_dom_len = 512;
	SID_NAME_USE snu = {0};
	RIOW32Dbg *rio = dbg->user;

	if (!OpenProcessToken (rio->ph, TOKEN_QUERY, &h_tok)) {
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
	usr = (LPTSTR)malloc (usr_len);
	if (!usr) {
		perror ("__w32_info_user/malloc usr");
		goto err___w32_info_user;
	}
	*usr = '\0';
	usr_dom = (LPTSTR)malloc (usr_dom_len);
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
	rdi->exe = __resolve_path (rio->ph);
#if 0
	HANDLE ph = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, dbg->pid);
	if (!ph) {
		r_sys_perror ("__w32_info_exe/OpenProcess");
		return;
	}
	rdi->exe = __resolve_path (ph);
	CloseHandle (ph);
#endif
}

RDebugInfo *w32_info(RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->lib = (void *) __r_debug_get_lib_item();
	rdi->thread = (void *)__r_debug_get_thread_item ();
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

static RDebugPid *__build_debug_pid(int pid, HANDLE ph, const char* name) {
	char *path = NULL;
	int uid = -1;
	if (!ph) {
		ph = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (ph) {
			path = __resolve_path (ph);
			DWORD sid;
			if (ProcessIdToSessionId (pid, &sid)) {
				uid = sid;
			}
			CloseHandle (ph);
		} else {
			return NULL;
		}
	} else {
		path = __resolve_path (ph);
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
				RDebugPid *dbg_pid = __build_debug_pid (pe.th32ProcessID, b ? rio->ph : NULL, pe.szExeFile);
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
	RList *ret;
	int i;
	HANDLE ph;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	NTSTATUS status;
	ULONG handleInfoSize = 0x10000;
	LPVOID buff;
	if (!(ph = OpenProcess (PROCESS_DUP_HANDLE, FALSE, pid))) {
		r_sys_perror ("win_desc_list/OpenProcess");
		return NULL;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc (handleInfoSize);
	#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
	#define SystemHandleInformation 16
	while ((status = w32_NtQuerySystemInformation (SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc (handleInfo, handleInfoSize *= 2);
	if (status) {
		r_sys_perror ("win_desc_list/NtQuerySystemInformation");
		return NULL;
	}
	ret = r_list_new ();
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
		if (w32_NtQueryObject (dupHandle, 1, objectNameInfo, 0x1000, &returnLength)) {
			objectNameInfo = realloc (objectNameInfo, returnLength);
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
			buff = malloc ((objectName.Length / 2) + 1);
			wcstombs (buff, objectName.Buffer, objectName.Length / 2);
			desc = r_debug_desc_new (handle.Handle, buff, 0, '?', 0);
			if (!desc) {
				break;
			}
			r_list_append (ret, desc);
			free (buff);
		} else {
			buff = malloc ((objectTypeInfo->Name.Length / 2) + 1);
			wcstombs (buff, objectTypeInfo->Name.Buffer, objectTypeInfo->Name.Length);
			desc = r_debug_desc_new (handle.Handle, buff, 0, '?', 0);
			if (!desc) {
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
