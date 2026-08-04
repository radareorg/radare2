/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_userconf.h>
#include <r_util.h>

#if R2__WINDOWS__ || __MINGW32__
#include <windows.h>

#if 1
static DWORD(*w32_GetThreadId)(HANDLE) = NULL; // Vista
static DWORD(*w32_GetProcessId)(HANDLE) = NULL; // XP
// fpu access API
static BOOL(*w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
// static BOOL (*w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64) = NULL;

typedef void (WINAPI *W32CondInit)(PCONDITION_VARIABLE);
typedef void (WINAPI *W32CondSignal)(PCONDITION_VARIABLE);
typedef BOOL (WINAPI *W32CondWait)(PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD);
static struct {
	bool initialized;
	bool available;
	W32CondInit init;
	W32CondSignal signal;
	W32CondSignal signal_all;
	W32CondWait wait;
} w32_cond;
#endif

static inline HANDLE w32_loadlib(const char *name, const char *libname) {
	HANDLE lib = GetModuleHandle (TEXT (name));
	if (!lib) {
		lib = LoadLibrary (TEXT (libname));
		if (!lib) {
			R_LOG_ERROR ("Cannot load %s to resolve %s. Aborting", libname, name);
			return (HANDLE)(size_t)0;
		}
	}
	return lib;
}

static bool w32_cond_init(void) {
	if (!w32_cond.initialized) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		if (lib) {
			w32_cond.init = (W32CondInit) GetProcAddress (lib, W32_TCALL ("InitializeConditionVariable"));
			w32_cond.signal = (W32CondSignal) GetProcAddress (lib, W32_TCALL ("WakeConditionVariable"));
			w32_cond.signal_all = (W32CondSignal) GetProcAddress (lib, W32_TCALL ("WakeAllConditionVariable"));
			w32_cond.wait = (W32CondWait) GetProcAddress (lib, W32_TCALL ("SleepConditionVariableCS"));
		}
		w32_cond.available = w32_cond.init && w32_cond.signal
			&& w32_cond.signal_all && w32_cond.wait;
		w32_cond.initialized = true;
	}
	return w32_cond.available;
}

R_API bool r_w32_has_condition_variables(void) {
	return w32_cond_init ();
}

R_API FARPROC r_w32_InitializeConditionVariable(PCONDITION_VARIABLE a) {
	if (!w32_cond_init ()) {
		return NULL;
	}
	w32_cond.init (a);
	return (FARPROC)w32_cond.init;
}

R_API FARPROC r_w32_WakeConditionVariable(PCONDITION_VARIABLE a) {
	if (!w32_cond_init ()) {
		return NULL;
	}
	w32_cond.signal (a);
	return (FARPROC)w32_cond.signal;
}

R_API FARPROC r_w32_WakeAllConditionVariable(PCONDITION_VARIABLE a) {
	if (!w32_cond_init ()) {
		return NULL;
	}
	w32_cond.signal_all (a);
	return (FARPROC)w32_cond.signal_all;
}

R_API BOOL r_w32_SleepConditionVariableCS(PCONDITION_VARIABLE a, PCRITICAL_SECTION b, DWORD c) {
	return w32_cond_init () ? w32_cond.wait (a, b, c) : FALSE;
}

R_API BOOL r_w32_ProcessIdToSessionId(DWORD a, DWORD *b) {
	static BOOL (WINAPI *x)(DWORD, DWORD*) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (BOOL (WINAPI *)(DWORD, DWORD*)) GetProcAddress (lib, W32_TCALL ("ProcessIdToSessionId"));
	}
	return x? x (a, b): FALSE;
}

R_API NTSTATUS r_w32_NtQuerySystemInformation(ULONG a, PVOID b, ULONG c, PULONG d) {
	static NTSTATUS (WINAPI *x)(ULONG, PVOID, ULONG, PULONG) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("ntdll", "ntdll.dll");
		x = (NTSTATUS (WINAPI *)(ULONG, PVOID, ULONG, PULONG)) GetProcAddress (lib, W32_TCALL ("NtQuerySystemInformation"));
	}
	return x? x (a, b, c, d): 0;
}

// XP1
R_API BOOL r_w32_DebugBreakProcess(HANDLE a) {
	static BOOL (WINAPI *x)(HANDLE) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (BOOL (WINAPI *)(HANDLE)) GetProcAddress (lib, W32_TCALL ("DebugBreakProcess"));
	}
	return x? x (a): false;
}

R_API BOOL r_w32_SetXStateFeaturesMask(PCONTEXT a, DWORD64 b) {
	static BOOL (WINAPI *x)(PCONTEXT, DWORD64) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (BOOL (WINAPI *)(PCONTEXT, DWORD64)) GetProcAddress (lib, W32_TCALL ("SetXStateFeaturesMask"));
	}
	return x? x (a, b): 0;
}

R_API PVOID r_w32_LocateXStateFeature(PCONTEXT a, DWORD b, PDWORD c) {
	static PVOID (WINAPI *x)(PCONTEXT, DWORD, PDWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (PVOID (WINAPI *)(PCONTEXT, DWORD, PDWORD)) GetProcAddress (lib, W32_TCALL ("LocateXStateFeature"));
	}
	return x? x (a, b, c): 0;
}

R_API BOOL r_w32_GetXStateFeaturesMask(PCONTEXT a, PDWORD64 b) {
	static BOOL (WINAPI *x)(PCONTEXT, PDWORD64) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (BOOL (WINAPI *)(PCONTEXT, PDWORD64)) GetProcAddress (lib, W32_TCALL ("GetXStateFeaturesMask"));
	}
	return x? x (a, b): 0;
}

R_API NTSTATUS r_w32_NtDuplicateObject(HANDLE a, HANDLE b, HANDLE c, PHANDLE d, ACCESS_MASK e, ULONG f, ULONG g) {
	static NTSTATUS (WINAPI *x)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("ntdll", "ntdll.dll");
		x = (NTSTATUS (WINAPI *)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)) GetProcAddress (lib, W32_TCALL ("NtDuplicateObject"));
	}
	return x? x (a, b, c, d, e, f, g): 0;
}

// api to retrieve YMM from w7 sp1
R_API ut64 r_w32_GetEnabledXStateFeatures(void) {
	static ut64 (WINAPI *x)(void) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (ut64 (WINAPI *)(void)) GetProcAddress (lib, W32_TCALL ("GetEnabledXStateFeatures"));
	}
	return x? x (): 0;
}

R_API BOOL r_w32_InitializeContext(PVOID a, DWORD b, PCONTEXT* c, PDWORD d) {
	static BOOL (WINAPI *x) (PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("ntdll", "ntdll.dll");
		x = (BOOL (WINAPI *) (PVOID, DWORD, PCONTEXT*, PDWORD))
			GetProcAddress (lib, W32_TCALL ("InitializeContext"));
	}
	return x? x (a, b, c, d): 0;
}

R_API NTSTATUS r_w32_NtQueryInformationThread(HANDLE a, ULONG b, PVOID c, ULONG d, PULONG e) {
	static NTSTATUS (WINAPI *x)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("ntdll", "ntdll.dll");
		x = (NTSTATUS (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
			GetProcAddress (lib, W32_TCALL ("NtQueryInformationThread"));
	}
	return x? x (a, b, c, d, e): 0;
}

// Requires Windows XP
#if 0
DWORD GetModuleFileNameExA(
  [in]           HANDLE  hProcess,
  [in, optional] HMODULE hModule,
  [out]          LPSTR   lpFilename,
  [in]           DWORD   nSize
);
#endif
R_API DWORD r_w32_GetModuleFileNameEx(HANDLE a, HMODULE b, LPSTR c, DWORD d) {
	// requires windows XP, and its important to note its STDCALL for 32bit compat
	// return GetModuleFileNameExA (a,b,c,d);
	static DWORD (WINAPI *x)(HANDLE, HMODULE, LPSTR, DWORD) = NULL; // &GetModuleFileNameExA;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		if (lib != INVALID_HANDLE_VALUE) {
			x = (DWORD (WINAPI *)(HANDLE, HMODULE, LPSTR, DWORD))
				GetProcAddress (lib, W32_TCALL ("GetModuleFileNameEx"));
		}
		if (!x) {
			lib = w32_loadlib ("psapi", "psapi.dll");
			if (lib != INVALID_HANDLE_VALUE) {
				x = (DWORD (WINAPI *)(HANDLE, HMODULE, LPSTR, DWORD))
					GetProcAddress (lib, W32_TCALL ("GetModuleFileNameEx"));
			}
		}
	}
	return x? x (a, b, c, d): 0;
}

R_API BOOL r_w32_CancelSynchronousIo(HANDLE a) {
	static BOOL (WINAPI *x)(HANDLE) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (BOOL (WINAPI *)(HANDLE)) GetProcAddress (lib, W32_TCALL ("CancelSynchronousIo"));
	}
	return x? x (a): 0;
}

R_API BOOL r_w32_QueryFullProcessImageName(HANDLE h, DWORD p, LPSTR s, PDWORD l) {
	static DWORD (WINAPI *x)(HANDLE, DWORD, LPTSTR, PDWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (DWORD (WINAPI *)(HANDLE, DWORD, LPTSTR, PDWORD))
			GetProcAddress (lib, W32_TCALL ("QueryFullProcessImageName"));
	}
	return x? x (h, p, s, l): 0;
}

R_API DWORD r_w32_GetMappedFileName(HANDLE h, LPVOID p, LPSTR s, DWORD l) {
	static DWORD (WINAPI *x)(HANDLE, LPVOID, LPSTR, DWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("psapi", "psapi.dll");
		x = (DWORD (WINAPI *)(HANDLE, LPVOID, LPSTR, DWORD))
			GetProcAddress (lib, W32_TCALL ("GetMappedFileName"));
	}
	return x? x (h, p, s, l): 0;
}

R_API DWORD r_w32_NtQueryObject(HANDLE a, ULONG b, PVOID c, ULONG d, PULONG e) {
	static NTSTATUS (WINAPI *x)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("ntdll", "ntdll.dll");
		x = (NTSTATUS (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG)) GetProcAddress(lib,"NtQueryObject");
	}
	return x? x (a, b, c, d , e): 0;
}

R_API DWORD r_w32_GetProcessImageFileName(HANDLE a, LPSTR b, DWORD c) {
	static DWORD (WINAPI *x)(HANDLE,LPSTR,DWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("psapi", "psapi.dll");
		x = (DWORD (WINAPI *)(HANDLE, LPSTR, DWORD))
			GetProcAddress (lib, W32_TCALL ("GetProcessImageFileName"));
	}
	return x ? x (a, b, c): 0;
}

#if 0
// Requires Windows XP
static inline HANDLE r_w32_CreateToolhelp32Snapshot(DWORD a, DWORD b) {
	static HANDLE (*x)(DWORD, DWORD) = NULL;
	if (!x) {
		HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
		x = (DWORD (*)(HANDLE, LPVOID, LPTSTR, DWORD))
			GetProcAddress (lib, W32_TCALL ("CreateToolhelp32Snapshot"));
	}
	return x? x(h, p, s, l): INVALID_HANDLE_VALUE;
}
#endif

#if 0
static bool setup_debug_privileges(bool b) {
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
#endif

static bool setup_debug_privilege_noarg(void) {
	/////////////////////////////////////////////////////////
	//   Note: Enabling SeDebugPrivilege adapted from sample
	//     MSDN @ https://msdn.microsoft.com/en-us/library/aa446619%28VS.85%29.aspx
	// Enable SeDebugPrivilege
	bool ret = true;
	TOKEN_PRIVILEGES tokenPriv;
	HANDLE hToken = NULL;
	LUID luidDebug;
	if (!OpenProcessToken (GetCurrentProcess (),
			TOKEN_ADJUST_PRIVILEGES, &hToken))
		return false;

	if (!LookupPrivilegeValue (NULL, SE_DEBUG_NAME, &luidDebug)) {
		CloseHandle (hToken);
		return false;
	}

	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luidDebug;
	tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (AdjustTokenPrivileges (hToken, FALSE, &tokenPriv, 0, NULL, NULL) != FALSE) {
		if (tokenPriv.Privileges[0].Attributes == SE_PRIVILEGE_ENABLED) {
		//	eprintf ("PRIV ENABLED\n");
		}
		// Always successful, even in the cases which lead to OpenProcess failure
		//	eprintf ("Successfully changed token privileges.\n");
		// XXX if we cant get the token nobody tells?? wtf
	} else {
		R_LOG_ERROR ("Failed to change token privileges 0x%x", (int)GetLastError());
		ret = false;
	}
	CloseHandle (hToken);
	return ret;
}

R_API bool r_w32_init(void) {
	// escalate privs (required for win7/vista)
	setup_debug_privilege_noarg ();
	HANDLE lib = w32_loadlib ("kernel32", "kernel32.dll");
	w32_cond_init ();
	// lookup function pointers for portability
	// w32_OpenProcess = (HANDLE (*)(DWORD, BOOL, DWORD))GetProcAddress (lib, "OpenProcess");

	// w32_DebugBreakProcess = (BOOL (*)(HANDLE)) GetProcAddress (lib, "DebugBreakProcess");
	// Windows XP
	// w32_CreateToolhelp32Snapshot = (HANDLE (*)(DWORD, DWORD)) GetProcAddress (lib, "CreateToolhelp32Snapshot");
	// only windows vista :(
	w32_GetThreadId = (DWORD (*)(HANDLE))
		GetProcAddress (lib, "GetThreadId");
	// from xp1
	w32_GetProcessId = (DWORD (*)(HANDLE))
		GetProcAddress (lib, "GetProcessId");
	w32_InitializeContext = (BOOL (*) (PVOID, DWORD, PCONTEXT*, PDWORD))
		GetProcAddress(lib, "InitializeContext");
	// w32_GetXStateFeaturesMask = (BOOL (*) (PCONTEXT Context, PDWORD64)) GetProcAddress(lib, "GetXStateFeaturesMask");
	// w32_LocateXStateFeature = (PVOID (*) (PCONTEXT Context, DWORD ,PDWORD)) GetProcAddress(lib, "LocateXStateFeature");

	lib = w32_loadlib ("ntdll", "ntdll.dll");
	// w32_NtQuerySystemInformation = (NTSTATUS  (*)(ULONG, PVOID, ULONG, PULONG)) GetProcAddress (lib, "NtQuerySystemInformation");
	//w32_NtDuplicateObject = (NTSTATUS  (*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG)) GetProcAddress (lib, "NtDuplicateObject");
	// w32_NtQueryInformationThread = (NTSTATUS  (*)(HANDLE, ULONG, PVOID, ULONG, PULONG))
	//	GetProcAddress (lib, "NtQueryInformationThread");
	return true;
}

#else

R_API bool r_w32_init(void) {
	// nothing to do
	return false;
}

#endif
