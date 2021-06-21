/* radare - LGPL - Copyright 2009-2021 - pancake */

#include <r_userconf.h>
#include <r_util.h>

#if __WINDOWS__
#include <windows.h>

DWORD (*w32_GetProcessImageFileName)(HANDLE,LPSTR,DWORD) = NULL;
DWORD (*w32_GetModuleBaseName)(HANDLE, HMODULE, LPTSTR, DWORD) = NULL;
BOOL (*w32_GetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD) = NULL;
BOOL (*w32_DebugActiveProcessStop)(DWORD) = NULL;
HANDLE (*w32_OpenThread)(DWORD, BOOL, DWORD) = NULL;
BOOL (*w32_DebugBreakProcess)(HANDLE) = NULL;
DWORD (*w32_GetThreadId)(HANDLE) = NULL; // Vista
DWORD (*w32_GetProcessId)(HANDLE) = NULL; // XP
HANDLE (*w32_OpenProcess)(DWORD, BOOL, DWORD) = NULL;
BOOL (*w32_QueryFullProcessImageName)(HANDLE, DWORD, LPTSTR, PDWORD) = NULL;
DWORD (*w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD) = NULL;
NTSTATUS (*w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = NULL;
NTSTATUS (*w32_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
NTSTATUS (*w32_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = NULL;
NTSTATUS (*w32_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
// fpu access API
ut64 (*w32_GetEnabledXStateFeatures)(void) = NULL;
BOOL (*w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
BOOL (*w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64) = NULL;
PVOID (*w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD) = NULL;
BOOL (*w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64) = NULL;
DWORD (*w32_GetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD) = NULL;
HANDLE (*w32_CreateToolhelp32Snapshot)(DWORD, DWORD) = NULL;

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

static bool setup_debug_privilege_noarg(void) {
	/////////////////////////////////////////////////////////
	//   Note: Enabling SeDebugPrivilege adapted from sample
	//     MSDN @ http://msdn.microsoft.com/en-us/library/aa446619%28VS.85%29.aspx
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
		eprintf ("Failed to change token privileges 0x%x\n", (int)GetLastError());
		ret = false;
	}
	CloseHandle (hToken);
	return ret;
}


R_API bool r_w32_init(void) {
	HANDLE lib;
	if (w32_DebugActiveProcessStop) {
		return false;
	}

	// escalate privs (required for win7/vista)
	setup_debug_privilege_noarg ();

	// lookup function pointers for portability
	w32_DebugActiveProcessStop = (BOOL (*)(DWORD))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")),
				"DebugActiveProcessStop");
	w32_OpenThread = (HANDLE (*)(DWORD, BOOL, DWORD))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")), "OpenThread");
	w32_OpenProcess = (HANDLE (*)(DWORD, BOOL, DWORD))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")), "OpenProcess");
	w32_DebugBreakProcess = (BOOL (*)(HANDLE))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")),
				"DebugBreakProcess");
	w32_CreateToolhelp32Snapshot = (HANDLE (*)(DWORD, DWORD))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")),
			       "CreateToolhelp32Snapshot");
	// only windows vista :(
	w32_GetThreadId = (DWORD (*)(HANDLE))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")), "GetThreadId");
	// from xp1
	w32_GetProcessId = (DWORD (*)(HANDLE))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")), "GetProcessId");
	w32_QueryFullProcessImageName = (BOOL (*)(HANDLE, DWORD, LPTSTR, PDWORD))
		GetProcAddress (GetModuleHandle (TEXT ("kernel32")), W32_TCALL ("QueryFullProcessImageName"));
	// api to retrieve YMM from w7 sp1
	w32_GetEnabledXStateFeatures = (ut64 (*) ())
		GetProcAddress(GetModuleHandle (TEXT ("kernel32")), "GetEnabledXStateFeatures");
	w32_InitializeContext = (BOOL (*) (PVOID, DWORD, PCONTEXT*, PDWORD))
		GetProcAddress(GetModuleHandle (TEXT ("kernel32")), "InitializeContext");
	w32_GetXStateFeaturesMask = (BOOL (*) (PCONTEXT Context, PDWORD64))
		GetProcAddress(GetModuleHandle (TEXT ("kernel32")), "GetXStateFeaturesMask");
	w32_LocateXStateFeature = (PVOID (*) (PCONTEXT Context, DWORD ,PDWORD))
		GetProcAddress(GetModuleHandle (TEXT ("kernel32")), "LocateXStateFeature");
	w32_SetXStateFeaturesMask = (BOOL (*) (PCONTEXT Context, DWORD64))
		GetProcAddress(GetModuleHandle (TEXT ("kernel32")), "SetXStateFeaturesMask");
	lib = LoadLibrary (TEXT("psapi.dll"));
	if(!lib) {
		eprintf ("Cannot load psapi.dll. Aborting\n");
		return false;
	}
	w32_GetMappedFileName = (DWORD (*)(HANDLE, LPVOID, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetMappedFileName"));
	w32_GetModuleBaseName = (DWORD (*)(HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetModuleBaseName"));
	w32_GetProcessImageFileName = (DWORD (*)(HANDLE, LPSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetProcessImageFileName"));
	w32_GetModuleInformation = (BOOL (*)(HANDLE, HMODULE, LPMODULEINFO, DWORD))
		GetProcAddress (lib, "GetModuleInformation");
	w32_GetModuleFileNameEx = (DWORD (*)(HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (lib, W32_TCALL ("GetModuleFileNameEx"));
	lib = LoadLibrary (TEXT("ntdll.dll"));
	w32_NtQuerySystemInformation = (NTSTATUS  (*)(ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQuerySystemInformation");
	w32_NtDuplicateObject = (NTSTATUS  (*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG))
		GetProcAddress (lib, "NtDuplicateObject");
	w32_NtQueryObject = (NTSTATUS  (*)(HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress(lib,"NtQueryObject");
	w32_NtQueryInformationThread = (NTSTATUS  (*)(HANDLE, ULONG, PVOID, ULONG, PULONG))
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

#else

R_API bool r_w32_init(void) {
	// nothing to do
	return false;
}

#endif
