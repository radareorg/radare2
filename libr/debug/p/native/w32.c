#undef UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winbase.h>
#include <psapi.h>
#include <tchar.h>

#ifndef NTSTATUS
#define NTSTATUS DWORD
#endif
#ifndef WINAPI
#define WINAPI
#endif

// XXX remove
#define WIN32_PI(x) x
#if 0
// list windows.. required to get list of windows for current pid and send kill signals
BOOL CALLBACK enumWindowsProc (HWND hwnd, LPARAM lParam) {

DWORD procid;

GetWindowThreadProcessId (hwnd, &procid);

if ((HANDLE)procid == g_hProc) { staticchar module[1024];
module[0] = 0;

if (g_softPhoneTitle.Size() > 0) { int rc = GetWindowText (hwnd, module, 1023);
module[rc] = 0;

}

if (IsWindow(hwnd) && ((g_appTitle.Size() == 0) || (g_appTitle.EqualsNoCase(module)))) {
g_hWnd = hwnd;

return (false);
}

}

return (true);
}

int

findApplicationWindow (void) {
g_hWnd = NULL;

EnumWindows (enumWindowsProc, 0);

return (0);
}
#endif

#if 0

1860 typedef struct _FLOATING_SAVE_AREA {
1861         DWORD   ControlWord;
1862         DWORD   StatusWord;
1863         DWORD   TagWord;
1864         DWORD   ErrorOffset;

1865         DWORD   ErrorSelector;
1866         DWORD   DataOffset;
1867         DWORD   DataSelector;
1868         BYTE    RegArea[80];
1869         DWORD   Cr0NpxState;
1870 } FLOATING_SAVE_AREA;

1871 typedef struct _CONTEXT {
1872         DWORD   ContextFlags;
1873         DWORD   Dr0;
1874         DWORD   Dr1;
1875         DWORD   Dr2;
1876         DWORD   Dr3;
1877         DWORD   Dr6;
1878         DWORD   Dr7;
1879         FLOATING_SAVE_AREA FloatSave;
1880         DWORD   SegGs;
1881         DWORD   SegFs;
1882         DWORD   SegEs;
1883         DWORD   SegDs;
1884         DWORD   Edi;
1885         DWORD   Esi;
1886         DWORD   Ebx;
1887         DWORD   Edx;
1888         DWORD   Ecx;
1889         DWORD   Eax;
1890         DWORD   Ebp;
1891         DWORD   Eip;
1892         DWORD   SegCs;
1893         DWORD   EFlags;
1894         DWORD   Esp;
1895         DWORD   SegSs;
1896         BYTE    ExtendedRegs[MAXIMUM_SUPPORTED_EXTENSION];
1897 } CONTEXT;
#endif

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_TYPE_INFORMATION
{
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

static void (*w32_GetModuleBaseName)(HANDLE, HMODULE, LPCSTR, int) = NULL;
static int (*w32_GetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, int) = NULL;
static BOOL (WINAPI *w32_DebugActiveProcessStop)(DWORD) = NULL;
static HANDLE (WINAPI *w32_openthread)(DWORD, BOOL, DWORD) = NULL;
static BOOL (WINAPI *w32_DebugBreakProcess)(HANDLE) = NULL;
static DWORD (WINAPI *w32_getthreadid)(HANDLE) = NULL; // Vista
static DWORD (WINAPI *w32_getprocessid)(HANDLE) = NULL; // XP
static HANDLE (WINAPI *w32_OpenProcess)(DWORD, BOOL, DWORD) = NULL;
static BOOL (WINAPI *w32_queryfullprocessimagename)(HANDLE, DWORD, LPCSTR, PDWORD) = NULL;
static DWORD (WINAPI *w32_GetMappedFileName)(HANDLE, LPVOID, LPCSTR, DWORD) = NULL;
static NTSTATUS (WINAPI *w32_ntquerysysteminformation)(ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_ntqueryinformationthread)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
static NTSTATUS (WINAPI *w32_ntduplicateobject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = NULL;
static NTSTATUS (WINAPI *w32_ntqueryobject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = NULL;
// fpu access API
static ut64 (WINAPI *w32_GetEnabledXStateFeatures)() = NULL;
static BOOL (WINAPI *w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD) = NULL;
static BOOL (WINAPI *w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64) = NULL;
static PVOID(WINAPI *w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD) = NULL;
static BOOL (WINAPI *w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64) = NULL;
static DWORD (WINAPI *w32_GetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD) = NULL;
static HANDLE (WINAPI *w32_CreateToolhelp32Snapshot)(DWORD, DWORD) = NULL;

#ifndef XSTATE_GSSE
#define XSTATE_GSSE 2
#endif

#ifndef XSTATE_LEGACY_SSE
#define XSTATE_LEGACY_SSE 1
#endif

#if defined(XSTATE_MASK_GSSE) && defined (MINGW32)
#undef XSTATE_MASK_GSSE
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
static bool w32dbg_SeDebugPrivilege() {
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

static int w32_dbg_init() {
	HANDLE lib;

	/* escalate privs (required for win7/vista) */
	w32dbg_SeDebugPrivilege ();
	/* lookup function pointers for portability */
	w32_DebugActiveProcessStop = (BOOL (WINAPI *)(DWORD))
		GetProcAddress (GetModuleHandleA ("kernel32"),
				"DebugActiveProcessStop");
	w32_openthread = (HANDLE (WINAPI *)(DWORD, BOOL, DWORD))
		GetProcAddress (GetModuleHandleA ("kernel32"), "OpenThread");
	w32_OpenProcess = (HANDLE (WINAPI *)(DWORD, BOOL, DWORD))
		GetProcAddress (GetModuleHandleA ("kernel32"), "OpenProcess");
	w32_DebugBreakProcess = (BOOL (WINAPI *)(HANDLE))
		GetProcAddress (GetModuleHandleA ("kernel32"),
				"DebugBreakProcess");
	w32_CreateToolhelp32Snapshot = (HANDLE (WINAPI *)(DWORD, DWORD))
		GetProcAddress (GetModuleHandleA ("kernel32"),
			       "CreateToolhelp32Snapshot");
	// only windows vista :(
	w32_getthreadid = (DWORD (WINAPI *)(HANDLE))
		GetProcAddress (GetModuleHandleA ("kernel32"), "GetThreadId");
	// from xp1
	w32_getprocessid = (DWORD (WINAPI *)(HANDLE))
		GetProcAddress (GetModuleHandleA ("kernel32"), "GetProcessId");
	w32_queryfullprocessimagename = (BOOL (WINAPI *)(HANDLE, DWORD, LPCSTR, PDWORD))
		GetProcAddress (GetModuleHandleA ("kernel32"), "QueryFullProcessImageNameA");
	// api to retrieve YMM from w7 sp1
	w32_GetEnabledXStateFeatures = (ut64 (WINAPI *) ())
		GetProcAddress(GetModuleHandleA ("kernel32"), "GetEnabledXStateFeatures");
	w32_InitializeContext = (BOOL (WINAPI *) (PVOID, DWORD, PCONTEXT*, PDWORD))
		GetProcAddress(GetModuleHandleA ("kernel32"), "InitializeContext");
	w32_GetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, PDWORD64))
		GetProcAddress(GetModuleHandleA ("kernel32"), "GetXStateFeaturesMask");
	w32_LocateXStateFeature = (PVOID (WINAPI *) (PCONTEXT Context, DWORD ,PDWORD))
		GetProcAddress(GetModuleHandleA ("kernel32"), "LocateXStateFeature");
	w32_SetXStateFeaturesMask = (BOOL (WINAPI *) (PCONTEXT Context, DWORD64))
		GetProcAddress(GetModuleHandleA ("kernel32"), "SetXStateFeaturesMask");
	lib = LoadLibraryA ("psapi.dll");
	if(!lib) {
		eprintf ("Cannot load psapi.dll. Aborting\n");
		return false;
	}
	w32_GetMappedFileName = (DWORD (WINAPI *)(HANDLE, LPVOID, LPCSTR, DWORD))
		GetProcAddress (lib, "GetMappedFileNameA");
	w32_GetModuleBaseName = (void (*)(HANDLE, HMODULE, LPCSTR, int))
		GetProcAddress (lib, "GetModuleBaseNameA");
	w32_GetModuleInformation = (int (*)(HANDLE, HMODULE, LPMODULEINFO, int))
		GetProcAddress (lib, "GetModuleInformation");
	w32_GetModuleFileNameEx = (DWORD (WINAPI *)(HANDLE, HMODULE, LPTSTR, DWORD))
		GetProcAddress (lib, "GetModuleFileNameExA");

	lib=LoadLibraryA("ntdll.dll");
	w32_ntquerysysteminformation = (NTSTATUS  (WINAPI *)(ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQuerySystemInformation");
	w32_ntduplicateobject = (NTSTATUS  (WINAPI *)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG))
		GetProcAddress (lib, "NtDuplicateObject");
	w32_ntqueryobject = (NTSTATUS  (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress(lib,"NtQueryObject");
	w32_ntqueryinformationthread = (NTSTATUS  (WINAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
		GetProcAddress (lib, "NtQueryInformationThread");
	if (!w32_DebugActiveProcessStop || !w32_openthread || !w32_DebugBreakProcess ||
	    !w32_GetModuleBaseName || !w32_GetModuleInformation) {
		// OOPS!
		eprintf ("debug_init_calls:\n"
			"DebugActiveProcessStop: 0x%p\n"
			"OpenThread: 0x%p\n"
			"DebugBreakProcess: 0x%p\n"
			"GetThreadId: 0x%p\n",
			w32_DebugActiveProcessStop, w32_openthread, w32_DebugBreakProcess, w32_getthreadid);
		return false;
	}
	return true;
}

#if 0
static HANDLE w32_t2h(pid_t tid) {
	TH_INFO *th = get_th (tid);
	if(!th) {
		/* refresh thread list */
		w32_dbg_threads (tid);

		/* try to search thread */
		if(!(th = get_th (tid)))
			return NULL;
	}
	return th->ht;
}
#endif

inline static int w32_h2t(HANDLE h) {
	if (w32_getthreadid != NULL) // >= Windows Vista
		return w32_getthreadid (h);
	if (w32_getprocessid != NULL) // >= Windows XP1
		return w32_getprocessid (h);
	return (int)(size_t)h; // XXX broken
}

static inline int w32_h2p(HANDLE h) {
	return w32_getprocessid (h);
}

static int w32_first_thread(int pid) {
	HANDLE th;
	HANDLE thid;
	THREADENTRY32 te32;
	te32.dwSize = sizeof (THREADENTRY32);

	if (!w32_openthread) {
		eprintf("w32_thread_list: no w32_openthread?\n");
		return -1;
	}
	th = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, pid);
	if (th == INVALID_HANDLE_VALUE) {
		eprintf ("w32_thread_list: invalid handle\n");
		return -1;
	}
	if (!Thread32First (th, &te32)) {
		CloseHandle (th);
		eprintf ("w32_thread_list: no thread first\n");
		return -1;
	}
	do {
		/* get all threads of process */
		if (te32.th32OwnerProcessID == pid) {
			thid = w32_openthread (THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (!thid) {
				r_sys_perror ("w32_first_thread/OpenThread");
				goto err_load_th;
			}
			CloseHandle (th);
			return te32.th32ThreadID;
		}
	} while (Thread32Next (th, &te32));
err_load_th:
	eprintf ("Could not find an active thread for pid %d\n", pid);
	CloseHandle (th);
	return pid;
}

static char *get_w32_excep_name(unsigned long code) {
	char *desc;
	switch (code) {
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
		desc = "access violation";
		break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		desc = "array bounds exceeded";
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		desc = "illegal instruction";
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		desc = "divide by zero";
		break;
	case EXCEPTION_STACK_OVERFLOW:
		desc = "stack overflow";
		break;
	default:
		desc = "unknown";
	}

	return desc;
}

static int debug_exception_event (DEBUG_EVENT *de) {
	unsigned long code = de->u.Exception.ExceptionRecord.ExceptionCode;
	switch (code) {
	case EXCEPTION_BREAKPOINT:
		break;
	case EXCEPTION_SINGLE_STEP:
		break;
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
		eprintf ("(%d) Fatal exception (%s) in thread %d\n",
			(int)de->dwProcessId, 
			get_w32_excep_name(code),
			(int)de->dwThreadId);
		break;
#if __MINGW64__ || _WIN64
	/* STATUS_WX86_BREAKPOINT */
	case 0x4000001f:
		eprintf ("(%d) WOW64 loaded.\n", (int)de->dwProcessId);
		return 1;
#endif
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

static char *get_file_name_from_handle (HANDLE handle_file) {
	HANDLE handle_file_map;
	CHAR *filename = NULL;

	DWORD file_size_high = 0;
	DWORD file_size_low = GetFileSize (handle_file, &file_size_high);
	if (file_size_low == 0 && file_size_high == 0) {
		return NULL;
	}

	handle_file_map = CreateFileMappingA (handle_file, NULL, PAGE_READONLY, 0, 1, NULL);

	if (!handle_file_map) {
		return NULL;
	}
	filename = malloc(MAX_PATH+1);

	/* Create a file mapping to get the file name. */
	void* map = MapViewOfFile (handle_file_map, FILE_MAP_READ, 0, 0, 1);

	if (!map) {
		free (filename);
		CloseHandle (handle_file_map);
		return NULL;
	}

	if (!w32_GetMappedFileName (GetCurrentProcess (),
		map,
		filename,
		MAX_PATH)) {

		free(filename);
		UnmapViewOfFile (map);
		CloseHandle (handle_file_map);
		return NULL;
	}

	/* Translate path with device name to drive letters. */
	CHAR temp_buffer[512];
	temp_buffer[0] = '\0';

	if (!GetLogicalDriveStringsA (511, temp_buffer)) {
		free (filename);
		UnmapViewOfFile (map);
		CloseHandle (handle_file_map);
		return NULL;
	}

	CHAR name[MAX_PATH];
	CHAR drive[3] =  " :";
	BOOL found = FALSE;
	CHAR *p = temp_buffer;
	do {
		/* Look up each device name */
		*drive = *p;
		if (QueryDosDeviceA (drive, name, MAX_PATH)) {
			size_t name_length = strlen (name);

			if (name_length < MAX_PATH) {
				found = strncmp (filename, name, name_length) == 0
					&& *(filename + name_length) == _T ('\\');

				if (found) {
					CHAR temp_filename[MAX_PATH];
					snprintf (temp_filename, MAX_PATH-1, "%s%s",
						drive, filename+name_length);
					strncpy (filename, temp_filename, MAX_PATH-1);
				}
			}
		}
		while (*p++);
	} while (!found && *p);

	UnmapViewOfFile (map);
	CloseHandle (handle_file_map);
	return filename;
}

typedef struct{
	int pid;
	HANDLE hFile;
	void* BaseOfDll;
	char Path[MAX_PATH];
	char Name[MAX_PATH];
} LIB_ITEM, *PLIB_ITEM;
LPVOID lstLib = 0;
PLIB_ITEM lstLibPtr = 0;
/*
static char * r_debug_get_dll() {
	return lstLibPtr->Path;
}
*/
static  PLIB_ITEM  r_debug_get_lib_item() {
	return lstLibPtr;
}
#define PLIB_MAX 512
static void r_debug_lstLibAdd(DWORD pid,LPVOID lpBaseOfDll, HANDLE hFile,char * dllname) {
	int x;
	if (lstLib == 0)
		lstLib = VirtualAlloc (0, PLIB_MAX * sizeof (LIB_ITEM), MEM_COMMIT, PAGE_READWRITE);
	lstLibPtr = (PLIB_ITEM)lstLib;
	for (x=0; x<PLIB_MAX; x++) {
		if (!lstLibPtr->hFile) {
			lstLibPtr->pid = pid;
			lstLibPtr->hFile = hFile; //DBGEvent->u.LoadDll.hFile;
			lstLibPtr->BaseOfDll = lpBaseOfDll;//DBGEvent->u.LoadDll.lpBaseOfDll;
			strncpy (lstLibPtr->Path,dllname,MAX_PATH-1);
			int i = strlen (dllname);
                        int n = i;
                        while(dllname[i] != '\\' && i >= 0) {
                             i--;
                        }
                        strncpy (lstLibPtr->Name, &dllname[i+1], n-i);
			return;
		}
		lstLibPtr++;
	}
	eprintf("r_debug_lstLibAdd: Cannot find slot\n");
}
static void * r_debug_findlib (void * BaseOfDll) {
	PLIB_ITEM libPtr = NULL;
	if (lstLib) {
		libPtr = (PLIB_ITEM)lstLib;
		while (libPtr->hFile != NULL) {
			if (libPtr->hFile != (HANDLE)-1)
				if (libPtr->BaseOfDll == BaseOfDll)
					return ((void*)libPtr);
			libPtr = (PLIB_ITEM)((ULONG_PTR)libPtr + sizeof (LIB_ITEM));
		}
	}
	return NULL;
}

// thread list
typedef struct {
	int pid;
	int tid;
	BOOL bFinished;
	HANDLE hThread;
	LPVOID lpThreadLocalBase;
	LPVOID lpStartAddress;
	PVOID lpThreadEntryPoint;
	DWORD dwExitCode;
} THREAD_ITEM, *PTHREAD_ITEM;
LPVOID lstThread = 0;
PTHREAD_ITEM lstThreadPtr = 0;
static  PTHREAD_ITEM  r_debug_get_thread_item () {
	return lstThreadPtr;
}
#define PTHREAD_MAX 1024
static void r_debug_lstThreadAdd (DWORD pid, DWORD tid, HANDLE hThread, LPVOID  lpThreadLocalBase, LPVOID lpStartAddress, BOOL bFinished) {
	int x;
	PVOID startAddress = 0;
	if (lstThread == 0)
		lstThread = VirtualAlloc (0, PTHREAD_MAX * sizeof (THREAD_ITEM), MEM_COMMIT, PAGE_READWRITE);
	lstThreadPtr = (PTHREAD_ITEM)lstThread;
	for (x = 0; x < PTHREAD_MAX; x++) {
		if (!lstThreadPtr->tid) {
			lstThreadPtr->pid = pid;
			lstThreadPtr->tid = tid;
			lstThreadPtr->bFinished = bFinished;
			lstThreadPtr->hThread = hThread;
			lstThreadPtr->lpThreadLocalBase = lpThreadLocalBase;
			lstThreadPtr->lpStartAddress = lpStartAddress;
			if (w32_ntqueryinformationthread (hThread, 0x9 /*ThreadQuerySetWin32StartAddress*/, &startAddress, sizeof (PVOID), NULL) == 0) {
				lstThreadPtr->lpThreadEntryPoint = startAddress;
			}
			return;
		}
		lstThreadPtr++;
	}
	eprintf ("r_debug_lstThreadAdd: Cannot find slot\n");
}

static void * r_debug_findthread (int pid, int tid) {
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

static int w32_dbg_wait(RDebug *dbg, int pid) {
	DEBUG_EVENT de;
	int tid, next_event = 0;
	unsigned int code;
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
		if (WaitForDebugEvent (&de, INFINITE) == 0) {
			r_sys_perror ("w32_dbg_wait/WaitForDebugEvent");
			return -1;
		}
		code = de.dwDebugEventCode;
		tid = de.dwThreadId;
		pid = de.dwProcessId;
		dbg->tid = tid;
		dbg->pid = pid;
		/* TODO: DEBUG_CONTROL_C */
		switch (code) {
		case CREATE_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) created process (%d:%p)\n",
				pid, w32_h2t (de.u.CreateProcessInfo.hProcess),
				de.u.CreateProcessInfo.lpStartAddress);
			r_debug_native_continue (dbg, pid, tid, -1);
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
			r_debug_lstThreadAdd (pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, FALSE);
			//r_debug_native_continue (dbg, pid, tid, -1);
			ret = R_DEBUG_REASON_NEW_TID;
			next_event = 0;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//eprintf ("(%d) Finished thread %d\n", pid, tid);
			lstThreadPtr = (PTHREAD_ITEM)r_debug_findthread (pid, tid);
			if (lstThreadPtr) {
				lstThreadPtr->bFinished = TRUE;
				lstThreadPtr->dwExitCode = de.u.ExitThread.dwExitCode;
			} else {
				r_debug_lstThreadAdd (pid, tid, de.u.CreateThread.hThread, de.u.CreateThread.lpThreadLocalBase, de.u.CreateThread.lpStartAddress, TRUE);
			}
			//r_debug_native_continue (dbg, pid, tid, -1);
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_TID;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			dllname = get_file_name_from_handle (de.u.LoadDll.hFile);
			//eprintf ("(%d) Loading library at %p (%s)\n",pid, de.u.LoadDll.lpBaseOfDll, dllname ? dllname : "no name");
			r_debug_lstLibAdd (pid,de.u.LoadDll.lpBaseOfDll, de.u.LoadDll.hFile, dllname);
			if (dllname) {
				free (dllname);
			}
			next_event = 0;
			ret = R_DEBUG_REASON_NEW_LIB;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//eprintf ("(%d) Unloading library at %p\n", pid, de.u.UnloadDll.lpBaseOfDll);
			lstLibPtr = (PLIB_ITEM)r_debug_findlib (de.u.UnloadDll.lpBaseOfDll);
			if (lstLibPtr != NULL) {
				lstLibPtr->hFile = (HANDLE)-1;
			} else {
				r_debug_lstLibAdd (pid, de.u.UnloadDll.lpBaseOfDll, (HANDLE)-1, "not cached");
				if (dllname)
					free (dllname);
			}
			next_event = 0;
			ret = R_DEBUG_REASON_EXIT_LIB;
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			eprintf ("(%d) Debug string\n", pid);
			r_debug_native_continue (dbg, pid, tid, -1);
			next_event = 1;
			break;
		case RIP_EVENT:
			eprintf ("(%d) RIP event\n", pid);
			r_debug_native_continue (dbg, pid, tid, -1);
			next_event = 1;
			// XXX unknown ret = R_DEBUG_REASON_TRAP;
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (de.u.Exception.ExceptionRecord.ExceptionCode) {
#if __MINGW64__ || _WIN64
			case 0x4000001f:
#endif
			case EXCEPTION_BREAKPOINT:
				ret = R_DEBUG_REASON_BREAKPOINT;
				next_event = 0;
				break;
			case EXCEPTION_SINGLE_STEP:
				ret = R_DEBUG_REASON_STEP;
				next_event = 0;
				break;
			default:
				if (!debug_exception_event (&de)) {
					ret = R_DEBUG_REASON_TRAP;
					next_event = 0;
				}
				else {
					next_event = 1;
					r_debug_native_continue (dbg, pid, tid, -1);
				}

			}
			break;
		default:
			eprintf ("(%d) unknown event: %d\n", pid, code);
			return -1;
		}
	} while (next_event);
	return ret;
}

static inline int is_pe_hdr(unsigned char *pe_hdr) {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)pe_hdr;
	IMAGE_NT_HEADERS *nt_headers;

	if (dos_header->e_magic==IMAGE_DOS_SIGNATURE) {
		nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
				+ dos_header->e_lfanew);
		if (nt_headers->Signature==IMAGE_NT_SIGNATURE)
			return 1;
	}
	return 0;
}

static HANDLE w32_open_thread (int pid, int tid) {
	HANDLE thread = w32_openthread (THREAD_ALL_ACCESS, 0, tid);
	if (thread == INVALID_HANDLE_VALUE) {
		r_sys_perror ("w32_open_thread/OpenThread");
	}
	return thread;
}

RList *w32_thread_list (int pid, RList *list) {
        HANDLE th;
        HANDLE thid;
        THREADENTRY32 te32;

        te32.dwSize = sizeof(THREADENTRY32);

	if (!w32_openthread) {
		eprintf("w32_thread_list: no w32_openthread?\n");
		return list;
	}
        th = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if(th == INVALID_HANDLE_VALUE || !Thread32First (th, &te32))
                goto err_load_th;
        do {
                /* get all threads of process */
                if (te32.th32OwnerProcessID == pid) {
			//te32.dwFlags);
                        /* open a new handler */
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
			thid = w32_openthread (THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
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
	return list;
}

static RDebugPid *build_debug_pid(PROCESSENTRY32 *pe) {
	HANDLE process = w32_OpenProcess (0x1000, //PROCESS_QUERY_LIMITED_INFORMATION,
		FALSE, pe->th32ProcessID);

	if (!process || !w32_queryfullprocessimagename) {
		return r_debug_pid_new (pe->szExeFile, pe->th32ProcessID, 0, 's', 0);
	}

	char image_name[MAX_PATH + 1];
	image_name[0] = '\0';
	DWORD length = MAX_PATH;

	if (w32_queryfullprocessimagename (process, 0,
		image_name, (PDWORD)&length)) {
		CloseHandle(process);
		return r_debug_pid_new (image_name, pe->th32ProcessID, 0, 's', 0);
	}

	CloseHandle(process);
	return r_debug_pid_new (pe->szExeFile, pe->th32ProcessID, 0, 's', 0);
}

RList *w32_pids (int pid, RList *list) {
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
	return list;
}

bool w32_terminate_process (RDebug *dbg, int pid) {
	HANDLE h_proc = w32_OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE , FALSE, pid);
	bool ret = false;
	if (!h_proc) {
		r_sys_perror ("w32_terminate_process/OpenProcess");
		goto err_w32_terminate_process;
	}
	/* stop debugging if we are still attached */
	if (w32_DebugActiveProcessStop) {
		w32_DebugActiveProcessStop (pid); //DebugActiveProcessStop (pid);
	}
	if (TerminateProcess (h_proc, 1) == 0) {
		r_sys_perror ("e32_terminate_process/TerminateProcess");
		goto err_w32_terminate_process;

	}
	/* wait up to one second to give the process some time to exit */
	DWORD ret_wait = WaitForSingleObject (h_proc, 1000);
	if (ret_wait == WAIT_FAILED) {
		r_sys_perror ("w32_terminate_process/WaitForSingleObject");
		goto err_w32_terminate_process;
	}
	if (ret_wait == WAIT_TIMEOUT) {
		eprintf ("(%d) Waiting for process to terminate timed out.\n", pid);
		goto err_w32_terminate_process;
	}
	ret = true;
err_w32_terminate_process:
	if (h_proc) {
		CloseHandle (h_proc);
	}
	return ret;
}

void w32_break_process (void *d) {
	RDebug *dbg = (RDebug *)d;
	HANDLE h_proc = w32_OpenProcess (PROCESS_ALL_ACCESS, FALSE, dbg->pid);
	if (!h_proc) {
		r_sys_perror ("w32_break_process/w32_OpenProcess");
		goto err_w32_break_process;
	}
	if (!w32_DebugBreakProcess (h_proc)) {
		r_sys_perror ("w32_break_process/w32_DebugBreakProcess");
		goto err_w32_break_process;
	}
err_w32_break_process:
	if (h_proc) {
		CloseHandle (h_proc);
	}
}

static int GetAVX (HANDLE hThread, ut128 * xmm, ut128 * ymm) {
	BOOL Success;
	int nRegs = 0, Index = 0;
	DWORD ContextSize = 0;
	DWORD FeatureLength = 0;
	ut64 FeatureMask = 0;
	ut128 * Xmm = NULL;
	ut128 * Ymm = NULL;
	void * buffer = NULL;
	PCONTEXT Context;
	if (w32_GetEnabledXStateFeatures == (ut64 (WINAPI *) ())-1) {
		return 0;
	}
	// Check for AVX extension
	FeatureMask = w32_GetEnabledXStateFeatures();
	if ((FeatureMask & XSTATE_MASK_AVX) == 0) {
		return 0;
	}
	Success = w32_InitializeContext(NULL, CONTEXT_ALL | CONTEXT_XSTATE, NULL, &ContextSize);
	if ((Success == TRUE) || (GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
		return 0;
	}
	buffer = malloc(ContextSize);
	if (buffer == NULL) {
		return 0;
	}
	Success = w32_InitializeContext(buffer, CONTEXT_ALL | CONTEXT_XSTATE, &Context, &ContextSize);
	if (Success == FALSE) {
		free(buffer);
		return 0;
	}
	Success = w32_SetXStateFeaturesMask(Context, XSTATE_MASK_AVX);
	if (Success == FALSE) {
		free(buffer);
		return 0;
	}
	Success = GetThreadContext(hThread, Context);
	if (Success == FALSE) {
		free(buffer);
		return 0;
	}
	Success = w32_GetXStateFeaturesMask(Context, &FeatureMask);
	if (Success == FALSE) {
		free(buffer);
		return 0;
	}
	Xmm = (ut128 *)w32_LocateXStateFeature(Context, XSTATE_LEGACY_SSE, &FeatureLength);
        nRegs = FeatureLength / sizeof(*Xmm);
	for (Index = 0; Index < nRegs; Index++) {
		ymm[Index].High = 0;
		xmm[Index].High = 0;
		ymm[Index].Low = 0;
		xmm[Index].Low = 0;
	}
	if (Xmm != NULL) {
		for (Index = 0; Index < nRegs; Index++) {
			xmm[Index].High = Xmm[Index].High;
			xmm[Index].Low = Xmm[Index].Low;
		}
	}
	if ((FeatureMask & XSTATE_MASK_AVX) != 0) {
		// check for AVX initialization and get the pointer.
		Ymm = (ut128 *)w32_LocateXStateFeature(Context, XSTATE_AVX, NULL);
		for (Index = 0; Index < nRegs; Index++) {
			ymm[Index].High = Ymm[Index].High;
			ymm[Index].Low = Ymm[Index].Low;
		}
	}
	free(buffer);
	return nRegs;
}

static void printwincontext(HANDLE hThread, CONTEXT * ctx) {
	ut128 xmm[16];
	ut128 ymm[16];
	ut80 st[8];
	ut64 mm[8];
	ut16 top = 0;
	int x = 0, nxmm = 0, nymm = 0;
#if __MINGW64__ || _WIN64
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", ctx->FltSave.ControlWord, ctx->FltSave.StatusWord);
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", ctx->MxCsr, ctx->FltSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", ctx->FltSave.ErrorOffset, ctx->FltSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", ctx->FltSave.ErrorSelector, ctx->FltSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].Low = ctx->FltSave.FloatRegisters[x].Low;
		st[x].High = (ut16)ctx->FltSave.FloatRegisters[x].High;
	}
	top = (ctx->FltSave.StatusWord & 0x3fff) >> 11;
	x = 0;
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
	eprintf ("ControlWord   = %08x StatusWord   = %08x\n", (ut32) ctx->FloatSave.ControlWord, (ut32) ctx->FloatSave.StatusWord);
	eprintf ("MxCsr         = %08x TagWord      = %08x\n", *(ut32 *)&ctx->ExtendedRegisters[24], (ut32)ctx->FloatSave.TagWord);
	eprintf ("ErrorOffset   = %08x DataOffset   = %08x\n", (ut32)ctx->FloatSave.ErrorOffset, (ut32)ctx->FloatSave.DataOffset);
	eprintf ("ErrorSelector = %08x DataSelector = %08x\n", (ut32)ctx->FloatSave.ErrorSelector, (ut32) ctx->FloatSave.DataSelector);
	for (x = 0; x < 8; x++) {
		st[x].High = (ut16) *((ut16 *)(&ctx->FloatSave.RegisterArea[x * 10] + 8));
		st[x].Low = (ut64)  *((ut64 *)&ctx->FloatSave.RegisterArea[x * 10]);
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
	nymm = GetAVX (hThread, &xmm, &ymm);
	if (nymm) {
		for (x = 0; x < nymm; x++) {
			eprintf ("Ymm%d: %016"PFMT64x" %016"PFMT64x" %016"PFMT64x" %016"PFMT64x"\n", x, ymm[x].High, ymm[x].Low, xmm[x].High, xmm[x].Low );
		}
	}
}

static int w32_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
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
		if (type == R_REG_TYPE_GPR) {
			if (size > sizeof (CONTEXT)) {
				size = sizeof (CONTEXT);
			}
			memcpy (buf, &ctx, size);
		} else {
			size = 0;
		}
	} else {
		r_sys_perror ("w32_reg_read/GetThreadContext");
		size = 0;
	}
	if (showfpu) {
		printwincontext (hThread, &ctx);
	}
	CloseHandle(hThread);
	return size;
}

static int w32_reg_write (RDebug *dbg, int type, const ut8* buf, int size) {
	BOOL ret = false;
	HANDLE thread;
#if _MSC_VER
	CONTEXT ctx;
#else
	CONTEXT ctx __attribute__((aligned (16)));
#endif
	thread = w32_open_thread (dbg->pid, dbg->tid);
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext (thread, &ctx);
	if (type == R_REG_TYPE_GPR) {
		if (size > sizeof (CONTEXT)) {
			size = sizeof (CONTEXT);
		}
		memcpy (&ctx, buf, size);
		ret = SetThreadContext (thread, &ctx)? true: false;
	}
	CloseHandle (thread);
	return ret;
}

static RDebugInfo* w32_info (RDebug *dbg, const char *arg) {
	RDebugInfo *rdi = R_NEW0 (RDebugInfo);
	rdi->status = R_DBG_PROC_SLEEP; // TODO: Fix this
	rdi->pid = dbg->pid;
	rdi->tid = dbg->tid;
	rdi->lib = (void *) r_debug_get_lib_item();
	rdi->thread = (void *)r_debug_get_thread_item ();
	rdi->uid = -1;// TODO
	rdi->gid = -1;// TODO
	rdi->cwd = NULL;
	rdi->exe = NULL;
	rdi->cmdline = NULL;
	rdi->libname = NULL;
	return rdi;
}

#include "maps/windows.c"
