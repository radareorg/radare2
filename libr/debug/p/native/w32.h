#ifndef W32_H
#define W32_H
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
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
	int pid;
	HANDLE hFile;
	void* BaseOfDll;
	char Path[MAX_PATH];
	char Name[MAX_PATH];
} LIB_ITEM, *PLIB_ITEM;

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

DWORD (WINAPI *w32_GetModuleBaseName)(HANDLE, HMODULE, LPTSTR, DWORD);
BOOL (WINAPI *w32_GetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
BOOL (WINAPI *w32_DebugActiveProcessStop)(DWORD);
HANDLE (WINAPI *w32_OpenThread)(DWORD, BOOL, DWORD);
BOOL (WINAPI *w32_DebugBreakProcess)(HANDLE);
DWORD (WINAPI *w32_GetThreadId)(HANDLE); // Vista
DWORD (WINAPI *w32_GetProcessId)(HANDLE); // XP
HANDLE (WINAPI *w32_OpenProcess)(DWORD, BOOL, DWORD);
BOOL (WINAPI *w32_QueryFullProcessImageName)(HANDLE, DWORD, LPTSTR, PDWORD);
DWORD (WINAPI *w32_GetMappedFileName)(HANDLE, LPVOID, LPTSTR, DWORD);
NTSTATUS (WINAPI *w32_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
NTSTATUS (WINAPI *w32_NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
NTSTATUS (WINAPI *w32_NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSTATUS (WINAPI *w32_NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
// fpu access API
ut64 (WINAPI *w32_GetEnabledXStateFeatures)();
BOOL (WINAPI *w32_InitializeContext)(PVOID, DWORD, PCONTEXT*, PDWORD);
BOOL (WINAPI *w32_GetXStateFeaturesMask)(PCONTEXT Context, PDWORD64);
PVOID (WINAPI *w32_LocateXStateFeature)(PCONTEXT Context, DWORD, PDWORD);
BOOL (WINAPI *w32_SetXStateFeaturesMask)(PCONTEXT Context, DWORD64);
DWORD (WINAPI *w32_GetModuleFileNameEx)(HANDLE, HMODULE, LPTSTR, DWORD);
HANDLE (WINAPI *w32_CreateToolhelp32Snapshot)(DWORD, DWORD);

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
void w32_break_process(void *d);
bool w32_terminate_process(RDebug *dbg, int pid);
int w32_first_thread(int pid);
int w32_dbg_wait(RDebug *dbg, int pid);
RDebugInfo *w32_info(RDebug *dbg, const char *arg);
RList *w32_pids(int pid, RList *list);
RList *w32_thread_list(int pid, RList *list);
bool is_pe_hdr(unsigned char *pe_hdr);
#include "maps/windows_maps.h"
#endif