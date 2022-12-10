#ifndef R_W32_H
#define R_W32_H

#ifdef __cplusplus
extern "C" {
#endif

#if R2__WINDOWS__
#include <windows.h> // CreateToolhelp32Snapshot
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName

#ifndef NTSTATUS
#define NTSTATUS DWORD
#undef TEXT
#define TEXT(x) (TCHAR*)(x)
#endif

R_API BOOL r_w32_ProcessIdToSessionId(DWORD a, DWORD *b);
R_API BOOL r_w32_CancelSynchronousIo(HANDLE a);
R_API DWORD r_w32_GetProcessImageFileName(HANDLE,LPSTR,DWORD);
// R_API DWORD r_w32_GetModuleBaseName(HANDLE, HMODULE, LPSTR, DWORD);
R_API BOOL r_w32_GetModuleInformation(HANDLE, HMODULE, LPMODULEINFO, DWORD);
R_API BOOL r_w32_DebugBreakProcess(HANDLE);
R_API DWORD r_w32_GetThreadId(HANDLE); // Vista
R_API DWORD r_w32_GetProcessId(HANDLE); // XP
R_API BOOL r_w32_QueryFullProcessImageName(HANDLE, DWORD, LPSTR, PDWORD);
R_API DWORD r_w32_GetMappedFileName(HANDLE, LPVOID, LPSTR, DWORD);
R_API NTSTATUS r_w32_NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
R_API NTSTATUS r_w32_NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
R_API NTSTATUS r_w32_NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
R_API NTSTATUS r_w32_NtQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
R_API ut64 r_w32_GetEnabledXStateFeatures(void);
R_API BOOL r_w32_InitializeContext(PVOID, DWORD, PCONTEXT*, PDWORD);
R_API BOOL r_w32_GetXStateFeaturesMask(PCONTEXT Context, PDWORD64);
R_API PVOID r_w32_LocateXStateFeature(PCONTEXT Context, DWORD, PDWORD);
R_API BOOL r_w32_SetXStateFeaturesMask(PCONTEXT Context, DWORD64);
R_API DWORD r_w32_GetModuleFileNameEx(HANDLE, HMODULE, LPSTR, DWORD);
// thcond
R_API FARPROC r_w32_InitializeConditionVariable(PCONDITION_VARIABLE a);
R_API FARPROC r_w32_WakeConditionVariable(PCONDITION_VARIABLE a);
R_API FARPROC r_w32_WakeAllConditionVariable(PCONDITION_VARIABLE a);
R_API BOOL r_w32_SleepConditionVariableCS(PCONDITION_VARIABLE a, PCRITICAL_SECTION b, DWORD c);

// R_API BOOL r_w32_DebugActiveProcessStop(DWORD);
// R_API HANDLE r_w32_OpenProcess(DWORD, BOOL, DWORD);

#endif

#ifdef __cplusplus
}
#endif

#endif //  R_W32_H
