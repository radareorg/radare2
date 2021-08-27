#ifndef R_W32_H
#define R_W32_H

#ifdef __cplusplus
extern "C" {
#endif

#if __WINDOWS__
#include <windows.h> // CreateToolhelp32Snapshot
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName

#ifndef NTSTATUS
#define NTSTATUS DWORD
#undef TEXT
#define TEXT(x) (TCHAR*)(x)
#endif

#if 0
#define WAPI(x) r_w32_##x

#define WAPI(GetMappedFileName)

// Plain Native APIs with no wraping needed
#define r_w32_GetMappedFileName GetMappedFileName
#endif

R_API DWORD r_w32_GetProcessImageFileName(HANDLE,LPSTR,DWORD);
R_API DWORD r_w32_GetModuleBaseName(HANDLE, HMODULE, LPTSTR, DWORD);
R_API BOOL r_w32_GetModuleInformation(HANDLE, HMODULE, LPMODULEINFO, DWORD);
// R_API BOOL r_w32_DebugActiveProcessStop(DWORD);
R_API BOOL r_w32_DebugBreakProcess(HANDLE);
R_API DWORD r_w32_GetThreadId(HANDLE); // Vista
R_API DWORD r_w32_GetProcessId(HANDLE); // XP
R_API HANDLE r_w32_OpenProcess(DWORD, BOOL, DWORD);
R_API BOOL r_w32_QueryFullProcessImageName(HANDLE, DWORD, LPTSTR, PDWORD);
R_API DWORD r_w32_GetMappedFileName(HANDLE, LPVOID, LPTSTR, DWORD);
R_API NTSTATUS r_w32_NtQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);
R_API NTSTATUS r_w32_NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
R_API NTSTATUS r_w32_NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
R_API NTSTATUS r_w32_NtQueryObject(HANDLE, ULONG, PVOID, ULONG, PULONG);
R_API ut64 r_w32_GetEnabledXStateFeatures(void);
R_API BOOL r_w32_InitializeContext(PVOID, DWORD, PCONTEXT*, PDWORD);
R_API BOOL r_w32_GetXStateFeaturesMask(PCONTEXT Context, PDWORD64);
R_API PVOID r_w32_LocateXStateFeature(PCONTEXT Context, DWORD, PDWORD);
R_API BOOL r_w32_SetXStateFeaturesMask(PCONTEXT Context, DWORD64);
R_API DWORD r_w32_GetModuleFileNameEx(HANDLE, HMODULE, LPTSTR, DWORD);
#endif

#ifdef __cplusplus
}
#endif

#endif //  R_W32_H
