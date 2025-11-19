#ifndef WINDOWS_DEBUG_H
#define WINDOWS_DEBUG_H
/*_______
 |   |   |
 |___|___|
 |   |   |
 |___|___|
*/

#include <r_types.h>
#include <r_debug.h>
#include <windows.h>
#include <tlhelp32.h> // CreateToolhelp32Snapshot
#include <psapi.h> // GetModuleFileNameEx, GetProcessImageFileName
#include <tchar.h>
#include <r_util/r_w32dw.h>

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
#define CONTEXT_XSTATE (0x00100040)
#else
#define CONTEXT_XSTATE (0x00010040)
#endif
#define XSTATE_AVX (XSTATE_GSSE)
#define XSTATE_MASK_AVX (XSTATE_MASK_GSSE)
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
} POOL_TYPE,
	*PPOOL_TYPE;

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

// thread list
typedef struct {
	int pid;
	int tid;
	bool bFinished;
	bool bSuspended;
	HANDLE hThread;
	LPVOID lpThreadLocalBase;
	LPVOID lpStartAddress;
	PVOID lpThreadEntryPoint;
	DWORD dwExitCode;
} THREAD_ITEM, *PTHREAD_ITEM;

typedef struct{
	int pid;
	HANDLE hFile;
	void *BaseOfDll;
	char *Path;
	char *Name;
} LIB_ITEM, *PLIB_ITEM;

// APIs
bool w32_init(RDebug *dbg);

int w32_reg_read(RDebug *dbg, int type, ut8 *buf, int size);
int w32_reg_write(RDebug *dbg, int type, const ut8 *buf, int size);

int w32_attach(RDebug *dbg, int pid);
int w32_detach(RDebug *dbg, int pid);
int w32_attach_new_process(RDebug* dbg, int pid);
bool w32_select(RDebug *dbg, int pid, int tid);
int w32_kill(RDebug *dbg, int pid, int tid, int sig);
void w32_break_process(void *user);
RDebugReasonType w32_dbg_wait(RDebug *dbg, int pid);

bool w32_step(RDebug *dbg);
bool w32_continue(RDebug *dbg, int pid, int tid, int sig);
RDebugMap *w32_map_alloc(RDebug *dbg, ut64 addr, int size);
bool w32_map_dealloc(RDebug *dbg, ut64 addr, int size);
bool w32_map_protect(RDebug *dbg, ut64 addr, int size, int perms);

RList *w32_thread_list(RDebug *dbg, int pid, RList *list);
RDebugInfo *w32_info(RDebug *dbg, const char *arg);

RList *w32_pid_list(RDebug *dbg, int pid, RList *list);

RList *w32_desc_list(int pid);
#endif
