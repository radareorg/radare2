#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winbase.h>
#include <psapi.h>

// XXX remove
#define WIN32_PI(x) x

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

BOOL WINAPI DebugActiveProcessStop(DWORD dwProcessId);
static void (*gmbn)(HANDLE, HMODULE, LPTSTR, int) = NULL;
static int (*gmi)(HANDLE, HMODULE, LPMODULEINFO, int) = NULL;
static BOOL WINAPI (*w32_detach)(DWORD) = NULL;
static HANDLE WINAPI (*w32_openthread)(DWORD, BOOL, DWORD) = NULL;
static HANDLE WINAPI (*w32_dbgbreak)(HANDLE) = NULL;
static DWORD WINAPI (*w32_getthreadid)(HANDLE) = NULL; // Vista
static DWORD WINAPI (*w32_getprocessid)(HANDLE) = NULL; // XP

static void print_lasterr(const char *str) {
	/* code from MSDN, :? */
	LPWSTR pMessage = L"%1!*.*s! %4 %5!*s!";
	DWORD_PTR pArgs[] = { (DWORD_PTR)4, (DWORD_PTR)2, (DWORD_PTR)L"Bill",  // %1!*.*s!
		(DWORD_PTR)L"Bob",                                                // %4
		(DWORD_PTR)6, (DWORD_PTR)L"Bill" };                               // %5!*s!
	const DWORD size = 100+1;
	WCHAR buffer[size];
	if (!FormatMessage (FORMAT_MESSAGE_FROM_STRING |
				FORMAT_MESSAGE_ARGUMENT_ARRAY,
				pMessage,
				0,  // ignored
				0,  // ignored
				(LPTSTR)&buffer,
				size,
				(va_list*)pArgs)) {
		eprintf ("(%s): Format message failed with 0x%x\n",
			r_str_get (str), GetLastError());
		return;
	}
	eprintf ("print_lasterr: %s ::: %s\n", r_str_get (str), r_str_get (buffer));
}


static int w32_dbg_init() {
	HANDLE lib;

	w32_detach = (BOOL WINAPI (*)(DWORD))
		GetProcAddress (GetModuleHandle ("kernel32"),
				"DebugActiveProcessStop");
	w32_openthread = (HANDLE WINAPI (*)(DWORD, BOOL, DWORD))
		GetProcAddress (GetModuleHandle ("kernel32"), "OpenThread");
	w32_dbgbreak = (HANDLE WINAPI (*)(HANDLE))
		GetProcAddress (GetModuleHandle ("kernel32"),
				"DebugBreakProcess");
	// only windows vista :(
	w32_getthreadid = (DWORD WINAPI (*)(HANDLE))
		GetProcAddress (GetModuleHandle ("kernel32"), "GetThreadId");
	// from xp1
	w32_getprocessid = (DWORD WINAPI (*)(HANDLE))  
		GetProcAddress (GetModuleHandle ("kernel32"), "GetProcessId");

	lib = LoadLibrary ("psapi.dll");
	if(lib == NULL) {
		eprintf ("Cannot load psapi.dll!!\n");
		return R_FALSE;
	}
	gmbn = (void (*)(HANDLE, HMODULE, LPTSTR, int))
		GetProcAddress (lib, "GetModuleBaseNameA");
	gmi = (int (*)(HANDLE, HMODULE, LPMODULEINFO, int))
		GetProcAddress (lib, "GetModuleInformation");

	if(w32_detach == NULL || w32_openthread == NULL || w32_dbgbreak == NULL || 
	   gmbn == NULL || gmi == NULL) {
		// OOPS!
		eprintf("debug_init_calls:\n"
			"DebugActiveProcessStop: 0x%x\n"
			"OpenThread: 0x%x\n"
			"DebugBreakProcess: 0x%x\n"
			"GetThreadId: 0x%x\n",
			w32_detach, w32_openthread, w32_dbgbreak, w32_getthreadid);
		return R_FALSE;
	}
	return R_TRUE;
}

static HANDLE w32_t2h(pid_t tid) {
#if 0
	TH_INFO *th = get_th (tid);
	if(th == NULL) {
		/* refresh thread list */
		w32_dbg_threads (tid);

		/* try to search thread */
		if((th = get_th (tid)) == NULL)
			return NULL;
	}
	return th->ht;
#endif
	return NULL;
}

inline static int w32_h2t(HANDLE h) {
	if (w32_getthreadid != NULL) // >= Windows Vista
		return w32_getthreadid (h);
	if (w32_getprocessid != NULL) // >= Windows XP1
		return w32_getprocessid (h);
	return (int)h; // XXX broken
}

static inline int w32_h2p(HANDLE h) {
	return w32_getprocessid (h);
}

// TODO: not yet used !!!
static int w32_dbg_threads(int pid) {
#if 0
	HANDLE th;
	THREADENTRY32 te32;
	TH_INFO *th_i;
	int ret = -1;
	te32.dwSize = sizeof (THREADENTRY32);

	th = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, ps.pid); 
	if (th == INVALID_HANDLE_VALUE || !Thread32First(th, &te32))
		goto err_load_th;

	//free_th ();
	do {
		/* get all threads of process */
		if (te32.th32OwnerProcessID == pid) {
			const char *path = "unk";
			RDebugPid *pid = r_debug_pid_new (
				path, te32.th32ThreadID, 's');
			eprintf ("THREAD: id=0x%08x flags=0x%08x\n",
				te32.th32ThreadID, te32.dwFlags);
			eprintf ("HANDLER: 0x%p\n", w32_openthread (
				THREAD_ALL_ACCESS, 0, te32.th32ThreadID));
			/* open a new handler */
			//th_i->ht = w32_openthread(THREAD_ALL_ACCESS, 0,
			//		te32.th32ThreadID);
			ret = te32.th32ThreadID;
			//r_list_append (list, thread);
		}
	} while (Thread32Next (th, &te32));

err_load_th:
	if (ret == -1) 
		return -1;
		//print_lasterr((char *)__FUNCTION__);

	if (th != INVALID_HANDLE_VALUE)
		ClosePlugin (th);
	return ret;
#endif
	return 0;
}

static int debug_exception_event (unsigned long code) {
	switch (code) {
	case EXCEPTION_BREAKPOINT:
		eprintf ("breakpoint\n");
		break;
	case EXCEPTION_SINGLE_STEP:
		eprintf ("singlestep\n");
		break;
	/* fatal exceptions */
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
		eprintf ("fatal exception\n");
		break;
	default:
		eprintf ("unknown exception\n");
		break;
	}
}

static int w32_dbg_wait(int pid) {
	DEBUG_EVENT de;
	int tid, next_event = 0;
	unsigned int code;

	do {
		/* handle debug events */
		if (WaitForDebugEvent (&de, INFINITE) == 0) {
			print_lasterr ((char *)__FUNCTION__);
			return -1;
		}
		/* save thread id */
		tid = de.dwThreadId;
		/* get exception code */
		code = de.dwDebugEventCode;
		/* Ctrl-C? */
		if (code == 0x2) {
			// TODO: interrupted
			//WS(event) = INT_EVENT;
			break;
		}
		/* set state */
		//WS(event) = UNKNOWN_EVENT;
		/* get kind of event */
		switch (code) {
		case CREATE_PROCESS_DEBUG_EVENT:
			eprintf ("(%d) created process (%d:0x%x)\n",
				    pid, w32_h2t (de.u.CreateProcessInfo.
					    hProcess),
				 de.u.CreateProcessInfo.lpStartAddress);
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			eprintf ("\n\n______________[ process finished ]_______________\n\n");
			//debug_load();
			next_event = 0;
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			eprintf ("(%d) created thread (0x%x)\n",
			pid, de.u.CreateThread.lpStartAddress);
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			eprintf("EXIT_THREAD\n");
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			eprintf("(%d) Loading %s library at 0x%x\n",
				pid, "", de.u.LoadDll.lpBaseOfDll);
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			eprintf ("UNLOAD_DLL\n");
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			eprintf("OUTPUT_DBUG_STING\n");
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case RIP_EVENT:
			eprintf("RIP_EVENT\n");
			r_debug_native_continue (pid, -1);
			next_event = 1;
			break;
		case EXCEPTION_DEBUG_EVENT:
			next_event = debug_exception_event (
				de.u.Exception.ExceptionRecord.ExceptionCode);
			break;
		default:
			eprintf ("Unknown event: %d\n", code);
			return -1;
		}
	} while (next_event);

	return 0;
}

static inline int CheckValidPE(unsigned char * PeHeader) {
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)PeHeader;
	IMAGE_NT_HEADERS *nt_headers;

	if (dos_header->e_magic==IMAGE_DOS_SIGNATURE) {
		nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
				+ dos_header->e_lfanew);
		if (nt_headers->Signature==IMAGE_NT_SIGNATURE)
			return 1;
	}
	return 0;
}

static RList *w32_dbg_maps() {
	RList *list;
	SYSTEM_INFO SysInfo;
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE hProcess;
	LPBYTE page;
	char *mapname = NULL;
	/* DEPRECATED */
	char PeHeader[1024];
	MODULEINFO ModInfo;
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_SECTION_HEADER *SectionHeader;
	int NumSections, i;
	DWORD ret_len;
	RDebugMap *mr;

	list = r_list_new ();

	memset (&SysInfo, 0, sizeof (SysInfo));
	GetSystemInfo (&SysInfo); // TODO: check return value
	if (gmi == NULL) {
		eprintf ("w32dbg: no gmi\n");
		return 0;
	}
	if (gmbn == NULL) {
		eprintf ("w32dbg: no gmn\n");
		return 0;
	}

	for (page=(LPBYTE)SysInfo.lpMinimumApplicationAddress;
			page<(LPBYTE)SysInfo.lpMaximumApplicationAddress;) {
		if (!VirtualQueryEx (WIN32_PI (hProcess), page, &mbi, sizeof (mbi)))  {
			eprintf ("VirtualQueryEx ERROR, address = 0x%08X\n", page );
			return -1;
		}
		if (mbi.Type == MEM_IMAGE) {
			ReadProcessMemory (WIN32_PI (hProcess), (const void *)page,
				(LPVOID)PeHeader, sizeof (PeHeader), &ret_len);

			if (ret_len == sizeof (PeHeader) && CheckValidPE (PeHeader)) {
				dos_header = (IMAGE_DOS_HEADER *)PeHeader;
				if (dos_header == NULL)
					break;
				nt_headers = (IMAGE_NT_HEADERS *)((char *)dos_header
						+ dos_header->e_lfanew);
				if (nt_headers == NULL) {
					/* skip before failing */
					break;
				}
				NumSections = nt_headers->FileHeader.NumberOfSections;
				SectionHeader = (IMAGE_SECTION_HEADER *) ((char *)nt_headers
					+ sizeof(IMAGE_NT_HEADERS));
				if(NumSections > 0) {
					mapname = (char *)malloc(MAX_PATH);
					if (!mapname) {
						perror (":map_reg alloc");
						return -1;
					}
					gmbn (WIN32_PI(hProcess), (HMODULE) page,
						(LPTSTR)mapname, MAX_PATH);

					for (i=0; i<NumSections; i++) {
						mr = r_debug_map_new (mapname,
							SectionHeader->VirtualAddress + page,
							SectionHeader->VirtualAddress + page
								+ SectionHeader->Misc.VirtualSize,
							SectionHeader->Characteristics, // XXX?
							0);
						if(mr == NULL)
							return -1;
						r_list_append (list, mr);
						SectionHeader++;
					}
					free (mapname);
				}
			} else {
				eprintf ("Invalid read\n");
				return NULL;
			}

			if (gmi (WIN32_PI (hProcess), (HMODULE) page,
					(LPMODULEINFO) &ModInfo, sizeof(MODULEINFO)) == 0)
				return NULL;
/* THIS CODE SEGFAULTS WITH NO REASON. BYPASS IT! */
#if 0
		eprintf("--> 0x%08x\n", ModInfo.lpBaseOfDll);
		eprintf("sz> 0x%08x\n", ModInfo.SizeOfImage);
		eprintf("rs> 0x%08x\n", mbi.RegionSize);
			/* avoid infinite loops */
		//	if (ModInfo.SizeOfImage == 0)
		//		return 0;
		//	page += ModInfo.SizeOfImage;
#endif
			page +=  mbi.RegionSize; 
		} else {
			mr = r_debug_map_new ("unk", page, page+mbi.RegionSize, mbi.Protect, 0);
			if (mr == NULL) {
				eprintf ("Cannot create r_debug_map_new\n");
				// XXX leak
				return NULL;
			}

			r_list_append (list, mr);
			page += mbi.RegionSize; 
		}
	}
	return list;
}
