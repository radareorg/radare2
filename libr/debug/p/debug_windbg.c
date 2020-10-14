/* radare - LGPL - Copyright 2020 - GustavoLCR */

#include <r_debug.h>
#include <DbgEng.h>

#ifndef CONTEXT_ARM
#define CONTEXT_ARM 0x00200000L
#endif
#ifndef CONTEXT_ARM64
#define CONTEXT_ARM64 0x00400000L
#endif
#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64 0x00100000L
#endif
#ifndef CONTEXT_i386
#define CONTEXT_i386 0x00010000L
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif
#ifndef DEBUG_DUMP_ACTIVE
#define DEBUG_DUMP_ACTIVE 1030
#endif

#define TIMEOUT 500
#define THISCALL(dbginterface, function, ...) dbginterface->lpVtbl->function (dbginterface, __VA_ARGS__)
#define ITHISCALL(dbginterface, function, ...) THISCALL (idbg->dbginterface, function, __VA_ARGS__)
#define RELEASE(I) if (I) THISCALL (I, Release);

typedef struct { // Keep in sync with io_windbg.c
	bool initialized;
	ULONG64 server;
	ULONG64 processBase;
	DWORD lastExecutionStatus;
	PDEBUG_CLIENT5 dbgClient;
	PDEBUG_CONTROL4 dbgCtrl;
	PDEBUG_DATA_SPACES4 dbgData;
	PDEBUG_REGISTERS2 dbgReg;
	PDEBUG_SYSTEM_OBJECTS4 dbgSysObj;
	PDEBUG_SYMBOLS3 dbgSymbols;
	PDEBUG_ADVANCED3 dbgAdvanced;
} DbgEngContext;

static bool __is_target_kernel(DbgEngContext *idbg) {
	ULONG Class, Qualifier;
	if (SUCCEEDED (ITHISCALL (dbgCtrl, GetDebuggeeType, &Class, &Qualifier))) {
		if (Class == DEBUG_CLASS_KERNEL) {
			return true;
		}
	}
	return false;
}

static int windbg_init(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	if (!idbg || !idbg->initialized) {
		return 0;
	}
	return 1;
}

static int windbg_step(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	idbg->lastExecutionStatus = DEBUG_STATUS_STEP_INTO;
	return SUCCEEDED (ITHISCALL (dbgCtrl, SetExecutionStatus, DEBUG_STATUS_STEP_INTO));
}

static int windbg_select(RDebug *dbg, int pid, int tid) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	ULONG Id = tid;
	if (!__is_target_kernel (idbg)) {
		ITHISCALL (dbgSysObj, GetThreadIdBySystemId, tid, &Id);
	}
	if (SUCCEEDED (ITHISCALL (dbgSysObj, SetCurrentThreadId, Id))) {
		return 1;
	}
	return 0;
}

static int windbg_continue(RDebug *dbg, int pid, int tid, int sig) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	idbg->lastExecutionStatus = DEBUG_STATUS_GO;
	ITHISCALL (dbgCtrl, SetExecutionStatus, DEBUG_STATUS_GO);
	return tid;
}

// nicked from windows_debug.c
static RDebugReasonType exception_to_reason(DWORD ExceptionCode) {
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

static int windbg_stop(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	return SUCCEEDED (ITHISCALL (dbgCtrl, SetInterrupt, DEBUG_INTERRUPT_ACTIVE));
}

static bool do_break = false;

static void __break(void *user) {
	RDebug *dbg = (RDebug *)user;
	DbgEngContext *idbg = dbg->user;
	if (__is_target_kernel (idbg)) {
		windbg_stop (dbg);
	}
	do_break = true;
}

static int windbg_wait(RDebug *dbg, int pid) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	ULONG Type, ProcessId, ThreadId;
	r_cons_break_push (__break, dbg);
	const ULONG timeout = __is_target_kernel (idbg) ? INFINITE : TIMEOUT;
	HRESULT hr;
	while ((hr = ITHISCALL (dbgCtrl, WaitForEvent, DEBUG_WAIT_DEFAULT, timeout)) == S_FALSE) {
		if (do_break) {
			ITHISCALL (dbgCtrl, SetExecutionStatus, DEBUG_STATUS_BREAK);
			do_break = false;
			r_cons_break_pop ();
			return R_DEBUG_REASON_USERSUSP;
		}
	}
	r_cons_break_pop ();
	if (FAILED (hr)) {
		return R_DEBUG_REASON_DEAD;
	}
	ITHISCALL (dbgCtrl, GetLastEventInformation, &Type, &ProcessId, &ThreadId, NULL, 0, NULL, NULL, 0, NULL);
	if (!__is_target_kernel (idbg)) {
		ITHISCALL (dbgSysObj, GetCurrentProcessSystemId, (PULONG)&dbg->pid);
		ITHISCALL (dbgSysObj, GetCurrentThreadSystemId, (PULONG)&dbg->tid);
	} else {
		dbg->pid = ProcessId;
		dbg->tid = ThreadId;
	}
	int ret;
	switch (Type) {
	case 0:
		// I dont really get why Type is zero here
		if (idbg->lastExecutionStatus == DEBUG_STATUS_STEP_INTO
			|| idbg->lastExecutionStatus == DEBUG_STATUS_STEP_OVER) {
			ret = R_DEBUG_REASON_STEP;
		} else {
			ret = R_DEBUG_REASON_ERROR;
		}
		break;
	case DEBUG_EVENT_BREAKPOINT:
		ret = R_DEBUG_REASON_BREAKPOINT;
		break;
	case DEBUG_EVENT_EXCEPTION: {
		EXCEPTION_RECORD64 exr;
		ITHISCALL (dbgCtrl, GetLastEventInformation, &Type, &ProcessId, &ThreadId, &exr, sizeof (exr), NULL, NULL, 0, NULL);
		dbg->reason.type = exception_to_reason (exr.ExceptionCode);
		dbg->reason.tid = dbg->tid;
		dbg->reason.addr = exr.ExceptionAddress;
		dbg->reason.timestamp = r_time_now ();
		ret = dbg->reason.type;
		break;
	}
	case DEBUG_EVENT_EXIT_PROCESS:
		ret = R_DEBUG_REASON_EXIT_PID;
		break;
	case DEBUG_EVENT_CREATE_PROCESS:
		ret = R_DEBUG_REASON_NEW_PID;
		break;
	default:
		ret = R_DEBUG_REASON_ERROR;
		break;
	}

	return ret;
}

static int windbg_step_over(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	idbg->lastExecutionStatus = DEBUG_STATUS_STEP_OVER;
	if (SUCCEEDED (ITHISCALL (dbgCtrl, SetExecutionStatus, DEBUG_STATUS_STEP_OVER))) {
		return windbg_wait (dbg, dbg->pid) != R_DEBUG_REASON_ERROR;
	}
	return 0;
}

static int windbg_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	static volatile LONG bp_idx = 0;
	RDebug *dbg = bp->user;
	r_return_val_if_fail (dbg, 0);
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	ULONG type = b->hw ? DEBUG_BREAKPOINT_DATA : DEBUG_BREAKPOINT_CODE;
	PDEBUG_BREAKPOINT bkpt;
	if (FAILED (ITHISCALL (dbgCtrl, GetBreakpointById, b->internal, &bkpt))) {
		HRESULT hr;
		do {
			b->internal = InterlockedIncrement (&bp_idx);
			hr = ITHISCALL (dbgCtrl, AddBreakpoint, type, b->internal, &bkpt);
		} while (hr == E_INVALIDARG);
		if (FAILED (hr)) {
			return 0;
		}
	}
	ULONG flags;
	THISCALL (bkpt, GetFlags, &flags);
	flags = set ? flags | DEBUG_BREAKPOINT_ENABLED : flags & ~DEBUG_BREAKPOINT_ENABLED;
	if (b->hw) {
		ULONG access_type = 0;
		if (b->perm & R_BP_PROT_EXEC) {
			access_type |= DEBUG_BREAK_EXECUTE;
		}
		if (b->perm & R_BP_PROT_READ) {
			access_type |= DEBUG_BREAK_READ;
		}
		if (b->perm & R_BP_PROT_WRITE) {
			access_type |= DEBUG_BREAK_WRITE;
		}
		if (b->perm & R_BP_PROT_ACCESS) {
			access_type |= DEBUG_BREAK_READ;
			access_type |= DEBUG_BREAK_WRITE;
		}
		THISCALL (bkpt, SetDataParameters, b->size, access_type);
	}
	THISCALL (bkpt, SetFlags, flags);
	THISCALL (bkpt, GetCurrentPassCount, (PULONG)&b->togglehits);
	THISCALL (bkpt, SetOffset, b->addr);
	return 1;
}

static char *windbg_reg_profile(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	ULONG type;
	if (!idbg || !idbg->initialized || FAILED (ITHISCALL (dbgCtrl, GetActualProcessorType, &type))) {
		if (dbg->bits & R_SYS_BITS_64) {
#include "native/reg/windows-x64.h"
		} else {
#include "native/reg/windows-x86.h"
		}
		return NULL;
	}
	if (type == IMAGE_FILE_MACHINE_IA64 || type == IMAGE_FILE_MACHINE_AMD64) {
#include "native/reg/windows-x64.h"
	} else if (type == IMAGE_FILE_MACHINE_I386) {
#include "native/reg/windows-x86.h"
	} else if (type == IMAGE_FILE_MACHINE_ARM) {
#include "native/reg/windows-arm.h"
	} else if (type == IMAGE_FILE_MACHINE_ARM64) {
#include "native/reg/windows-arm64.h"
	}
	return NULL;
}

static int windbg_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	ULONG ptype;
	if (!idbg || !idbg->initialized || FAILED (ITHISCALL (dbgCtrl, GetActualProcessorType, &ptype))) {
		return 0;
	}
	if (ptype == IMAGE_FILE_MACHINE_IA64 || ptype == IMAGE_FILE_MACHINE_AMD64) {
		DWORD *b = (DWORD *)(buf + 0x30);
		*b |= 0xff | CONTEXT_AMD64;
	} else if (ptype == IMAGE_FILE_MACHINE_I386) {
		DWORD *b = (DWORD *)buf;
		*b |= 0xff | CONTEXT_i386;
	} else if (ptype == IMAGE_FILE_MACHINE_ARM64) {
		DWORD *b = (DWORD *)buf;
		*b |= 0xff | CONTEXT_ARM64;
	} else if (ptype == IMAGE_FILE_MACHINE_ARM64) {
		DWORD *b = (DWORD *)buf;
		*b |= 0xff | CONTEXT_ARM;
	}
	if (SUCCEEDED (ITHISCALL (dbgAdvanced, GetThreadContext, (PVOID)buf, size))) {
		return size;
	}
	return 0;
}
static int windbg_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	if (SUCCEEDED (ITHISCALL (dbgAdvanced, SetThreadContext, (PVOID)buf, size))) {
		return size;
	}
	return 0;
}

static RList *windbg_frames(RDebug *dbg, ut64 at) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	const size_t frame_cnt = 128;
	PDEBUG_STACK_FRAME dbgframes = R_NEWS (DEBUG_STACK_FRAME, frame_cnt);
	if (!dbgframes) {
		return NULL;
	}
	ULONG frames_filled;
	if (FAILED (ITHISCALL (dbgCtrl, GetStackTrace, 0, 0, 0, dbgframes, frame_cnt, &frames_filled))) {
		free (dbgframes);
		return NULL;
	}
	RList *frames = r_list_newf (free);
	size_t i;
	for (i = 0; i < frames_filled; i++) {
		RDebugFrame *f = R_NEW0 (RDebugFrame);
		if (!f) {
			break;
		}
		f->sp = dbgframes[i].StackOffset;
		f->bp = dbgframes[i].FrameOffset;
		f->addr = dbgframes[i].ReturnOffset;
		f->size = f->bp - f->sp;
		r_list_append (frames, f);
	}
	return frames;
}

static RList *windbg_modules_get(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	ULONG mod_cnt, mod_un_cnt;
	if (FAILED (ITHISCALL (dbgSymbols, GetNumberModules, &mod_cnt, &mod_un_cnt))) {
		return NULL;
	}
	if (!mod_cnt) {
		return NULL;
	}
	PDEBUG_MODULE_PARAMETERS params = R_NEWS (DEBUG_MODULE_PARAMETERS, mod_cnt);
	if (!params) {
		return NULL;
	}
	if (FAILED (ITHISCALL (dbgSymbols, GetModuleParameters, mod_cnt, 0, 0, params))) {
		return NULL;
	}
	RList *modules_list = r_list_newf ((RListFree)r_debug_map_free);
	if (!modules_list) {
		return NULL;
	}
	size_t i;
	for (i = 0; i < mod_cnt; i++) {
		char *mod_name = malloc (params[i].ModuleNameSize);
		char *image_name = malloc (params[i].ImageNameSize);
		if (!mod_name || !image_name) {
			free (mod_name);
			free (image_name);
			break;
		}
		if (FAILED (
			    ITHISCALL (dbgSymbols, GetModuleNames,
				    DEBUG_ANY_ID, params[i].Base,
				    image_name, params[i].ImageNameSize, NULL,
				    mod_name, params[i].ModuleNameSize, NULL,
				    NULL, 0, NULL))) {
			free (mod_name);
			free (image_name);
			break;
		}
		RDebugMap *mod = r_debug_map_new (mod_name, params[i].Base, params[i].Base + params[i].Size, 0, params[i].Size);
		if (mod) {
			mod->file = strdup (image_name);
			r_list_append (modules_list, mod);
		}
		free (mod_name);
		free (image_name);
	}
	return modules_list;
}

static RList *windbg_map_get(RDebug *dbg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, NULL);
	int perm;
	ULONG64 to = 0ULL;
	MEMORY_BASIC_INFORMATION64 mbi;
	RList *mod_list = windbg_modules_get (dbg);
	RList *map_list = r_list_newf ((RListFree)r_debug_map_free);
	const int mod_cnt = mod_list ? r_list_length (mod_list) : 0;
	PIMAGE_NT_HEADERS64 h = R_NEWS (IMAGE_NT_HEADERS64, mod_cnt);
	PIMAGE_SECTION_HEADER *s = R_NEWS0 (PIMAGE_SECTION_HEADER, mod_cnt);
	RListIter *it;
	RDebugMap *mod = NULL;
	size_t i = 0;
	r_list_foreach (mod_list, it, mod) {
		if (FAILED (ITHISCALL (dbgData, ReadImageNtHeaders, mod->addr, h + i))) {
			memset (h + i, 0, sizeof (IMAGE_NT_HEADERS64));
		} else {
			IMAGE_DOS_HEADER dos;
			ITHISCALL (dbgData, ReadVirtual, mod->addr, (PVOID)&dos, sizeof (IMAGE_DOS_HEADER), NULL);
			const size_t header_size = h[i].OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
				? sizeof (IMAGE_NT_HEADERS32)
				: sizeof (IMAGE_NT_HEADERS64);
			ULONG64 offset = mod->addr + dos.e_lfanew + header_size;
			const ULONG size = sizeof (IMAGE_SECTION_HEADER) * h[i].FileHeader.NumberOfSections;
			s[i] = malloc (size);
			ITHISCALL (dbgData, ReadVirtual, offset, (PVOID)s[i], size, NULL);
		}
		i++;
	}
	ULONG page_size = 1;
	ITHISCALL (dbgCtrl, GetPageSize, &page_size);
	ULONG p_mask = page_size - 1;
	while (SUCCEEDED (ITHISCALL (dbgData, QueryVirtual, to, &mbi))) {
		to = mbi.BaseAddress + mbi.RegionSize;
		perm = 0;
		perm |= mbi.Protect & PAGE_READONLY ? R_PERM_R : 0;
		perm |= mbi.Protect & PAGE_READWRITE ? R_PERM_RW : 0;
		perm |= mbi.Protect & PAGE_EXECUTE ? R_PERM_X : 0;
		perm |= mbi.Protect & PAGE_EXECUTE_READ ? R_PERM_RX : 0;
		perm |= mbi.Protect & PAGE_EXECUTE_READWRITE ? R_PERM_RWX : 0;
		perm = mbi.Protect & PAGE_NOACCESS ? 0 : perm;
		if (!perm) {
			continue;
		}
		char *name = "";
		if (mbi.Type == MEM_IMAGE) {
			i = 0;
			r_list_foreach (mod_list, it, mod) {
				if (mbi.BaseAddress >= mod->addr && mbi.BaseAddress < mod->addr + mod->size) {
					break;
				}
				i++;
			}
			if (i < mod_cnt && mod) {
				size_t j;
				for (j = 0; j < h[i].FileHeader.NumberOfSections; j++) {
					ut64 sect_vaddr = mod->addr + s[i][j].VirtualAddress;
					ut64 sect_vsize = (((ut64)s[i][j].Misc.VirtualSize) + p_mask) & ~p_mask;
					if (mbi.BaseAddress >= sect_vaddr && mbi.BaseAddress < sect_vaddr + sect_vsize) {
						name = sdb_fmt ("%s | %.8s", mod->name, s[i][j].Name);
						break;
					}
				}
				if (!*name) {
					name = mod->name;
				}
			}
		}
		RDebugMap *map = r_debug_map_new (name, mbi.BaseAddress, to, perm, 0);
		r_list_append (map_list, map);
	}
	for (i = 0; i < mod_cnt; i++) {
		free (s[i]);
	}
	free (s);
	free (h);
	r_list_free (mod_list);
	return map_list;
}

static int windbg_attach(RDebug *dbg, int pid) {
	ULONG Id = 0;
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, -1);
	if (SUCCEEDED (ITHISCALL (dbgSysObj, GetCurrentProcessSystemId, &Id))) {
		if (Id == pid && SUCCEEDED (ITHISCALL (dbgSysObj, GetCurrentThreadSystemId, &Id))) {
			return Id;
		}
	}
	if (SUCCEEDED (ITHISCALL (dbgClient, AttachProcess, idbg->server, pid, DEBUG_ATTACH_DEFAULT))) {
		return windbg_wait (dbg, pid);
	}
	return -1;
}

static int windbg_detach(RDebug *dbg, int pid) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, 0);
	return SUCCEEDED (ITHISCALL (dbgClient, DetachProcesses));
}

static bool windbg_kill(RDebug *dbg, int pid, int tid, int sig) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, false);
	if (!sig) {
		ULONG exit_code, class, qualifier;
		if (SUCCEEDED (ITHISCALL (dbgCtrl, GetDebuggeeType, &class, &qualifier))) {
			if (class == DEBUG_CLASS_UNINITIALIZED) {
				return false;
			}
			if (qualifier >= DEBUG_DUMP_SMALL && qualifier <= DEBUG_DUMP_ACTIVE) {
				return true;
			}
		}
		if (FAILED (ITHISCALL (dbgClient, GetExitCode, &exit_code))) {
			return false;
		}
		return exit_code == STILL_ACTIVE;
	}
	HRESULT hr = ITHISCALL (dbgClient, TerminateProcesses);
	return SUCCEEDED (hr);
}

static RList *windbg_threads(RDebug *dbg, int pid) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, NULL);
	ULONG thread_cnt = 0;
	ITHISCALL (dbgSysObj, GetNumberThreads, &thread_cnt);
	if (!thread_cnt) {
		return NULL;
	}
	PULONG threads_ids = R_NEWS (ULONG, thread_cnt);
	PULONG threads_sysids = R_NEWS (ULONG, thread_cnt);
	RList *list = r_list_newf ((RListFree)r_debug_pid_free);
	if (!list || !threads_ids || !threads_sysids) {
		free (list);
		free (threads_ids);
		free (threads_sysids);
		return NULL;
	}
	ITHISCALL (dbgSysObj, GetThreadIdsByIndex, 0, thread_cnt, threads_ids, threads_sysids);
	size_t i;
	for (i = 0; i < thread_cnt; i++) {
		ULONG64 pc;
		ITHISCALL (dbgSysObj, SetCurrentThreadId, threads_ids[i]);
		ITHISCALL (dbgReg, GetInstructionOffset, &pc);
		r_list_append (list, r_debug_pid_new (NULL, threads_sysids[i], 0, 's', pc));
	}
	windbg_select (dbg, dbg->pid, dbg->tid);
	free (threads_ids);
	free (threads_sysids);
	return list;
}

static RDebugInfo *windbg_info(RDebug *dbg, const char *arg) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, NULL);
	char exeinfo[MAX_PATH];
	char cmdline[MAX_PATH];
	if (SUCCEEDED (ITHISCALL (dbgClient, GetRunningProcessDescription, idbg->server, dbg->pid, DEBUG_PROC_DESC_NO_SERVICES | DEBUG_PROC_DESC_NO_MTS_PACKAGES, exeinfo, MAX_PATH, NULL, cmdline, MAX_PATH, NULL))) {
		RDebugInfo *info = R_NEW0 (RDebugInfo);
		if (!info) {
			return NULL;
		}
		info->pid = dbg->pid;
		info->tid = dbg->tid;
		info->exe = strdup (exeinfo);
		info->cmdline = strdup (cmdline);
	}
	return NULL;
}

static bool windbg_gcore(RDebug *dbg, RBuffer *dest) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, false);
	char *path = r_sys_getenv (R_SYS_TMP);
	if (R_STR_ISEMPTY (path)) {
		free (path);
		path = r_sys_getdir ();
		if (R_STR_ISEMPTY (path)) {
			free (path);
			return false;
		}
	}
	path = r_str_appendf (path, "\\core.%d", dbg->pid);
	ITHISCALL (dbgClient, WriteDumpFile, path, DEBUG_DUMP_DEFAULT);
	free (path);
	return true;
}

RList *windbg_pids(RDebug *dbg, int pid) {
	DbgEngContext *idbg = dbg->user;
	r_return_val_if_fail (idbg && idbg->initialized, NULL);
	RList *list = r_list_newf ((RListFree)r_debug_pid_free);
	ULONG ids[1000];
	ULONG ids_cnt;
	if (SUCCEEDED (ITHISCALL (dbgClient, GetRunningProcessSystemIds,
		idbg->server, ids, _countof (ids), &ids_cnt))) {
		size_t i;
		for (i = 0; i < ids_cnt; i++) {
			char path[MAX_PATH];
			if (SUCCEEDED (ITHISCALL (dbgClient, GetRunningProcessDescription,
				    idbg->server, ids[i], DEBUG_PROC_DESC_DEFAULT,
					path, sizeof (path), NULL, NULL, 0, NULL))) {
				RDebugPid *pid = r_debug_pid_new (path, ids[i], 0, 'r', 0);
				r_list_append (list, pid);
			}
		}
	}
	return list;
}

RDebugPlugin r_debug_plugin_windbg = {
	.name = "windbg",
	.license = "LGPL3",
	.bits = R_SYS_BITS_64,
	.arch = "x86,x64,arm,arm64",
	.canstep = 1,
	.init = windbg_init,
	.attach = windbg_attach,
	.detach = windbg_detach,
	.breakpoint = windbg_breakpoint,
	.frames = windbg_frames,
	.kill = windbg_kill,
	.select = windbg_select,
	.step = windbg_step,
	.step_over = windbg_step_over,
	.threads = windbg_threads,
	.cont = windbg_continue,
	.wait = windbg_wait,
	.stop = windbg_stop,
	.reg_read = windbg_reg_read,
	.reg_write = windbg_reg_write,
	.reg_profile = windbg_reg_profile,
	.map_get = windbg_map_get,
	.modules_get = windbg_modules_get,
	.info = windbg_info,
	.gcore = windbg_gcore,
	.pids = windbg_pids
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_windbg,
	.version = R2_VERSION
};
#endif // R2_PLUGIN_INCORE
