/* radare - LGPL - Copyright 2020 - GustavoLCR */

#define INITGUID
#include <r_core.h>
#include <DbgEng.h>

typedef HRESULT (__stdcall *DebugCreate_t)(
	_In_ REFIID InterfaceId,
	_Out_ PVOID *Interface
);

typedef HRESULT (__stdcall *DebugConnectWide_t)(
	_In_ PCWSTR RemoteOptions,
	_In_ REFIID InterfaceId,
	_Out_ PVOID *Interface
);

static DebugCreate_t w32_DebugCreate = NULL;
static DebugConnectWide_t w32_DebugConnectWide = NULL;

#define WINDBGURI "windbg://"

typedef struct { // Keep in sync with debug_windbg.c
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

#define THISCALL(dbginterface, function, ...) dbginterface->lpVtbl->function (dbginterface, __VA_ARGS__)
#define ITHISCALL(dbginterface, function, ...) THISCALL (idbg->dbginterface, function, __VA_ARGS__)

#define DECLARE_CALLBACKS_IMPL(Type, IFace)           \
typedef struct IFace##_impl {                         \
	IFace *lpVtbl;                                    \
	DbgEngContext *m_idbg;                            \
	LONG m_ref;                                       \
} Type##_IMPL, *P##Type##_IMPL;                       \

#define INIT_IUNKNOWN_CALLBACKS(IFace, lpVtbl)        \
lpVtbl->QueryInterface = IFace##_QueryInterface_impl; \
lpVtbl->AddRef = IFace##_AddRef_impl;                 \
lpVtbl->Release = IFace##_Release_impl                \

#define DECLARE_NEW(IFace, IVtbl)                     \
static P##IFace IFace##_impl_new(                     \
	DbgEngContext *idbg) {                            \
	if (!idbg) {                                      \
		return NULL;                                  \
	}                                                 \
	P##IFace##_IMPL callbacks = R_NEW (IFace##_IMPL); \
	if (!callbacks) {                                 \
		return NULL;                                  \
	}                                                 \
	callbacks->lpVtbl = R_NEW (IVtbl);                \
	if (!callbacks->lpVtbl) {                         \
		free (callbacks);                             \
		return NULL;                                  \
	}                                                 \
	IFace##_vtbl_init ((P##IFace)callbacks);          \
	callbacks->m_idbg = idbg;                         \
	callbacks->m_ref = 1;                             \
	return (P##IFace)callbacks;                       \
}

#define DECLARE_QUERYINTERFACE(IFace, IFaceIID)       \
static STDMETHODIMP IFace##_QueryInterface_impl (     \
	P##IFace This,                                    \
	_In_ REFIID InterfaceId,                          \
	_Out_ PVOID *Interface) {                         \
	*Interface = NULL;                                \
	if (IsEqualIID (InterfaceId, &IID_IUnknown) ||    \
		IsEqualIID (InterfaceId, &IFaceIID)) {        \
		*Interface = This;                            \
		THISCALL (This, AddRef);                      \
		return S_OK;                                  \
	} else {                                          \
		return E_NOINTERFACE;                         \
	}                                                 \
}

#define DECLARE_ADDREF(IFace)                         \
static STDMETHODIMP_(ULONG) IFace##_AddRef_impl(      \
	P##IFace This) {                                  \
	P##IFace##_IMPL impl = (P##IFace##_IMPL)This;     \
	return InterlockedIncrement (&impl->m_ref);       \
}

#define DECLARE_RELEASE(IFace)                        \
static STDMETHODIMP_(ULONG) IFace##_Release_impl(     \
	P##IFace This) {                                  \
	P##IFace##_IMPL impl = (P##IFace##_IMPL)This;     \
	LONG ret = InterlockedDecrement (&impl->m_ref);   \
	if (!ret) {                                       \
		free (This->lpVtbl);                          \
		free (This);                                  \
	}                                                 \
	return ret;                                       \
}

DECLARE_CALLBACKS_IMPL (DEBUG_EVENT_CALLBACKS, IDebugEventCallbacksVtbl)
DECLARE_CALLBACKS_IMPL (DEBUG_INPUT_CALLBACKS, IDebugInputCallbacksVtbl)
DECLARE_CALLBACKS_IMPL (DEBUG_OUTPUT_CALLBACKS, IDebugOutputCallbacksVtbl)

static STDMETHODIMP __interest_mask(PDEBUG_EVENT_CALLBACKS This, PULONG Mask) {
	*Mask = DEBUG_EVENT_BREAKPOINT | DEBUG_EVENT_CREATE_PROCESS;
	*Mask |= DEBUG_EVENT_EXCEPTION | DEBUG_EVENT_SYSTEM_ERROR;
	*Mask |= DEBUG_EVENT_EXIT_PROCESS;
	return S_OK;
}

static STDMETHODIMP __createprocess_cb(
	PDEBUG_EVENT_CALLBACKS This,
	ULONG64 ImageFileHandle,
	ULONG64 Handle,
	ULONG64 BaseOffset,
	ULONG ModuleSize,
	PCSTR ModuleName,
	PCSTR ImageName,
	ULONG CheckSum,
	ULONG TimeDateStamp,
	ULONG64 InitialThreadHandle,
	ULONG64 ThreadDataOffset,
	ULONG64 StartOffset) {
	PDEBUG_EVENT_CALLBACKS_IMPL impl = (PDEBUG_EVENT_CALLBACKS_IMPL)This;
	impl->m_idbg->processBase = BaseOffset;
	return DEBUG_STATUS_BREAK;
}

static STDMETHODIMP __breakpoint_cb(PDEBUG_EVENT_CALLBACKS This, PDEBUG_BREAKPOINT Bp) {
	return DEBUG_STATUS_BREAK;
}

static STDMETHODIMP __exception_cb(PDEBUG_EVENT_CALLBACKS This, PEXCEPTION_RECORD64 Exception, ULONG FirstChance) {
	return DEBUG_STATUS_BREAK;
}

static STDMETHODIMP __exit_process_cb(PDEBUG_EVENT_CALLBACKS This, ULONG ExitCode) {
	return DEBUG_STATUS_BREAK;
}

static STDMETHODIMP __system_error_cb(PDEBUG_EVENT_CALLBACKS This, ULONG Error, ULONG Level) {
	return DEBUG_STATUS_BREAK;
}

static STDMETHODIMP __input_cb(PDEBUG_INPUT_CALLBACKS This, ULONG BufferSize) {
	char prompt[512];
	PDEBUG_INPUT_CALLBACKS_IMPL impl = (PDEBUG_INPUT_CALLBACKS_IMPL)This;
	DbgEngContext *idbg = impl->m_idbg;
	ITHISCALL (dbgCtrl, GetPromptText, prompt, sizeof (prompt), NULL);
	r_line_set_prompt (prompt);
	const char *str = r_line_readline ();
	char *ret = r_str_ndup (str, R_MIN (strlen (str), BufferSize));
	ITHISCALL (dbgCtrl, ReturnInput, ret);
	return S_OK;
}

static STDMETHODIMP __input_end_cb(PDEBUG_INPUT_CALLBACKS This) {
	return S_OK;
}

static STDMETHODIMP __output_cb(PDEBUG_OUTPUT_CALLBACKS This, ULONG Mask, PCSTR Text) {
	eprintf ("%s", Text);
	return S_OK;
}

DECLARE_QUERYINTERFACE (DEBUG_EVENT_CALLBACKS, IID_IDebugEventCallbacks)
DECLARE_QUERYINTERFACE (DEBUG_INPUT_CALLBACKS, IID_IDebugInputCallbacks)
DECLARE_QUERYINTERFACE (DEBUG_OUTPUT_CALLBACKS, IID_IDebugOutputCallbacks)

DECLARE_ADDREF (DEBUG_EVENT_CALLBACKS)
DECLARE_ADDREF (DEBUG_INPUT_CALLBACKS)
DECLARE_ADDREF (DEBUG_OUTPUT_CALLBACKS)

DECLARE_RELEASE (DEBUG_EVENT_CALLBACKS)
DECLARE_RELEASE (DEBUG_INPUT_CALLBACKS)
DECLARE_RELEASE (DEBUG_OUTPUT_CALLBACKS)

static void DEBUG_EVENT_CALLBACKS_vtbl_init(PDEBUG_EVENT_CALLBACKS callbacks) {
	INIT_IUNKNOWN_CALLBACKS (DEBUG_EVENT_CALLBACKS, callbacks->lpVtbl);
	callbacks->lpVtbl->GetInterestMask = __interest_mask;
	callbacks->lpVtbl->Breakpoint = __breakpoint_cb;
	callbacks->lpVtbl->Exception = __exception_cb;
	callbacks->lpVtbl->CreateProcess = __createprocess_cb;
	callbacks->lpVtbl->ExitProcess = __exit_process_cb;
	callbacks->lpVtbl->SystemError = __system_error_cb;
}

static void DEBUG_INPUT_CALLBACKS_vtbl_init(PDEBUG_INPUT_CALLBACKS callbacks) {
	INIT_IUNKNOWN_CALLBACKS (DEBUG_INPUT_CALLBACKS, callbacks->lpVtbl);
	callbacks->lpVtbl->StartInput = __input_cb;
	callbacks->lpVtbl->EndInput = __input_end_cb;
}

static void DEBUG_OUTPUT_CALLBACKS_vtbl_init(PDEBUG_OUTPUT_CALLBACKS callbacks) {
	INIT_IUNKNOWN_CALLBACKS (DEBUG_OUTPUT_CALLBACKS, callbacks->lpVtbl);
	callbacks->lpVtbl->Output = __output_cb;
}

DECLARE_NEW (DEBUG_EVENT_CALLBACKS, IDebugEventCallbacksVtbl)
DECLARE_NEW (DEBUG_INPUT_CALLBACKS, IDebugInputCallbacksVtbl)
DECLARE_NEW (DEBUG_OUTPUT_CALLBACKS, IDebugOutputCallbacksVtbl)

static void __free_context(DbgEngContext *idbg) {
#define RELEASE(I)               \
	if (idbg->I) {               \
		ITHISCALL (I, Release);  \
		idbg->I = NULL;          \
	}
	RELEASE (dbgAdvanced);
	RELEASE (dbgClient);
	RELEASE (dbgCtrl);
	RELEASE (dbgData);
	RELEASE (dbgReg);
	RELEASE (dbgSymbols);
	RELEASE (dbgSysObj);
	free (idbg);
#undef RELEASE
}

static bool init_callbacks(DbgEngContext *idbg) {
#define RELEASE(I) if (I) THISCALL (I, Release);
	if (!idbg->dbgClient) {
		return false;
	}

	PDEBUG_EVENT_CALLBACKS event_callbacks = DEBUG_EVENT_CALLBACKS_impl_new (idbg);
	PDEBUG_INPUT_CALLBACKS input_callbacks = DEBUG_INPUT_CALLBACKS_impl_new (idbg);
	PDEBUG_OUTPUT_CALLBACKS output_callbacks = DEBUG_OUTPUT_CALLBACKS_impl_new (idbg);

	if (!event_callbacks || !output_callbacks || !event_callbacks) {
		RELEASE (event_callbacks);
		RELEASE (input_callbacks);
		RELEASE (output_callbacks);
		return false;
	}

	if (FAILED (ITHISCALL (dbgClient, SetEventCallbacks, event_callbacks)) ||
		FAILED (ITHISCALL (dbgClient, SetInputCallbacks, input_callbacks)) ||
		FAILED (ITHISCALL (dbgClient, SetOutputCallbacks, output_callbacks))) {
		goto fail;
	}

	RELEASE (event_callbacks);
	RELEASE (input_callbacks);
	RELEASE (output_callbacks);
	return true;
fail:
	ITHISCALL (dbgClient, SetEventCallbacks, NULL);
	ITHISCALL (dbgClient, SetInputCallbacks, NULL);
	ITHISCALL (dbgClient, SetOutputCallbacks, NULL);
	return false;
#undef RELEASE
}

static DbgEngContext *create_remote_context(const char *opts) {
	DbgEngContext *idbg = R_NEW0 (DbgEngContext);

	if (!idbg) {
		return false;
	}

	LPWSTR wopts = (LPWSTR)r_utf8_to_utf16 (opts);

	// Initialize interfaces
	if (w32_DebugConnectWide (wopts, &IID_IDebugClient5, (PVOID *)&idbg->dbgClient) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugControl4, (PVOID *)&idbg->dbgCtrl) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugDataSpaces4, (PVOID *)&idbg->dbgData) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugRegisters2, (PVOID *)&idbg->dbgReg) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugSystemObjects4, (PVOID *)&idbg->dbgSysObj) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugAdvanced3, (PVOID *)&idbg->dbgAdvanced) != S_OK) {
		goto fail;
	}
	if (w32_DebugConnectWide (wopts, &IID_IDebugSymbols3, (PVOID *)&idbg->dbgSymbols) != S_OK) {
		goto fail;
	}
	if (!init_callbacks (idbg)) {
		goto fail;
	}
	idbg->initialized = true;
	return idbg;
fail:
	__free_context (idbg);
	return NULL;
}

static DbgEngContext *create_context(void) {
	DbgEngContext *idbg = R_NEW0 (DbgEngContext);

	if (!idbg) {
		return false;
	}

	// Initialize interfaces
	if (w32_DebugCreate (&IID_IDebugClient5, (PVOID *)&idbg->dbgClient) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugControl4, (PVOID *)&idbg->dbgCtrl) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugDataSpaces4, (PVOID *)&idbg->dbgData) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugRegisters2, (PVOID *)&idbg->dbgReg) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugSystemObjects4, (PVOID *)&idbg->dbgSysObj) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugAdvanced3, (PVOID *)&idbg->dbgAdvanced) != S_OK) {
		goto fail;
	}
	if (w32_DebugCreate (&IID_IDebugSymbols3, (PVOID *)&idbg->dbgSymbols) != S_OK) {
		goto fail;
	}
	if (!init_callbacks (idbg)) {
		goto fail;
	}
	idbg->initialized = true;
	return idbg;
fail:
	__free_context (idbg);
	return NULL;
}

static int windbg_init(void) {
	if (w32_DebugCreate && w32_DebugConnectWide) {
		return 1;
	}
	char *ext_path = r_sys_getenv ("_NT_DEBUGGER_EXTENSION_PATH");
	HANDLE h = NULL;
	if (R_STR_ISNOTEMPTY (ext_path)) {
		char *s = strtok (ext_path, ";");
		do {
			PWCHAR dir = r_utf8_to_utf16 (s);
			SetDllDirectoryW (dir);
			free (dir);
			h = LoadLibrary (TEXT ("dbgeng.dll"));
		} while (!h && (s = strtok (NULL, ";")));
		SetDllDirectoryW (NULL);
	}
	free (ext_path);
	if (!h) {
		h = LoadLibrary (TEXT ("dbgeng.dll"));
	}
	if (!h) {
		r_sys_perror ("LoadLibrary (\"dbgeng.dll\")");
		return 0;
	}

	w32_DebugCreate = (DebugCreate_t)GetProcAddress (h, "DebugCreate");
	if (!w32_DebugCreate) {
		r_sys_perror ("GetProcAddress (\"DebugCreate\")");
		return 0;
	}

	w32_DebugConnectWide = (DebugConnectWide_t)GetProcAddress (h, "DebugConnectWide");
	if (!w32_DebugConnectWide) {
		r_sys_perror ("GetProcAddress (\"DebugConnectWide\")");
		return 0;
	}

	return 1;
}

static bool windbg_check(RIO *io, const char *uri, bool many) {
	return !strncmp (uri, WINDBGURI, strlen (WINDBGURI));
}

typedef enum {
	TARGET_LOCAL_SPAWN,
	TARGET_LOCAL_ATTACH,
	TARGET_LOCAL_KERNEL,
	TARGET_DUMP_FILE,
	TARGET_KERNEL,
} DbgEngTarget;

static RIODesc *windbg_open(RIO *io, const char *uri, int perm, int mode) {
	if (!windbg_check (io, uri, 0)) {
		return NULL;
	}
	if (!windbg_init ()) {
		return NULL;
	}
	HRESULT hr = E_FAIL;
	RIODesc *fd = NULL;
	RCore *core = io->corebind.core;
	DbgEngContext *idbg = NULL;
	const char *args = uri + strlen (WINDBGURI);
	if (r_str_startswith (args, "-remote")) {
		args += strlen ("-remote") + 1;
		idbg = create_remote_context (args);
		if (idbg) {
			goto remote_client;
		}
	} else {
		idbg = create_context ();
		if (idbg && r_str_startswith (args, "-premote")) {
			args += strlen ("-premote") + 1;
			if (FAILED (ITHISCALL (dbgClient, ConnectProcessServer, args, &idbg->server))) {
				__free_context (idbg);
				return NULL;
			}
			goto remote_client;
		}
	}	
	if (!idbg) {
		return NULL;
	}
	ITHISCALL (dbgCtrl, AddEngineOptions, DEBUG_ENGOPT_INITIAL_BREAK);
	ITHISCALL (dbgCtrl, AddEngineOptions, DEBUG_ENGOPT_FINAL_BREAK);
	ITHISCALL (dbgCtrl, AddEngineOptions, DEBUG_ENGOPT_ALLOW_READ_ONLY_BREAKPOINTS);
	ITHISCALL (dbgCtrl, SetCodeLevel, DEBUG_LEVEL_ASSEMBLY);
	int argc;
	char **argv = r_str_argv (args, &argc);
	const size_t argv_sz = sizeof (char *) * ((size_t)argc + 2);
	char **tmp = realloc (argv, argv_sz);
	if (!tmp) {
		__free_context (idbg);
		r_str_argv_free (argv);
		return NULL;
	}
	argv = tmp;
	memmove (argv + 1, argv, argv_sz - sizeof (char *));
	argv[0] = strdup (WINDBGURI);
	argc++;
	const char *command = NULL;
	bool image_path_set = false, symbol_path_set = false;
	DbgEngTarget target = TARGET_LOCAL_SPAWN;
	DWORD spawn_options = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
	DWORD attach_options = DEBUG_ATTACH_DEFAULT;
	DWORD pid = 0;
	int c;
	RGetopt opt;
	r_getopt_init (&opt, argc, (const char **)argv, "c:dgGh:i:k:op:y:z:");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'c':
			command = opt.arg;
			break;
		case 'd':
			ITHISCALL (dbgCtrl, AddEngineOptions, DEBUG_ENGOPT_INITIAL_MODULE_BREAK);
			break;
		case 'g':
			ITHISCALL (dbgCtrl, RemoveEngineOptions, DEBUG_ENGOPT_INITIAL_BREAK);
			break;
		case 'G':
			ITHISCALL (dbgCtrl, RemoveEngineOptions, DEBUG_ENGOPT_FINAL_BREAK);
			break;
		case 'h':
			if (strcmp (opt.arg, "d")) {
				spawn_options |= DEBUG_CREATE_PROCESS_NO_DEBUG_HEAP;
			}
			break;
		case 'i':
			ITHISCALL (dbgSymbols, SetImagePath, opt.arg);
			image_path_set = true;
			break;
		case 'k':
			if (strcmp (opt.arg, "l")) {
				target = TARGET_LOCAL_KERNEL;
			} else if (strcmp (opt.arg, "qm")) {
				ITHISCALL (dbgCtrl, AddEngineOptions, DEBUG_ENGOPT_KD_QUIET_MODE);
			} else {
				target = TARGET_KERNEL;
				args = opt.arg;
			}
			break;
		case 'o':
			spawn_options &= ~DEBUG_ONLY_THIS_PROCESS;
			spawn_options |= DEBUG_PROCESS;
			break;
		case 'p':
			if (r_str_isnumber (opt.arg)) {
				target = TARGET_LOCAL_ATTACH;
				pid = atoi (opt.arg);
			} else {
				if (strcmp (opt.arg, "b")) {
					attach_options |= DEBUG_ATTACH_INVASIVE_NO_INITIAL_BREAK;
				} else if (strcmp (opt.arg, "e")) {
					attach_options |= DEBUG_ATTACH_EXISTING;
				} else if (strcmp (opt.arg, "v")) {
					attach_options |= DEBUG_ATTACH_NONINVASIVE;
				}
			}
			break;
		case 'y':
			symbol_path_set = true;
			ITHISCALL (dbgSymbols, SetSymbolPath, opt.arg);
			break;
		case 'z':
			target = TARGET_DUMP_FILE;
			args = opt.arg;
			break;
		default:
			break;
		}
	}
	if (!symbol_path_set) {
		const char *store = io->corebind.cfgGet (core, "pdb.symstore");
		const char *server = io->corebind.cfgGet (core, "pdb.server");
		char *s = strdup (server);
		r_str_replace_ch (s, ';', '*', true);
		char *sympath = r_str_newf ("cache*;srv*%s*%s", store, s);
		ITHISCALL (dbgSymbols, SetSymbolPath, sympath);
		free (s);
		free (sympath);
	}
	if (!image_path_set) {
		char *path = r_sys_getenv ("PATH");
		ITHISCALL (dbgSymbols, AppendImagePath, path);
		free (path);
	}
	switch (target) {
	case TARGET_LOCAL_SPAWN:
		if (argv[opt.ind]) {
			char *cmd = r_str_format_msvc_argv ((size_t)opt.argc - opt.ind, (const char **)argv + opt.ind);
			hr = ITHISCALL (dbgClient, CreateProcess, 0ULL, cmd, spawn_options);
			free (cmd);
		} else {
			eprintf ("Missing argument for local spawn\n");
		}
		break;
	case TARGET_LOCAL_ATTACH: // -p (PID)
		hr = ITHISCALL (dbgClient, AttachProcess, 0ULL, pid, attach_options);
		break;
	case TARGET_LOCAL_KERNEL: // -kl
		if (ITHISCALL (dbgClient, IsKernelDebuggerEnabled) == S_FALSE) {
			eprintf ("Live Kernel debug not available. Set the /debug boot switch to enable it\n");
		} else {
			hr = ITHISCALL (dbgClient, AttachKernel, DEBUG_ATTACH_LOCAL_KERNEL, args);
		}
		break;
	case TARGET_DUMP_FILE: // -z
		hr = ITHISCALL (dbgClient, OpenDumpFile, args);
		break;
	case TARGET_KERNEL: // -k
		hr = ITHISCALL (dbgClient, AttachKernel, DEBUG_ATTACH_KERNEL_CONNECTION, args);
		break;
	}
	if (hr != S_OK) {
		r_str_argv_free (argv);
		__free_context (idbg);
		return NULL;
	}
	ITHISCALL (dbgCtrl, WaitForEvent, DEBUG_WAIT_DEFAULT, INFINITE);
	if (command) {
		ITHISCALL (dbgCtrl, Execute, DEBUG_OUTCTL_ALL_CLIENTS, command, DEBUG_EXECUTE_DEFAULT);	
	}
	r_str_argv_free (argv);
remote_client:
	fd = r_io_desc_new (io, &r_io_plugin_windbg, uri, perm | R_PERM_X, mode, idbg);
	fd->name = strdup (args);
	core->dbg->user = idbg;
	io->corebind.cmd (io->corebind.core, "dL windbg");
	return fd;
}

static int windbg_close(RIODesc *fd) {
	DbgEngContext *idbg = fd->data;
	if (idbg->server) {
		ITHISCALL (dbgClient, EndSession, DEBUG_END_DISCONNECT);
		ITHISCALL (dbgClient, DisconnectProcessServer, idbg->server);
		idbg->server = 0ULL;
	} else {
		ITHISCALL (dbgClient, EndSession, DEBUG_END_PASSIVE);
	}
	__free_context (idbg);
	return 1;
}

static ut64 windbg_lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += (st64)offset;
		break;
	case R_IO_SEEK_END:
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static int windbg_read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	DbgEngContext *idbg = fd->data;
	ULONG bytesRead = 0ULL;
	if (FAILED (ITHISCALL (dbgData, ReadVirtual, io->off, (PVOID)buf, count, &bytesRead))) {
		ULONG64 ValidBase;
		ULONG ValidSize;
		if (SUCCEEDED (ITHISCALL (dbgData, GetValidRegionVirtual, io->off, count, &ValidBase, &ValidSize))) {
			if (ValidSize && ValidBase < io->off + count) {
				const ULONG64 skipped = ValidBase - io->off;
				const ULONG toRead = count - skipped;
				ITHISCALL (dbgData, ReadVirtual, ValidBase, (PVOID)(buf + skipped), toRead, &bytesRead);
				bytesRead += skipped;
			}
		}
	}
	return bytesRead;
}

static int windbg_write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	DbgEngContext *idbg = fd->data;
	ULONG bytesWritten = 0ULL;
	ITHISCALL (dbgData, WriteVirtual, io->off, (PVOID)buf, count, &bytesWritten);
	return bytesWritten;
}

static int windbg_getpid(RIODesc *fd) {
	DbgEngContext *idbg = fd->data;
	ULONG Id = 0, Class, Qualifier;
	if (SUCCEEDED (ITHISCALL (dbgCtrl, GetDebuggeeType, &Class, &Qualifier))) {
		if (Class == DEBUG_CLASS_KERNEL) {
			ITHISCALL (dbgSysObj, GetCurrentProcessId, &Id);
		} else {
			ITHISCALL (dbgSysObj, GetCurrentProcessSystemId, &Id);
		}
	}
	return Id;
}

static int windbg_gettid(RIODesc *fd) {
	DbgEngContext *idbg = fd->data;
	ULONG Id = 0, Class, Qualifier;
	if (SUCCEEDED (ITHISCALL (dbgCtrl, GetDebuggeeType, &Class, &Qualifier))) {
		if (Class == DEBUG_CLASS_KERNEL) {
			ITHISCALL (dbgSysObj, GetCurrentThreadId, &Id);
		} else {
			ITHISCALL (dbgSysObj, GetCurrentThreadSystemId, &Id);
		}
	}
	return Id;
}

static bool windbg_getbase(RIODesc *fd, ut64 *base) {
	DbgEngContext *idbg = fd->data;
	*base = idbg->processBase;
	return true;
}

static char *windbg_system(RIO *io, RIODesc *fd, const char *cmd) {
	DbgEngContext *idbg = fd->data;
	if (R_STR_ISEMPTY (cmd) || !strncmp ("pid", cmd, 3)) {
		return NULL;
	}
	ITHISCALL (dbgCtrl, Execute, DEBUG_OUTCTL_ALL_CLIENTS, cmd, DEBUG_EXECUTE_DEFAULT);
	return NULL;
}

RIOPlugin r_io_plugin_windbg = {
	.name = "windbg",
	.desc = "WinDBG (DbgEng.dll) based io plugin for Windows",
	.license = "LGPL3",
	.uris = WINDBGURI,
	.isdbg = true,
	.init = windbg_init,
	.open = windbg_open,
	.lseek = windbg_lseek,
	.read = windbg_read,
	.write = windbg_write,
	.system = windbg_system,
	.close = windbg_close,
	.getpid = windbg_getpid,
	.gettid = windbg_gettid,
	.getbase = windbg_getbase,
	.check = windbg_check,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_windbg,
	.version = R2_VERSION
};
#endif
