/* radare - LGPL - Copyright 2014-2026 - pancake */

#include <windows.h>
#include <wchar.h>

#if defined(_MSC_VER) && defined(_M_IX86)
#pragma comment(linker, "/EXPORT:rundll_inject=_rundll_inject@16")
#pragma comment(linker, "/EXPORT:rundll_injectA=_rundll_injectA@16")
#pragma comment(linker, "/EXPORT:rundll_injectW=_rundll_injectW@16")
#elif defined(__GNUC__) && defined(__i386__)
// rundll32 looks up the undecorated export name, but x86 stdcall symbols are decorated.
__asm__ (".section .drectve\n.ascii \" -export:rundll_inject=_rundll_inject@16\"");
__asm__ (".section .drectve\n.ascii \" -export:rundll_injectA=_rundll_injectA@16\"");
__asm__ (".section .drectve\n.ascii \" -export:rundll_injectW=_rundll_injectW@16\"");
#endif

static const WCHAR *rundll_skip_spaces(const WCHAR *p) {
	while (p && (*p == L' ' || *p == L'\t')) {
		p++;
	}
	return p;
}

static const WCHAR *rundll_skip_arg_sep(const WCHAR *p) {
	p = rundll_skip_spaces (p);
	if (p && *p == L',') {
		p++;
	}
	return rundll_skip_spaces (p);
}

static void rundll_print_inject_usage(void) {
	R_LOG_ERROR ("Usage: rundll32.exe libr2.dll,rundll_inject <pid> [path-to-libr2.dll]");
}

static bool rundll_copy_path(const WCHAR *input, WCHAR *path, size_t path_len) {
	const WCHAR *start, *end;
	input = rundll_skip_spaces (input);
	if (!input || !*input) {
		return false;
	}
	if (*input == L'"') {
		start = input + 1;
		end = wcschr (start, L'"');
		if (!end) {
			end = start + wcslen (start);
		}
	} else {
		start = input;
		end = start;
		while (*end && *end != L' ' && *end != L'\t') {
			end++;
		}
	}
	size_t len = end - start;
	if (len < 1 || len >= path_len) {
		return false;
	}
	memcpy (path, start, len * sizeof (WCHAR));
	path[len] = 0;
	return true;
}

static bool rundll_get_module_path(HINSTANCE hinst, WCHAR *path, DWORD path_len) {
	DWORD len = GetModuleFileNameW ((HMODULE)hinst, path, path_len);
	if (!len || len >= path_len) {
		r_sys_perror ("rundll_inject/GetModuleFileNameW");
		return false;
	}
	return true;
}

static bool rundll_parse_inject_args(HINSTANCE hinst, const WCHAR *cmdline, DWORD *pid, WCHAR *path, DWORD path_len) {
	const WCHAR *p = rundll_skip_spaces (cmdline);
	if (!p || !*p || *p == L'?') {
		return false;
	}
	if (!wcscmp (p, L"-h") || !wcscmp (p, L"--help")) {
		return false;
	}
	WCHAR *end = NULL;
	unsigned long parsed_pid = wcstoul (p, &end, 0);
	if (end == p || parsed_pid == 0) {
		return false;
	}
	*pid = (DWORD)parsed_pid;
	p = rundll_skip_arg_sep (end);
	if (p && *p) {
		return rundll_copy_path (p, path, path_len);
	}
	return rundll_get_module_path (hinst, path, path_len);
}

static bool rundll_inject_loadlibrary(DWORD pid, const WCHAR *path) {
	bool ok = false;
	HANDLE process = OpenProcess (
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, pid);
	if (!process) {
		r_sys_perror ("rundll_inject/OpenProcess");
		return false;
	}
	SIZE_T path_size = (wcslen (path) + 1) * sizeof (WCHAR);
	LPVOID remote_path = VirtualAllocEx (process, NULL, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remote_path) {
		r_sys_perror ("rundll_inject/VirtualAllocEx");
		CloseHandle (process);
		return false;
	}
	SIZE_T written = 0;
	if (!WriteProcessMemory (process, remote_path, path, path_size, &written)) {
		r_sys_perror ("rundll_inject/WriteProcessMemory");
		goto beach;
	}
	if (written != path_size) {
		R_LOG_ERROR ("Short WriteProcessMemory in rundll_inject");
		goto beach;
	}
	HMODULE kernel32 = GetModuleHandleW (L"kernel32.dll");
	if (!kernel32) {
		r_sys_perror ("rundll_inject/GetModuleHandleW");
		goto beach;
	}
	FARPROC load_library = GetProcAddress (kernel32, "LoadLibraryW");
	if (!load_library) {
		r_sys_perror ("rundll_inject/GetProcAddress");
		goto beach;
	}
	HANDLE thread = CreateRemoteThread (process, NULL, 0, (LPTHREAD_START_ROUTINE)load_library, remote_path, 0, NULL);
	if (!thread) {
		r_sys_perror ("rundll_inject/CreateRemoteThread");
		goto beach;
	}
	if (WaitForSingleObject (thread, INFINITE) == WAIT_FAILED) {
		r_sys_perror ("rundll_inject/WaitForSingleObject");
		CloseHandle (thread);
		goto beach;
	}
	DWORD exit_code = 0;
	if (!GetExitCodeThread (thread, &exit_code)) {
		r_sys_perror ("rundll_inject/GetExitCodeThread");
		CloseHandle (thread);
		goto beach;
	}
	CloseHandle (thread);
	if (!exit_code) {
		R_LOG_ERROR ("Remote LoadLibraryW failed for pid %lu", (unsigned long)pid);
		goto beach;
	}
	ok = true;
	R_LOG_INFO ("Injected libr2 into pid %lu", (unsigned long)pid);
beach:
	VirtualFreeEx (process, remote_path, 0, MEM_RELEASE);
	CloseHandle (process);
	return ok;
}

static void rundll_inject_w(HINSTANCE hinst, const WCHAR *cmdline) {
	DWORD pid = 0;
	WCHAR path[MAX_PATH];
	if (!rundll_parse_inject_args (hinst, cmdline, &pid, path, R_ARRAY_SIZE (path))) {
		rundll_print_inject_usage ();
		return;
	}
	rundll_inject_loadlibrary (pid, path);
}

static WCHAR *rundll_ansi_to_wide(const char *cmdline) {
	int len = MultiByteToWideChar (CP_ACP, 0, cmdline, -1, NULL, 0);
	if (len < 1) {
		r_sys_perror ("rundll_inject/MultiByteToWideChar");
		return NULL;
	}
	WCHAR *wide = calloc (len, sizeof (WCHAR));
	if (!wide) {
		R_LOG_ERROR ("Cannot allocate rundll32 command line");
		return NULL;
	}
	if (!MultiByteToWideChar (CP_ACP, 0, cmdline, -1, wide, len)) {
		r_sys_perror ("rundll_inject/MultiByteToWideChar");
		free (wide);
		return NULL;
	}
	return wide;
}

static bool running_from_rundll32(void) {
	WCHAR path[MAX_PATH];
	DWORD len = GetModuleFileNameW (NULL, path, R_ARRAY_SIZE (path));
	if (!len || len >= R_ARRAY_SIZE (path)) {
		return false;
	}
	WCHAR *base = wcsrchr (path, L'\\');
	base = base? base + 1: path;
	return !lstrcmpiW (base, L"rundll32.exe");
}

void alloc_console(void) {
	CONSOLE_SCREEN_BUFFER_INFO coninfo;
	HANDLE hStdin = GetStdHandle (STD_INPUT_HANDLE);
	DWORD lpMode;

	AllocConsole ();
	GetConsoleMode (hStdin, &lpMode);
	SetConsoleMode (hStdin, lpMode & (~ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT));
	GetConsoleScreenBufferInfo (hStdin, &coninfo);
	coninfo.dwSize.Y = 4096;
	SetConsoleScreenBufferSize (hStdin, coninfo.dwSize);

	freopen ("conin$", "r", stdin);
	freopen ("conout$", "w", stdout);
	freopen ("conout$", "w", stderr);
}

static void start_r2(void) {
	core = r_core_new ();
	r_core_loadlibs (core, R_LIB_LOAD_ALL, NULL);
	RIODesc *fd = r_core_file_open (core, "self://", R_PERM_RW, 0);
	r_core_prompt_loop (core);
	if (fd) {
		r_io_desc_close (fd);
	}
}

static DWORD WINAPI start_r2_thread(LPVOID user) {
	(void)user;
	alloc_console ();
	start_r2 ();
	return 0;
}

static void start_r2_async(void) {
	HANDLE thread = CreateThread (NULL, 0, start_r2_thread, NULL, 0, NULL);
	if (thread) {
		CloseHandle (thread);
	} else {
		r_sys_perror ("libr2/CreateThread");
	}
}

/**
 * Neat little helper function to later enable injecting without
 * a .exe
 * simply call: rundll32.exe libr2.dll,rundll_inject <pid> [path-to-libr2.dll]
 */
R_API void CALLBACK rundll_inject(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
	(void)hwnd;
	(void)nCmdShow;
	WCHAR *cmdline = rundll_ansi_to_wide (lpszCmdLine? lpszCmdLine: "");
	if (cmdline) {
		rundll_inject_w (hinst, cmdline);
		free (cmdline);
	}
}

R_API void CALLBACK rundll_injectA(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
	rundll_inject (hwnd, hinst, lpszCmdLine, nCmdShow);
}

R_API void CALLBACK rundll_injectW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	(void)hwnd;
	(void)nCmdShow;
	rundll_inject_w (hinst, lpszCmdLine? lpszCmdLine: L"");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD result, LPVOID lpReserved) {
	(void)lpReserved;
	switch (result) {
	case DLL_PROCESS_DETACH:
		break;
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls (hModule);
		if (!running_from_rundll32 ()) {
			start_r2_async ();
		}
		break;
	}
	return 1;
}
