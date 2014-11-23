#include <r_core.h>

#if __WINDOWS__
#include <windows.h>
#endif

static RCore *core = NULL;

static void sigusr1(int s) {
	RCoreFile *fd = r_core_file_open (core, "self://", R_IO_RW, 0);
	r_core_prompt_loop (core);
	r_core_file_close (core, fd);
}

#if __UNIX__
static void _libwrap_init() __attribute__ ((constructor));
static void _libwrap_init() {
	signal (SIGUSR1, sigusr1);
	printf ("libr2 initialized. send SIGUSR1 to %d in order to reach the r2 prompt\n", getpid ());
	printf ("kill -USR1 %d\n", getpid());
	core = r_core_new ();
	r_core_loadlibs (core, R_CORE_LOADLIBS_ALL, NULL);
	// TODO: maybe reopen every time a signal is spawned to reload memory regions information
	// TODO: open io_self
}
#elif __WINDOWS__
void alloc_console() {
	CONSOLE_SCREEN_BUFFER_INFO coninfo;
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD lpMode;

	AllocConsole();
	GetConsoleMode(hStdin, &lpMode);
	SetConsoleMode(hStdin, lpMode & (~ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT));
	GetConsoleScreenBufferInfo(hStdin, &coninfo);
	coninfo.dwSize.Y = 4096;
	SetConsoleScreenBufferSize(hStdin, coninfo.dwSize);

	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);
}

void start_r2() {
	core = r_core_new ();
	r_core_loadlibs (core, R_CORE_LOADLIBS_ALL, NULL);
	RCoreFile *fd = r_core_file_open (core, "self://", R_IO_RW, 0);
	r_core_prompt_loop (core);
	r_core_file_close (core, fd);
}

/**
 * Neat little helper function to later enable injecting without
 * a .exe
 * simply call: rundll32.exe libr2.dll,rundll_inject 0,0,0,0
 * TODO: implement all injecting methods
 */
void rundll_inject(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD result, LPVOID lpReserved) {
	switch (result) {
		case DLL_PROCESS_DETACH:
			break;
		case DLL_PROCESS_ATTACH:
			alloc_console();
			start_r2();
			break;
	}
	return 1;
}
#endif
