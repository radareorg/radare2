#include <r_types.h>

typedef struct _window {
	DWORD pid;
	DWORD tid;
	HANDLE h;
	char *name;
	ut64 proc;
} window;

R_API bool r_w32_add_winmsg_breakpoint(RDebug *dbg, const char *input);
R_API void r_w32_identify_window(void);
R_API void r_w32_print_windows(RDebug *dbg);
