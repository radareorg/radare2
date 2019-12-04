#include <r_types.h>

typedef struct _window {
	ut32 pid;
	ut32 tid;
	HANDLE h;
	char *name;
	ut64 proc;
} window;

R_API bool r_w32_add_winmsg_breakpoint(RDebug *dbg, char *name);
R_API void r_w32_identify_window(void);
R_API void r_w32_print_windows(RDebug *dbg);
