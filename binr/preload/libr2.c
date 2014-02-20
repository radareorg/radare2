#include <r_core.h>

static RCore *core = NULL;

static void sigusr1(int s) {
	RCoreFile *fd = r_core_file_open (core, "self://", R_IO_RW, 0);
	r_core_prompt_loop (core);
	r_core_file_close (core, fd);
}

static void _libwrap_init() __attribute__ ((constructor));
static void _libwrap_init() {
	signal (SIGUSR1, sigusr1);
	printf ("libr2 initialized. send SIGUSR1 to %d in order to reach the r2 prompt\n", getpid ());
	printf ("kill -USR1 %d\n", getpid());
	core = r_core_new ();
	// TODO: maybe reopen every time a signal is spawned to reload memory regions information
	// TODO: open io_self
}
