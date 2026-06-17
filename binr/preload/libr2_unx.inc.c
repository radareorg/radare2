/* radare - LGPL - Copyright 2014-2026 - pancake */

// XXX check if its already opened
static RIODesc *openself(void) {
	RIODesc *fd = NULL;
	char *out = r_core_cmd_str (core, "o");
	if (out) {
		if (!strstr (out, "self://")) {
			fd = r_core_file_open (core, "self://", R_PERM_RW, 0);
		}
		free (out);
	}
	return fd;
}

static void sigusr1(int s) {
	RIODesc *fd = openself ();
	r_core_prompt_loop (core);
	if (fd) {
		r_io_desc_close (fd);
	}
}

static void sigusr2(int s) {
	(void)openself ();
	r_core_cmd0 (core, "=H&");
}

static void _libwrap_init() __attribute__((constructor));
static void _libwrap_init(void) {
	char *web;
	r_sys_signal (SIGUSR1, sigusr1);
	r_sys_signal (SIGUSR2, sigusr2);
	int pid = r_sys_getpid ();
	printf ("libr2 initialized. send SIGUSR1 to %d in order to reach the r2 prompt\n", pid);
	printf ("kill -USR1 %d\n", pid);
	fflush (stdout);
	web = r_sys_getenv ("RARUN2_WEB");
	core = r_core_new ();
	r_core_loadlibs (core, R_LIB_LOAD_ALL, NULL);
	if (web) {
		r_core_cmd0 (core, "=H&");
		r_sys_setenv ("RARUN2_WEB", NULL);
		free (web);
	}
	// TODO: maybe reopen every time a signal is spawned to reload memory regions information
	// TODO: open io_self
}
