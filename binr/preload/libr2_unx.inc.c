/* radare - LGPL - Copyright 2014-2026 - pancake */

static RIODesc *openself(bool refresh) {
	RIODesc *fd = r_io_desc_get_byuri (core->io, "self://");
	if (fd) {
		if (refresh) {
			const int oldfd = fd->fd;
			if (!r_io_reopen (core->io, oldfd, R_PERM_RW, 0)) {
				return fd;
			}
			fd = r_io_desc_get (core->io, oldfd);
		}
		return fd;
	}
	return r_core_file_open (core, "self://", R_PERM_RW, 0);
}

static void sigusr1(int s) {
	(void)s;
	(void)openself (true);
	r_core_prompt_loop (core);
}

static void sigusr2(int s) {
	(void)s;
	(void)openself (true);
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
	(void)openself (false);
	if (web) {
		r_core_cmd0 (core, "=H&");
		r_sys_setenv ("RARUN2_WEB", NULL);
		free (web);
	}
}
