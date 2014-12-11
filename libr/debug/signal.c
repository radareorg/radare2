/* radare - LGPL - Copyright 2014 - pancake */

#include <r_debug.h>

#define DB dbg->sgnls

// TODO: this must be done by the debugger plugin
static struct {
	const char *k;
	const char *v;
} signals[] = {
	// hardcoded from linux
	{ "SIGHUP", "1" },
	{ "SIGINT", "2" },
	{ "SIGQUIT", "3" },
	{ "SIGILL", "4" },
	{ "SIGTRAP", "5" },
	{ "SIGABRT", "6" },
	{ "SIGIOT", "6" },
	{ "SIGBUS", "7" },
	{ "SIGFPE", "8" },
	{ "SIGKILL", "9" },
	{ "SIGUSR1", "10" },
	{ "SIGSEGV", "11" },
	{ "SIGUSR2", "12" },
	{ "SIGPIPE", "13" },
	{ "SIGALRM", "14" },
	{ "SIGTERM", "15" },
	{ "SIGSTKFLT", "16" },
	{ "SIGCHLD", "17" },
	{ "SIGCONT", "18" },
	{ "SIGSTOP", "19" },
	{ "SIGTSTP", "20" },
	{ "SIGTTIN", "21" },
	{ "SIGTTOU", "22" },
	{ "SIGURG", "23" },
	{ "SIGXCPU", "24" },
	{ "SIGXFSZ", "25" },
	{ "SIGVTALRM", "26" },
	{ "SIGPROF", "27" },
	{ "SIGWINCH", "28" },
	{ "SIGIO", "29" },
	{ "SIGPOLL", "SIGIO" },
	{ "SIGLOST", "29" },
	{ "SIGPWR", "30" },
	{ "SIGSYS", "31" },
	{ "SIGRTMIN", "32" },
	{ "SIGRTMAX", "NSIG" },
	{ "SIGSTKSZ", "8192" },
	{ NULL }
};

R_API void r_debug_signal_init(RDebug *dbg) {
	int i;
	// XXX
	DB = sdb_new (NULL, "signals", 0);
	for (i=0; signals[i].k; i++) {
		sdb_set (DB, signals[i].k, signals[i].v, 0);
		sdb_set (DB, signals[i].v, signals[i].k, 0);
	}
}

static int siglistcb (void *p, const char *k, const char *v) {
	static char key[32] = "cfg.";
	RDebug *dbg = (RDebug *)p;
	int mode = dbg->_mode;
	int opt;
	if (atoi (k)>0) {
		strcpy (key+4, k);
		opt = sdb_num_get (DB, key, 0);
		if (opt) {
			r_cons_printf ("%s %s", k, v);
			if (opt & R_DBG_SIGNAL_CONT)
				r_cons_strcat (" cont");
			if (opt & R_DBG_SIGNAL_SKIP)
				r_cons_strcat (" skip");
			r_cons_newline ();
		} else {
			if (mode == 0)
				r_cons_printf ("%s %s\n", k, v);
		}
	}
	return 1;
}

R_API void r_debug_signal_list(RDebug *dbg, int mode) {
	dbg->_mode = mode;
	sdb_foreach (DB, siglistcb, dbg);
	dbg->_mode = 0;
}

R_API int r_debug_signal_resolve(RDebug *dbg, const char *signame) {
	int ret;
	char *name;
	if (strchr (signame, '.'))
		return 0;
	name = strdup (signame);
	r_str_case (name, R_TRUE);
	if (strncmp (name, "SIG", 3))
		name = r_str_prefix (name, "SIG");
	ret = (int)sdb_num_get (DB, name, 0);
	free (name);
	return ret;
}

R_API const char *r_debug_signal_resolve_i(RDebug *dbg, int signum) {
	char k[32];
	snprintf (k, sizeof (k), "%d", signum);
	return sdb_const_get (DB, k, 0);
}

R_API int r_debug_signal_send(RDebug *dbg, int num) {
	return r_sandbox_kill (dbg->pid, num);
}

R_API void r_debug_signal_setup(RDebug *dbg, int num, int opt) {
	sdb_queryf (DB, "cfg.%d=%d", num, opt);
}

R_API int r_debug_signal_what(RDebug *dbg, int num) {
	char k[32];
	snprintf (k, sizeof (k), "cfg.%d", num);
	return sdb_num_get (DB, k, 0);
}

R_API int r_debug_signal_set(RDebug *dbg, int num, ut64 addr) {
	// TODO
	// r_debug_syscall (dbg, "signal", "addr");
	return 0;
}

/* TODO rename to _kill_ -> _signal_ */
R_API RList *r_debug_kill_list(RDebug *dbg) {
	if (dbg->h->kill_list)
		return dbg->h->kill_list (dbg);
	return NULL;
}

R_API int r_debug_kill_setup(RDebug *dbg, int sig, int action) {
	eprintf ("TODO: set signal handlers of child\n");
	// TODO: must inject code to call signal()
#if 0
	if (dbg->h->kill_setup)
		return dbg->h->kill_setup (dbg, sig, action);
#endif
	// TODO: implement r_debug_kill_setup
	return R_FALSE;
}

