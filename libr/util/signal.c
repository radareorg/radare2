#include <r_util.h>

#include <signal.h>
#include <stddef.h>

static struct {
	const char *name;
	int code;
} signals[] = {
	{ "SIGHUP", SIGHUP },
	{ "SIGINT", SIGINT },
	{ "SIGQUIT", SIGQUIT },
	{ "SIGILL", SIGILL },
	{ "SIGTRAP", SIGTRAP },
	{ "SIGABRT", SIGABRT },
	{ "SIGBUS", SIGBUS },
	{ "SIGFPE", SIGFPE },
	{ "SIGKILL", SIGKILL },
	{ "SIGUSR1", SIGUSR1 },
	{ "SIGSEGV", SIGSEGV },
	{ "SIGUSR2", SIGUSR2 },
	{ "SIGPIPE", SIGPIPE },
	{ "SIGALRM", SIGALRM },
	{ "SIGTERM", SIGTERM },
	{ "SIGSTKFLT", SIGSTKFLT },
	{ "SIGCHLD", SIGCHLD },
	{ "SIGCONT", SIGCONT },
	{ "SIGSTOP", SIGSTOP },
	{ "SIGTSTP", SIGTSTP },
	{ "SIGTTIN", SIGTTIN },
	{ "SIGTTOU", SIGTTOU },
	{ "SIGURG", SIGURG },
	{ "SIGXCPU", SIGXCPU },
	{ "SIGXFSZ", SIGXFSZ },
	{ "SIGVTALRM", SIGVTALRM },
	{ "SIGPROF", SIGPROF },
#if __LINUX__
	{ "SIGWINCH", SIGWINCH },
	{ "SIGIO", SIGIO },
	{ "SIGPWR", SIGPWR },
	{ "SIGSTKSZ", SIGSTKSZ },
#endif
	{ "SIGPOLL", SIGPOLL },
	{ "SIGSYS", SIGSYS },
	{ NULL }
};

R_API int r_signal_from_string (const char *e) {
	int i;
	for (i = 1; signals[i].name; i++) {
		const char *str = signals[i].name;
		if (!strcmp (e, str)) {
			return signals[i].code;
		}
	}

	return atoi (e);
}

R_API const char* r_signal_to_string (int code) {
  int i;
  for (i = 1; signals[i].name; i++) {
	if (signals[i].code == code) {
	  return signals[i].name;
	}
  }

  return NULL;
}
