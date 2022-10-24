/* radare - LGPL - Copyright 2017-2020 - polsha3 */

#include <r_util.h>

#include <signal.h>
#include <stddef.h>

static struct {
	const char *name;
	int code;
} signals[] = {
	{ "SIGINT", SIGINT },
	{ "SIGILL", SIGILL },
	{ "SIGABRT", SIGABRT },
	{ "SIGFPE", SIGFPE },
	{ "SIGSEGV", SIGSEGV },
	{ "SIGTERM", SIGTERM },
#if __linux__
	{ "SIGWINCH", SIGWINCH },
	{ "SIGIO", SIGIO },
	{ "SIGPWR", SIGPWR },
	{ "SIGPOLL", SIGPOLL },
#endif
#if !__WINDOWS__
	{ "SIGHUP", SIGHUP },
	{ "SIGQUIT", SIGQUIT },
	{ "SIGTRAP", SIGTRAP },
	{ "SIGBUS", SIGBUS },
	{ "SIGKILL", SIGKILL },
	{ "SIGUSR1", SIGUSR1 },
	{ "SIGUSR2", SIGUSR2 },
	{ "SIGPIPE", SIGPIPE },
	{ "SIGALRM", SIGALRM },
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
	{ "SIGSYS", SIGSYS },
#endif
	{ NULL }
};

R_API int r_signal_from_string(const char *e) {
	int i;
	for (i = 1; signals[i].name; i++) {
		const char *str = signals[i].name;
		if (!strcmp (e, str)) {
			return signals[i].code;
		}
	}
	return atoi (e);
}

R_API const char* r_signal_tostring(int code) {
	int i;
	for (i = 1; signals[i].name; i++) {
		if (signals[i].code == code) {
			return signals[i].name;
		}
	}
	return NULL;
}

#if __UNIX__
R_API void r_signal_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask) {
#if HAVE_PTHREAD
	pthread_sigmask (how, newmask, oldmask);
#endif
}
#endif

R_API const char *r_signal_to_human(int signum) {
#if __UNIX__
	switch (signum) {
	case SIGALRM: return "Alarm Clock";
	case SIGBUS: return "Bus Error";
	case SIGCHLD: return "Child";
	case SIGCONT: return "Continue Execution";
#ifdef SIGEMT
	case SIGEMT: return "Hardware Error";
#endif
	case SIGFPE: return "Floating Point Exception";
	case SIGHUP: return "Hangup";
	case SIGILL: return "Illegal instruction";
	case SIGABRT: return "Abort";
	case SIGKILL: return "Killed";
	case SIGPROF: return "Profiling Timer Expired";
#if __linux__
	case SIGPWR: return "Power Failure";
	case SIGPOLL: return "Pollable Event (Same as SIGIO)";
	// case SIGIO: return "IO ready";
#endif
	case SIGQUIT: return "Quit";
	case SIGSEGV: return "Segmentation fault";
	case SIGSTOP: return "Stopped";
	case SIGSYS: return "Bad system call";
	case SIGTERM: return "Terminated";
	case SIGTSTP: return "Stopped";
	case SIGPIPE: return "Broken pipe";
	case SIGTTIN: return "Stopped";
	case SIGTTOU: return "Stopped";
	case SIGURG: return "Urgent";
	case SIGUSR1: return "User Defined Signal 1";
	case SIGUSR2: return "User Defined Signal 2";
	case SIGVTALRM: return "Virtual Timer Expired";
	case SIGWINCH: return "Window Changed Size";
	case SIGXCPU: return "CPU time limit exceeded";
	case SIGXFSZ: return "File size limit exceeded";
	default: return "unhandled";
	}
#else
	return "unhandled";
#endif
}

