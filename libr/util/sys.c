/* radare - LGPL - Copyright 2009-2014 - pancake */

#if defined(__NetBSD__)
# include <sys/param.h>
# if __NetBSD_Prereq__(7,0,0)
#  define NETBSD_WITH_BACKTRACE
# endif
#endif
#include <sys/types.h>
#include <dirent.h>
#include <r_types.h>
#include <r_util.h>
#if (__linux__ && __GNU_LIBRARY__) || defined(NETBSD_WITH_BACKTRACE)
# include <execinfo.h>
#endif
#if __APPLE__
#include <errno.h>
#include <execinfo.h>
// iOS dont have this we cant hardcode
// #include <crt_externs.h>
extern char ***_NSGetEnviron(void);
# ifndef PROC_PIDPATHINFO_MAXSIZE
#  define PROC_PIDPATHINFO_MAXSIZE 1024
int proc_pidpath(int pid, void * buffer, ut32 buffersize);
//#  include <libproc.h>
# endif
#endif
#if __UNIX__ || __CYGWIN__
# include <sys/wait.h>
# include <sys/stat.h>
# include <errno.h>
# include <signal.h>
#ifdef __HAIKU__
# define Sleep sleep
#endif
#endif
#if __WINDOWS__
# include <io.h>
# include <winbase.h>
#endif

R_LIB_VERSION(r_util);

static const struct {const char* name; ut64 bit;} arch_bit_array[] = {
    {"x86", R_SYS_ARCH_X86},
    {"arm", R_SYS_ARCH_ARM},
    {"ppc", R_SYS_ARCH_PPC},
    {"m68k", R_SYS_ARCH_M68K},
    {"java", R_SYS_ARCH_JAVA},
    {"mips", R_SYS_ARCH_MIPS},
    {"sparc", R_SYS_ARCH_SPARC},
    {"csr", R_SYS_ARCH_CSR},
    {"tms320", R_SYS_ARCH_TMS320},
    {"msil", R_SYS_ARCH_MSIL},
    {"objd", R_SYS_ARCH_OBJD},
    {"bf", R_SYS_ARCH_BF},
    {"sh", R_SYS_ARCH_SH},
    {"avr", R_SYS_ARCH_AVR},
    {"dalvik", R_SYS_ARCH_DALVIK},
    {"z80", R_SYS_ARCH_Z80},
    {"arc", R_SYS_ARCH_ARC},
    {"i8080", R_SYS_ARCH_I8080},
    {"rar", R_SYS_ARCH_RAR},
    {NULL, 0}
};

/* TODO: import stuff fron bininfo/p/bininfo_addr2line */
/* TODO: check endianness issues here */
R_API ut64 r_sys_now(void) {
	ut64 ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 20;
	ret |= now.tv_usec;
	//(sizeof (now.tv_sec) == 4
	return ret;
}

R_API int r_sys_truncate(const char *file, int sz) {
#if __WINDOWS__
	int fd = r_sandbox_open (file, O_RDWR, 0644);
	if (!fd) return R_FALSE;
	ftruncate (fd, sz);
	close (fd);
	return R_TRUE;
#else
	return truncate (file, sz)? R_FALSE: R_TRUE;
#endif
}

R_API RList *r_sys_dir(const char *path) {
	RList *list = NULL;
	struct dirent *entry;
	DIR *dir = r_sandbox_opendir (path);
	if (dir) {
		list = r_list_new ();
		if (list) {
			list->free = free;
			while ((entry = readdir (dir))) {
				r_list_append (list, strdup (entry->d_name));
			}
		}
		closedir (dir);
	}
	return list;
}

R_API char *r_sys_cmd_strf(const char *fmt, ...) {
	char *ret, cmd[4096];
	va_list ap;
	va_start (ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd_str (cmd, NULL, NULL);
	va_end (ap);
	return ret;
}

#ifdef __MAC_10_7
#define APPLE_WITH_BACKTRACE 1
#endif
#ifdef __IPHONE_4_0
#define APPLE_WITH_BACKTRACE 1
#endif

R_API void r_sys_backtrace(void) {
#if (__linux__ && __GNU_LIBRARY__) || (__APPLE__ && APPLE_WITH_BACKTRACE) || defined(NETBSD_WITH_BACKTRACE)
        void *array[10];
        size_t i, size = backtrace (array, 10);
        char **strings = (char **)(size_t)backtrace_symbols (array, size);
        printf ("Backtrace %zd stack frames.\n", size);
        for (i = 0; i < size; i++)
                printf ("%s\n", strings[i]);
        free (strings);
#elif __APPLE__
	void **fp = (void **) __builtin_frame_address (0);
	void *saved_pc = __builtin_return_address (0);
	void *saved_fp = __builtin_frame_address (1);
	int depth = 0;

	printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	fp = saved_fp;
	while (fp != NULL) {
		saved_fp = *fp;
		fp = saved_fp;
		if (*fp == NULL)
			break;
		saved_pc = *(fp + 2);
		printf ("[%d] pc == %p fp == %p\n", depth++, saved_pc, saved_fp);
	}
#else
#warning TODO: r_sys_bt : unimplemented
#endif
}

R_API int r_sys_sleep(int secs) {
#if __UNIX__
	return sleep (secs);
#else
	Sleep (secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs) {
#if __UNIX__
	// unix api uses microseconds
	return usleep (usecs);
#else
	// w32 api uses milliseconds
	usecs /= 1000;
	Sleep (usecs); // W32
	return 0;
#endif
}

R_API int r_sys_setenv(const char *key, const char *value) {
#if __UNIX__ || __CYGWIN__
	if (!key) return 0;
	if (value == NULL) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif __WINDOWS__
	SetEnvironmentVariable (key, (LPSTR)value);
	return 0; // TODO. get ret
#else
#warning r_sys_setenv : unimplemented for this platform
	return 0;
#endif
}

static char *crash_handler_cmd = NULL;

static void signal_handler(int signum) {
	int len;
	char *cmd;
	if (!crash_handler_cmd)
		return;
	len = strlen (crash_handler_cmd)+32;
	cmd = malloc (len);
	snprintf (cmd, len, crash_handler_cmd, getpid ());
	r_sys_backtrace ();
	exit (r_sys_cmd (cmd));
}

static int checkcmd(const char *c) {
	char oc = 0;
	for (;*c;c++) {
		if (oc == '%')
			if (*c!='d' && *c!='%')
				return 0;
		oc = *c;
	}
	return 1;
}

R_API int r_sys_crash_handler(const char *cmd) {
#if __UNIX__
	struct sigaction sigact;
	if (!checkcmd (cmd))
		return R_FALSE;
	free (crash_handler_cmd);
	crash_handler_cmd = strdup (cmd);
	sigact.sa_handler = signal_handler;
	sigemptyset (&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction (SIGINT, &sigact, (struct sigaction *)NULL);

	sigaddset (&sigact.sa_mask, SIGSEGV);
	sigaction (SIGSEGV, &sigact, (struct sigaction *)NULL);

	sigaddset (&sigact.sa_mask, SIGBUS);
	sigaction (SIGBUS, &sigact, (struct sigaction *)NULL);

	sigaddset (&sigact.sa_mask, SIGQUIT);
	sigaction (SIGQUIT, &sigact, (struct sigaction *)NULL);

	sigaddset (&sigact.sa_mask, SIGHUP);
	sigaction (SIGHUP, &sigact, (struct sigaction *)NULL);

	sigaddset (&sigact.sa_mask, SIGKILL);
	sigaction (SIGKILL, &sigact, (struct sigaction *)NULL);
	return R_TRUE;
#else
	return R_FALSE;
#endif
}

R_API char *r_sys_getenv(const char *key) {
#if __WINDOWS__ && !__CYGWIN__
	static char envbuf[1024];
	if (!key) return NULL;
	envbuf[0] = 0;
	GetEnvironmentVariable (key, (LPSTR)&envbuf, sizeof (envbuf));
	// TODO: handle return value of GEV
	return *envbuf? strdup (envbuf): NULL;
#else
	char *b;
	if (!key) return NULL;
	b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

R_API char *r_sys_getdir(void) {
	char *ret;
#if __WINDOWS__
	char *cwd = _getcwd (NULL, 0);
#else
	char *cwd = getcwd (NULL, 0);
#endif
	ret = cwd ? strdup (cwd) : NULL;
	if (cwd)
		free (cwd);
	return ret;
}

R_API int r_sys_chdir(const char *s) {
	return r_sandbox_chdir (s)==0;
}

#if __UNIX__
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	char buffer[1024], *outputptr = NULL;
	char *inputptr = (char *)input;
	int pid, bytes = 0, status;
	int sh_in[2], sh_out[2], sh_err[2];

	if (len) *len = 0;
	if (pipe (sh_in))
		return R_FALSE;
	if (output) {
		if (pipe (sh_out)) {
			close (sh_in[0]);
			close (sh_in[1]);
			close (sh_out[0]);
			close (sh_out[1]);
			return R_FALSE;
		}
	}
	if (pipe (sh_err)) {
		close (sh_in[0]);
		close (sh_in[1]);
		return R_FALSE;
	}

	switch ((pid = fork ())) {
	case -1:
		return R_FALSE;
	case 0:
		dup2 (sh_in[0], 0);
		close (sh_in[0]);
		close (sh_in[1]);
		if (output) {
			dup2 (sh_out[1], 1);
			close (sh_out[0]);
			close (sh_out[1]);
		}
		if (sterr) dup2 (sh_err[1], 2); else close (2);
		close (sh_err[0]); close (sh_err[1]);
		exit (r_sandbox_system (cmd, 0));
	default:
		outputptr = strdup ("");
		if (!outputptr)
			return R_FALSE;
		if (sterr) {
			*sterr = strdup ("");
			if (!*sterr) {
				free (outputptr);
				return R_FALSE;
			}
		}
		if (output) close (sh_out[1]);
		close (sh_err[1]);
		close (sh_in[0]);
		if (!inputptr || !*inputptr)
			close (sh_in[1]);

		// we should handle broken pipes somehow better
		signal (SIGPIPE, SIG_IGN);
		for (;;) {
			fd_set rfds, wfds;
			int nfd;

			FD_ZERO (&rfds);
			FD_ZERO (&wfds);
			if (output)
				FD_SET (sh_out[0], &rfds);
			if (sterr)
				FD_SET (sh_err[0], &rfds);
			if (inputptr && *inputptr)
				FD_SET (sh_in[1], &wfds);
			memset (buffer, 0, sizeof (buffer));
			nfd = select (sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
			if (nfd < 0)
				break;
			if (output && FD_ISSET (sh_out[0], &rfds)) {
				if ((bytes = read (sh_out[0], buffer, sizeof (buffer)-1)) == 0) break;
				buffer[sizeof(buffer) - 1] = '\0';
				if (len) *len += bytes;
				outputptr = r_str_concat (outputptr, buffer);
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if (read (sh_err[0], buffer, sizeof (buffer)-1) == 0) break;
				buffer[sizeof(buffer) - 1] = '\0';
				*sterr = r_str_concat (*sterr, buffer);
			} else if (FD_ISSET (sh_in[1], &wfds) && inputptr && *inputptr) {
				int inputptr_len = strlen (inputptr);
				bytes = write (sh_in[1], inputptr, inputptr_len);
				if (bytes != inputptr_len) {
					break;
				}
				inputptr += bytes;
				if (!*inputptr) {
					close (sh_in[1]);
					/* If neither stdout nor stderr should be captured,
					 * abort now - nothing more to do for select(). */
					if (!output && !sterr) break;
				}
			}
		}
		if (output)
			close (sh_out[0]);
		close (sh_err[0]);
		close (sh_in[1]);
		waitpid (pid, &status, 0);
		if (status != 0) {
			char *escmd = r_str_escape (cmd);
			eprintf ("%s: failed command '%s'\n", __func__, escmd);
			free (escmd);
			return R_FALSE;
		}

		if (output) *output = outputptr;
		else free (outputptr);
		return R_TRUE;
	}
	return R_FALSE;
}
#elif __WINDOWS__
// TODO: fully implement the rest
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	char *result = r_sys_cmd_str_w32 (cmd);
	if (len) *len = 0;
	if (output) *output = result;
	if (result) return R_TRUE;
	return R_FALSE;
}
#else
R_API int r_sys_cmd_str_full(const char *cmd, const char *input, char **output, int *len, char **sterr) {
	eprintf ("r_sys_cmd_str: not yet implemented for this platform\n");
	return R_FALSE;
}
#endif

R_API int r_sys_cmdf (const char *fmt, ...) {
	int ret;
	char cmd[4096];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd (cmd);
	va_end (ap);
	return ret;
}

R_API int r_sys_cmdbg (const char *str) {
#if __UNIX__
	int ret, pid = fork ();
	if (pid == -1) return -1;
	if (pid) return pid;
	ret = r_sandbox_system (str, 0);
	eprintf ("{exit: %d, pid: %d, cmd: \"%s\"}", ret, pid, str);
	exit (0);
	return -1;
#else
#warning r_sys_cmdbg is not implemented for this platform
	return -1;
#endif
}

R_API int r_sys_cmd (const char *str) {
#if __FreeBSD__
	/* freebsd system() is broken */
	int st, pid, fds[2];
	if (pipe (fds))
		return -1;
	pid = vfork ();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		dup2 (1, fds[1]);
		// char *argv[] = { "/bin/sh", "-c", str, NULL};
		// execv (argv[0], argv);
		r_sandbox_system (str, 0);
		_exit (127); /* error */
	} else {
		dup2 (1, fds[0]);
		waitpid (pid, &st, 0);
	}
	return WEXITSTATUS (st);
#else
	return r_sandbox_system (str, 1);
#endif
}

R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len) {
	char *output;
	if (r_sys_cmd_str_full (cmd, input, &output, len, NULL))
		return output;
	return NULL;
}

R_API int r_sys_rmkdir(const char *dir) {
	int ret = R_TRUE;
	char *path = strdup (dir), *ptr = path;
	// XXX: Wrong for w32 (/).. and no errno ?
	if (*ptr=='/') ptr++;
	while ((ptr = strchr (ptr, '/'))) {
		*ptr = 0;
		if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
			eprintf ("r_sys_rmkdir: fail %s\n", dir);
			free (path);
			return R_FALSE;
		}
		*ptr = '/';
		ptr++;
	}
	if (!r_sys_mkdir (path) && r_sys_mkdir_failed ())
		ret = R_FALSE;
	free (path);
	return ret;
}

R_API void r_sys_perror(const char *fun) {
#if __UNIX__
	perror (fun);
#elif __WINDOWS__
	char *lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError ();

	FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL );

	lpDisplayBuf = (LPVOID)LocalAlloc (LMEM_ZEROINIT,
			(lstrlen ((LPCTSTR)lpMsgBuf)+
			lstrlen ((LPCTSTR)fun)+40)*sizeof (TCHAR));
	eprintf ("%s: %s\n", fun, lpMsgBuf);

	LocalFree (lpMsgBuf);
	LocalFree (lpDisplayBuf);
#endif
}

R_API int r_sys_arch_id(const char *arch) {
    int i;
    for (i=0; arch_bit_array[i].name; i++)
        if (!strcmp (arch, arch_bit_array[i].name))
            return arch_bit_array[i].bit;
    return 0;
}

R_API const char *r_sys_arch_str(int arch) {
    int i;
    for (i=0; arch_bit_array[i].name; i++)
        if (arch & arch_bit_array[i].bit)
            return arch_bit_array[i].name;
	return "none";
}

#define USE_FORK 0
R_API int r_sys_run(const ut8 *buf, int len) {
	const int sz = 4096;
	int pdelta, ret, (*cb)();
#if USE_FORK
	int st, pid;
#endif
// TODO: define R_SYS_ALIGN_FORWARD in r_util.h
	ut8 *ptr, *p = malloc ((sz+len)<<1);
	ptr = p;
	pdelta = ((size_t)(p)) & (4096-1);
	if (pdelta)
		ptr += (4096-pdelta);
	if (!ptr || !buf) {
		eprintf ("r_sys_run: Cannot run empty buffer\n");
		free (p);
		return R_FALSE;
	}
	memcpy (ptr, buf, sz);
	r_mem_protect (ptr, sz, "rx");
	//r_mem_protect (ptr, sz, "rwx"); // try, ignore if fail
	cb = (void*)ptr;
#if USE_FORK
#if __UNIX__
	pid = fork ();
	//pid = -1;
#else
	pid = -1;
#endif
	if (pid<0) {
		return cb ();
	} else if (!pid) {
		ret = cb ();
		exit (ret);
		return ret;
	}
	st = 0;
	waitpid (pid, &st, 0);
	if (WIFSIGNALED (st)) {
		int num = WTERMSIG(st);
		eprintf ("Got signal %d\n", num);
		ret = num;
	} else {
		ret = WEXITSTATUS (st);
	}
#else
	ret = cb ();
#endif
	free (p);
	return ret;
}

R_API int r_is_heap (void *p) {
	void *q = malloc (8);
	ut64 mask = UT64_MAX;
	ut64 addr = (ut64)(size_t)q;
	addr>>=16;
	addr<<=16;
	mask>>=16;
	mask<<=16;
	free (q);
	return (((ut64)(size_t)p) == mask);
}

#if __WINDOWS__
static DWORD WINAPI (*gpifn) (HANDLE, LPTSTR, DWORD);
#endif

R_API char *r_sys_pid_to_path(int pid) {
#if __WINDOWS__
	HANDLE psapi = LoadLibrary ("psapi.dll");
	if (!psapi) {
		eprintf ("Error getting the handle to psapi.dll\n");
		return NULL;
	}
	gpifn = GetProcAddress (psapi, "GetProcessImageFileNameA");
	if (!gpifn) {
		eprintf ("Error getting the address of GetProcessImageFileNameA\n");
		return NULL;
	}
	HANDLE handle = NULL;
	TCHAR filename[MAX_PATH];
	handle = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (handle != NULL) {
		if (gpifn (handle, filename, MAX_PATH) == 0) {
			eprintf("Error calling GetProcessImageFileNameA\n");
			CloseHandle (handle);
			return NULL;
		} else {
			CloseHandle (handle);
			return strdup (filename);
		}
	}
	return NULL;
#elif __APPLE__
	char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
	pathbuf[0] = 0;
	int ret = proc_pidpath (pid, pathbuf, sizeof (pathbuf));
	if (ret <= 0)
		return NULL;
	return strdup (pathbuf);
#else
	int ret;
	char buf[128], pathbuf[1024];
#if __FreeBSD__
	snprintf (buf, sizeof (buf), "/proc/%d/file", pid);
#else
	snprintf (buf, sizeof (buf), "/proc/%d/exe", pid);
#endif
	ret = readlink (buf, pathbuf, sizeof (pathbuf)-1);
	if (ret<1)
		return NULL;
	pathbuf[ret] = 0;
	return strdup (pathbuf);
#endif
}

static char** env = NULL;

R_API char **r_sys_get_environ () {
#if __APPLE__
	env = *_NSGetEnviron();
#endif
	// return environ if available??
	if (!env)
		env = r_lib_dl_sym (NULL, "environ");
	return env;
}

R_API void r_sys_set_environ (char **e) {
	env = e;
}

R_API char *r_sys_whoami (char *buf) {
	char _buf[32];
	int pid = getpid ();
	int hasbuf = (buf)? 1: 0;
	if (!hasbuf) buf = _buf;
	sprintf (buf, "pid%d", pid);
	return hasbuf? buf: strdup (buf);
}

R_API int r_sys_getpid() {
#if __UNIX__
	return getpid ();
#else
#warning r_sys_getpid not implemented for this platform
	return -1;
#endif
}
