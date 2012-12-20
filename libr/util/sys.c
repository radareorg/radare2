/* radare - LGPL - Copyright 2009-2012 - pancake */

#include <sys/types.h>
#include <dirent.h>
#include <r_types.h>
#include <r_util.h>
#if __linux__ && __GNU_LIBRARY__
# include <execinfo.h>
#endif
#if __UNIX__
# include <sys/wait.h>
# include <sys/stat.h>
# include <errno.h>
# include <signal.h>
#elif __WINDOWS__
# include <io.h>
#endif

/* TODO: import stuff fron bininfo/p/bininfo_addr2line */
/* TODO: check endianness issues here */
R_API ut64 r_sys_now(void) {
	ut64 ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 32;
	ret += now.tv_usec;
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
	struct dirent *entry;
	DIR *dir;
	if (!path || (r_sandbox_enable (0) && !r_sandbox_check_path (path)))
		return NULL;
	dir = opendir (path);
	if (dir) {
		RList *list = r_list_new ();
		if (list) {
			list->free = free;
			while ((entry = readdir (dir))) {
				r_list_append (list, strdup (entry->d_name));
			}
			closedir (dir);
			return list;
		}
	}
	return NULL;
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

R_API void r_sys_backtrace(void) {
#if __linux__ && __GNU_LIBRARY__
        void *array[10];
        size_t i, size = backtrace (array, 10);
        char **strings = backtrace_symbols (array, size);
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
	return sleep(secs);
#else
	Sleep (secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs) {
#if __UNIX__
	return usleep (usecs);
#else
	Sleep (usecs); // W32
	return 0;
#endif
}

R_API int r_sys_setenv(const char *key, const char *value) {
#if __UNIX__
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
#if __WINDOWS__
	static char envbuf[1024];
	envbuf[0] = 0;
	GetEnvironmentVariable (key, (LPSTR)&envbuf, sizeof (envbuf));
	// TODO: handle return value of GEV
	return *envbuf? strdup (envbuf): NULL;
#else
	char *b = getenv (key);
	return b? strdup (b): NULL;
#endif
}

R_API char *r_sys_getdir(void) {
#if __WINDOWS__
	char *cwd = _getcwd (NULL, 0);
#else
	char *cwd = getcwd (NULL, 0);
#endif
	return cwd? strdup (cwd): NULL;
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
			return R_FALSE;
		}
	}
	if (pipe (sh_err)) {
		close (sh_in[0]);
		close (sh_in[1]);
		close (sh_out[0]);
		close (sh_out[1]);
		return R_FALSE;
	}

	switch ((pid=fork ())) {
	case -1:
		return R_FALSE;
	case 0:
		dup2 (sh_in[0], 0); close (sh_in[0]); close (sh_in[1]);
		if (output) { dup2 (sh_out[1], 1); close (sh_out[0]); close (sh_out[1]); }
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
				if (len) *len += bytes;
				outputptr = r_str_concat (outputptr, buffer);
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if (read (sh_err[0], buffer, sizeof (buffer)-1) == 0) break;
				*sterr = r_str_concat (*sterr, buffer);
			} else if (FD_ISSET (sh_in[1], &wfds) && inputptr && *inputptr) {
				bytes = write (sh_in[1], inputptr, strlen (inputptr));
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
			eprintf ("%s: command '%s' returned !0\n", __func__, cmd);
			return R_FALSE;
		}

		if (output) {
			*output = outputptr;
		} else if (outputptr) {
			free(outputptr);
		}
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

// TODO: use array :P
R_API int r_sys_arch_id(const char *arch) {
	if (!strcmp (arch, "x86")) return R_SYS_ARCH_X86;
	if (!strcmp (arch, "arm")) return R_SYS_ARCH_ARM;
	if (!strcmp (arch, "ppc")) return R_SYS_ARCH_PPC;
	if (!strcmp (arch, "m68k")) return R_SYS_ARCH_M68K;
	if (!strcmp (arch, "java")) return R_SYS_ARCH_JAVA;
	if (!strcmp (arch, "mips")) return R_SYS_ARCH_MIPS;
	if (!strcmp (arch, "sparc")) return R_SYS_ARCH_SPARC;
	if (!strcmp (arch, "csr")) return R_SYS_ARCH_CSR;
	if (!strcmp (arch, "msil")) return R_SYS_ARCH_MSIL;
	if (!strcmp (arch, "objd")) return R_SYS_ARCH_OBJD;
	if (!strcmp (arch, "bf")) return R_SYS_ARCH_BF;
	if (!strcmp (arch, "sh")) return R_SYS_ARCH_SH;
	if (!strcmp (arch, "avr")) return R_SYS_ARCH_AVR;
	if (!strcmp (arch, "dalvik")) return R_SYS_ARCH_DALVIK;
	if (!strcmp (arch, "z80")) return R_SYS_ARCH_Z80;
	if (!strcmp (arch, "arc")) return R_SYS_ARCH_ARC;
	if (!strcmp (arch, "i8080")) return R_SYS_ARCH_I8080;
	if (!strcmp (arch, "rar")) return R_SYS_ARCH_RAR;
	return 0;
}

R_API const char *r_sys_arch_str(int arch) {
	if (arch & R_SYS_ARCH_X86) return "x86";
	if (arch & R_SYS_ARCH_ARM) return "arm";
	if (arch & R_SYS_ARCH_PPC) return "ppc";
	if (arch & R_SYS_ARCH_M68K) return "m68k";
	if (arch & R_SYS_ARCH_JAVA) return "java";
	if (arch & R_SYS_ARCH_MIPS) return "mips";
	if (arch & R_SYS_ARCH_SPARC) return "sparc";
	if (arch & R_SYS_ARCH_CSR) return "csr";
	if (arch & R_SYS_ARCH_MSIL) return "msil";
	if (arch & R_SYS_ARCH_OBJD) return "objd";
	if (arch & R_SYS_ARCH_BF) return "bf";
	if (arch & R_SYS_ARCH_SH) return "sh";
	if (arch & R_SYS_ARCH_AVR) return "avr";
	if (arch & R_SYS_ARCH_DALVIK) return "dalvik";
	if (arch & R_SYS_ARCH_Z80) return "z80";
	if (arch & R_SYS_ARCH_ARC) return "arc";
	if (arch & R_SYS_ARCH_I8080) return "i8080";
	if (arch & R_SYS_ARCH_RAR) return "rar";
	return "none";
}

R_API int r_sys_run(const ut8 *buf, int len) {
	const int sz = 4096;
	int ret, (*cb)();
	ut8 *ptr, *p = malloc ((sz+len)<<1);
	ptr = (ut8*)R_MEM_ALIGN (p);
	if (!ptr) {
		free (p);
		return R_FALSE;
	}
	memcpy (ptr, buf, sz);
	r_mem_protect (ptr, sz, "rx");
	r_mem_protect (ptr, sz, "rwx"); // try, ignore if fail
	cb = (void*)ptr;
	ret = cb ();
	free (p);
	return ret;
}
