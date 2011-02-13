/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#if __UNIX__
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#if __linux__
#include <execinfo.h>
#endif
#elif __WINDOWS__
#include <io.h>
#endif
#include <sys/types.h>

/* TODO: import stuff fron bininfo/p/bininfo_addr2line */
/* TODO: check endianness issues here */
R_API ut64 r_sys_now(void) {
	ut64 ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 32;
	ret |= now.tv_usec;
	//(sizeof (now.tv_sec) == 4
	return ret;
}

R_API RList *r_sys_dir(const char *path) {
	DIR *dir = opendir (path);
	struct dirent *entry;
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
	va_start(ap, fmt);
	vsnprintf (cmd, sizeof (cmd), fmt, ap);
	ret = r_sys_cmd_str (cmd, NULL, NULL);
	va_end(ap);
	return ret;
}

R_API void r_sys_backtrace(void) {
#if __linux__
        void *array[10];
        size_t size;
        char **strings;
        size_t i;
        size = backtrace (array, 10);
        strings = backtrace_symbols (array, size);
        printf ("Backtrace %zd stack frames.\n", size);
        for (i = 0; i < size; i++)
                printf ("%s\n", strings[i]);
        free (strings);
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

#if __WINDOWS__
R_API const char *r_sys_getenv(const char *key) {
	static char envbuf[1024];
	envbuf[0] = 0;
	GetEnvironmentVariable (key, (LPSTR)&envbuf, sizeof (envbuf));
	return envbuf;
}
#else
R_API const char *r_sys_getenv(const char *key) {
	return getenv (key);
}
#endif

R_API char *r_sys_getcwd(void) {
#if __UNIX__
	return getcwd (NULL, 0);
#elif __WINDOWS__
	return _getcwd (NULL, 0);
#else
#warning TODO: r_sys_getcwd
#endif
}

#if __UNIX__
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr) {
	char *output, buffer[1024];
	char *inputptr = (char *)input;
	int pid, bytes = 0;
	int sh_in[2], sh_out[2], sh_err[2];

	if (len) *len = 0;
	if (pipe (sh_in)) 
		return NULL;
	if (pipe (sh_out)) {
		close (sh_in[0]);
		close (sh_in[1]);
		return NULL;
	}
	if (pipe (sh_err)) {
		close (sh_in[0]);
		close (sh_in[1]);
		close (sh_out[0]);
		close (sh_out[1]);
		return NULL;
	}

	switch ((pid=fork ())) {
	case -1:
		return NULL;
	case 0:
		dup2 (sh_in[0], 0); close (sh_in[0]); close (sh_in[1]);
		dup2 (sh_out[1], 1); close (sh_out[0]); close (sh_out[1]);
		if (sterr) dup2 (sh_err[1], 2); else close (2);
		close (sh_err[0]); close (sh_err[1]); 
		execl ("/bin/sh", "sh", "-c", cmd, NULL);
		exit (1);
	default:
		{
		output = calloc (1, 1024); // TODO: use malloc
		if (!output)
			return NULL;
		if (sterr) {
			*sterr = calloc (1, 1024);
			if (!*sterr) {
				free (output);
				return NULL;
			}
		}
		close (sh_out[1]);
		close (sh_err[1]);
		close (sh_in[0]);
		if (!inputptr || !*inputptr)
			close (sh_in[1]);

		for (;;) {
			fd_set rfds, wfds;
			int nfd;

			FD_ZERO (&rfds);
			FD_ZERO (&wfds);
			FD_SET (sh_out[0], &rfds);
			if (sterr) 
				FD_SET (sh_err[0], &rfds);
			if (inputptr && *inputptr)
				FD_SET (sh_in[1], &wfds);
			memset (buffer, 0, sizeof (buffer));
			nfd = select (sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
			if (nfd < 0)
				break;
			if (FD_ISSET (sh_out[0], &rfds)) {
				if ((bytes = read (sh_out[0], buffer, sizeof (buffer)-1)) == 0) break;
				if (len) *len += bytes;
				output = r_str_concat (output, buffer);
			} else if (FD_ISSET (sh_err[0], &rfds) && sterr) {
				if (read (sh_err[0], buffer, sizeof (buffer)-1) == 0) break;
				*sterr = r_str_concat (*sterr, buffer);
			} else if (FD_ISSET (sh_in[1], &wfds) && inputptr && *inputptr) {
				bytes = write (sh_in[1], inputptr, strlen (inputptr));
				inputptr += bytes;
				if (!*inputptr) close (sh_in[1]);
			}
		}
		close (sh_out[0]);
		close (sh_err[0]);
		close (sh_in[1]);

		if (*output)
			return output;
		free (output);
		}
	}
	return NULL;
}
#elif __WINDOWS__
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr) {
	// TODO: fully implement the rest
	if (len) *len = 0;
	return r_sys_cmd_str_w32 (cmd);
}
#else
R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr) {
	eprintf ("r_sys_cmd_str: not yet implemented for this platform\n");
	return NULL;
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
/* TODO: implement for other systems */
#if __FreeBSD__
	/* freebsd system() is broken */
	int fds[2];
	int st,pid;
	char *argv[] = { "/bin/sh", "-c", input, NULL};
	pipe (fds);
	/* not working ?? */
	//pid = rfork(RFPROC|RFCFDG);
	pid = vfork ();
	if (pid == 0) {
		dup2 (1, fds[1]);
		execv (argv[0], argv);
		_exit (127); /* error */
	} else {
		dup2 (1, fds[0]);
		waitpid (pid, &st, 0);
	}
	return WEXITSTATUS (st);
#else
	return system (str);
#endif
}

R_API char *r_sys_cmd_str(const char *cmd, const char *input, int *len) {
	return r_sys_cmd_str_full (cmd, input, len, NULL);
}

R_API int r_sys_rmkdir(const char *dir) {
	int ret = R_TRUE;
	char *path = strdup (dir), *ptr = path;
	// XXX: Wrong for w32 (/).. and no errno ?
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
	DWORD dw = GetLastError(); 

	FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL );

	lpDisplayBuf = (LPVOID)LocalAlloc (LMEM_ZEROINIT, 
			(lstrlen((LPCTSTR)lpMsgBuf)+
			lstrlen((LPCTSTR)fun)+40)*sizeof (TCHAR)); 
	eprintf ("%s: %s\n", fun, lpMsgBuf);

	LocalFree (lpMsgBuf);
	LocalFree (lpDisplayBuf);
#endif
}
