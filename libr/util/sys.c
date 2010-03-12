/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#if __UNIX__
#include <sys/wait.h>
#include <signal.h>
#elif __WINDOWS__
#include <io.h>
#endif
#include <sys/types.h>
/* TODO: import stuff fron bininfo/p/bininfo_addr2line */

R_API ut64 r_sys_now() {
	ut64 ret;
	struct timeval now;
	gettimeofday (&now, NULL);
	ret = now.tv_sec;
	ret <<= 32;
	ret |= now.tv_usec;
	//(sizeof (now.tv_sec) == 4
	return ret;
}

R_API char *r_sys_cmd_strf(const char *cmd, ...) {
	// FIXME Implement r_sys_cmd_strf
	return NULL;
}

R_API int r_sys_sleep(int secs) {
#if __UNIX__
	return sleep(secs);
#else
	Sleep(secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs) {
#if __UNIX__
	return usleep(usecs);
#else
	Sleep(usecs); // W32
#endif
}

R_API int r_sys_setenv(const char *key, const char *value, int ow) {
#if __UNIX__
	return setenv(key, value, ow);
#else
#warning TODO: r_sys_setenv
#endif
}

R_API const char *r_sys_getenv(const char *key) {
#if __UNIX__
	return getenv(key);
#else
#warning TODO: r_sys_getenv
#endif
}

R_API char *r_sys_getcwd() {
#if __UNIX__
	return getcwd(NULL, 0);
#elif __WINDOWS__
	return _getcwd(NULL, 0);
#else
#warning TODO: r_sys_getcwd
#endif
}

R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr) {
#if __UNIX__
	char *inputptr = (char *)input;
	int bytes = 0;
	int sh_in[2];
	int sh_out[2];
	int sh_err[2];
	pipe(sh_in);
	pipe(sh_out);
	pipe(sh_err);
	*len = 0;

	int pid = fork();
	if (!pid) {
		dup2(sh_in[0], 0); close(sh_in[0]); close(sh_in[1]);
		dup2(sh_out[1], 1); close(sh_out[0]); close(sh_out[1]);
		if (sterr) dup2(sh_err[1], 2);
		else close(2);
		close(sh_err[0]); close(sh_err[1]); 
		execl("/bin/sh", "sh", "-c", cmd, NULL);
	} else {
		char buffer[1024];
		char *output = calloc(1, 1024);
		if (sterr)
			*sterr = calloc(1, 1024);

		close(sh_out[1]);
		close(sh_err[1]);
		close(sh_in[0]);
		if (!inputptr || !*inputptr)
			close(sh_in[1]);

		while (1) {
			fd_set rfds, wfds;
			int nfd;

			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(sh_out[0], &rfds);
			if (sterr) 
				FD_SET(sh_err[0], &rfds);
			if (inputptr && *inputptr)
				FD_SET(sh_in[1], &wfds);

			memset(buffer, 0, sizeof(buffer));
			nfd = select(sh_err[0] + 1, &rfds, &wfds, NULL, NULL);
	        if (nfd < 0) {
				break;
			} else {
				if (FD_ISSET(sh_out[0], &rfds)) {
					if ((bytes = read(sh_out[0], buffer, sizeof(buffer)-1)) == 0) break;
					*len += bytes;
					output = r_str_concat(output, buffer);
				} else if (FD_ISSET(sh_err[0], &rfds) && sterr) {
					if (read(sh_err[0], buffer, sizeof(buffer)-1) == 0) break;
					*sterr = r_str_concat(*sterr, buffer);
				} else if (FD_ISSET(sh_in[1], &wfds) && inputptr && *inputptr) {
					bytes = write(sh_in[1], inputptr, strlen(inputptr));
					inputptr += bytes;
					if (!*inputptr) close(sh_in[1]);
				}  
			}
		}
		close(sh_out[0]);
		close(sh_err[0]);
		close(sh_in[1]);

		if (strlen(output))
			return output;
	}
	return NULL;
#else
#warning NO r_sys_cmd_str support for this platform
	return NULL;
#endif
}

R_API int r_sys_cmd (const char *str) {
/* TODO: implement for other systems */
#if __FreeBSD__
	/* freebsd system() is broken */
	int fds[2];
	int st,pid;
	char *argv[] ={ "/bin/sh", "-c", input, NULL};
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
