/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */
#include <r_types.h>
#include <r_util.h>
#if __UNIX__
#include <sys/wait.h>
#include <signal.h>
#endif
#include <sys/types.h>
/* TODO: import stuff fron bininfo/p/bininfo_addr2line */

R_API char *r_sys_cmd_strf(const char *cmd, ...)
{
	return NULL;
}

R_API int r_sys_sleep(int secs)
{
#if __UNIX__
	return sleep(secs);
#else
	Sleep(secs * 1000); // W32
	return 0;
#endif
}

R_API int r_sys_usleep(int usecs)
{
#if __UNIX__
	return usleep(usecs);
#else
	Sleep(usecs); // W32
#endif
}

R_API int r_sys_setenv(const char *key, const char *value, int ow)
{
#if __UNIX__
	return setenv(key, value, ow);
#else
#warning TODO: r_sys_setenv
#endif
}

R_API const char *r_sys_getenv(const char *key)
{
#if __UNIX__
	return getenv(key);
#else
#warning TODO: r_sys_getenv
#endif
}

R_API char *r_sys_cmd_str_full(const char *cmd, const char *input, int *len, char **sterr)
{
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
		dup2(sh_in[0], 0);
		dup2(sh_out[1], 1);
		if (sterr) dup2(sh_err[1], 2);
		else close(2);
		execl("/bin/sh", "sh", "-c", cmd, NULL);
	} else {
		char buffer[1024];
		char *output = calloc(1, 1024);
		if (sterr)
			*sterr = calloc(1, 1024);

		while (1) {
			fd_set rfds, wfds;
			int nfd;
			struct timeval tv;
			tv.tv_sec=0;
			tv.tv_usec=100000;

			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_SET(sh_out[0], &rfds);
			FD_SET(sh_err[0], &rfds);
			if (inputptr && *inputptr)
				FD_SET(sh_in[1], &wfds);

			memset(buffer, 0, sizeof(buffer));
			nfd = select(sh_err[0] + 1, &rfds, &wfds, NULL, &tv);
	        if (nfd <= 0) {
				if (waitpid(pid, NULL, WNOHANG)) break;
				else if (nfd < 0) {
					kill(pid, 15);
					break;
				} 
			} else {
				if (FD_ISSET(sh_out[0], &rfds)) {
					*len += read(sh_out[0], buffer, sizeof(buffer)-1);
					output = r_str_concat(output, buffer);
				} else if (FD_ISSET(sh_err[0], &rfds) && sterr) {
					read(sh_err[0], buffer, sizeof(buffer)-1);
					*sterr = r_str_concat(*sterr, buffer);
				} else if (FD_ISSET(sh_in[1], &wfds) && inputptr && *inputptr) {
					bytes = write(sh_in[1], inputptr, strlen(inputptr));
					inputptr += bytes;
				}  
			}
		}
		if (strlen(output))
			return output;
	}
	return NULL;
#else
#warning NO r_sys_cmd_str support for this platform
	return NULL;
#endif
}

R_API int r_sys_cmd (const char *str)
{
/* TODO: implement for other systems */
	return system (str);
}
