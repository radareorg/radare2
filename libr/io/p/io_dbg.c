/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#if __linux__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

static int __waitpid(int pid)
{
	int st = 0;
	if (waitpid(pid, &st, 0) == -1)
		return R_FALSE;
	if (WIFEXITED(st)) {
	//if ((WEXITSTATUS(wait_val)) != 0) {
		perror("==> Process has exited\n");
		//debug_exit();
		return -1;
	}
	return R_TRUE;
}

// TODO: move to common os/ directory
/* 
 * Creates a new process and returns the result:
 * -1 : error
 *  0 : ok 
 * TODO: should be pid number?
 * TODO: should accept argv and so as arguments
 */
//#include <linux/user.h>
#define MAGIC_EXIT 31337
static int fork_and_ptraceme(const char *cmd)
{
	int pid = -1;

	pid = vfork();
	switch(pid) {
	case -1:
		fprintf(stderr, "Cannot fork.\n");
		break;
	case 0:
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
			fprintf(stderr, "ptrace-traceme failed\n");
			exit(MAGIC_EXIT);
		}
#if 0
		eprintf("argv = [ ");
		for(i=0;ps.argv[i];i++)
			eprintf("'%s', ", ps.argv[i]);
		eprintf("]\n");
#endif

		// TODO: USE TM IF POSSIBLE TO ATTACH IT FROM ANOTHER CONSOLE!!!
		// TODO: 
		//debug_environment();
{
	char *buf;
	char *argv[2];
	char *ptr;

	buf = strdup(cmd);
	ptr = strchr(buf, ' ');
	if (ptr) {
		*ptr='\0';
	}

	argv[0] = r_file_path(cmd);
	argv[1] = NULL;
		//execv(cmd, argv); //ps.argv[0], ps.argv);
	execvp(argv[0], argv);
}
		perror("fork_and_attach: execv");
		//printf(stderr, "[%d] %s execv failed.\n", getpid(), ps.filename);
		exit(MAGIC_EXIT); /* error */
		break;
	default:
		__waitpid(pid);
		/* required for some BSDs */
		kill(pid, SIGSTOP);
		break;
	}
	printf("PID = %d\n", pid);

	return pid;
}

static int __handle_open(struct r_io_t *io, const char *file)
{
	if (!memcmp(file, "dbg://", 6))
		return R_TRUE;
	return R_FALSE;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode)
{
	char uri[1024];
	if (__handle_open(io, file)) {
		int pid = atoi(file+6);
		if (pid == 0) {
			pid = fork_and_ptraceme(file+6);
			if (pid > 0) {
				sprintf(uri, "ptrace://%d", pid);
				r_io_redirect(io, uri);
				return -1;
			}
		} else {
			char foo[1024];
			sprintf(uri, "attach://%d", pid);
			r_io_redirect(io, foo);
			return -1;
		}
	}
	r_io_redirect(io, NULL);
	return -1;
}

static int __handle_fd(struct r_io_t *io, int fd)
{
	return R_FALSE;
}

static int __init(struct r_io_t *io)
{
	printf("dbg init\n");
	return R_TRUE;
}

struct r_io_handle_t r_io_plugin_dbg = {
        //void *handle;
	.name = "io_dbg",
        .desc = "Debug a program or pid. dbg:///bin/ls, dbg://1388",
        .open = __open,
        .handle_open = __handle_open,
        .handle_fd = __handle_fd,
	.lseek = NULL,
	.system = NULL,
	.debug = (void *)1,
	.init = __init,
        //void *widget;
/*
        struct debug_t *debug;
        ut32 (*write)(int fd, const ut8 *buf, ut32 count);
	int fds[R_IO_NFDS];
*/
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_dbg
};
#endif

#endif
