/* radare - LGPL - Copyright 2007-2010 pancake<nopcode.org> */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>


#if __linux__ || __NetBSD__ || __FreeBSD__ || __OpenBSD__ || __APPLE__

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

static void inferior_abort_handler(int pid) {
        eprintf ("Inferior received signal SIGABRT. Executing BKPT.\n");
}

#if __APPLE__
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_traps.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach/vm_map.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

// XXX this is OSX
static pid_t start_inferior(int argc, char **argv) {
        char **child_args;
        int status;
        pid_t kid;

        eprintf ("Starting process...\n");

        if ((kid = fork ())) {
                //waitpid (kid, &status, 0);
                wait (&status);
                if (WIFSTOPPED (status)) {
                        eprintf ("Process with PID %d started...\n", (int)kid);
                        return kid;
                }
                return -1;
        }

        child_args = (char **)malloc (sizeof (char *) * (argc + 1));
        memcpy (child_args, argv, sizeof(char *) * argc);
        child_args[argc] = NULL;

        ptrace (PT_TRACE_ME, 0, 0, 0);
        /* why altering these signals? */
        /* XXX this can be monitorized by the child */
        signal (SIGTRAP, SIG_IGN); // SINO NO FUNCIONA EL STEP
        signal (SIGABRT, inferior_abort_handler);

        execvp (argv[0], child_args);

        eprintf ("Failed to start inferior.\n");
	exit (0);
}
#endif

static int __waitpid(int pid) {
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
	int status, pid = -1;

	pid = vfork();
	switch (pid) {
	case -1:
		fprintf(stderr, "Cannot fork.\n");
		break;
	case 0:
#if __APPLE__
		signal (SIGTRAP, SIG_IGN); // SINO NO FUNCIONA EL STEP
		signal (SIGABRT, inferior_abort_handler);
		if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) {
#else
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
#endif
			eprintf ("ptrace-traceme failed\n");
			exit (MAGIC_EXIT);
		}
#if 0
		eprintf ("argv = [ ");
		for (i=0;ps.argv[i];i++)
			eprintf ("'%s', ", ps.argv[i]);
		eprintf ("]\n");
#endif

		// TODO: USE TM IF POSSIBLE TO ATTACH IT FROM ANOTHER CONSOLE!!!
		// TODO: 
		//debug_environment();
{
	char *buf;
	char *argv[2];
	char *ptr;

	buf = strdup (cmd);
	ptr = strchr (buf, ' ');
	if (ptr)
		*ptr='\0';

	argv[0] = r_file_path (cmd);
	argv[1] = NULL;
		//execv(cmd, argv); //ps.argv[0], ps.argv);
	execvp (argv[0], argv);
}
		perror ("fork_and_attach: execv");
		//printf(stderr, "[%d] %s execv failed.\n", getpid(), ps.filename);
		exit (MAGIC_EXIT); /* error */
		break;
	default:
		/* XXX: clean this dirty code */
#if __APPLE__
                wait (&status);
                if (WIFSTOPPED (status))
                        eprintf ("Process with PID %d started...\n", (int)pid);
#else
		__waitpid (pid);
		kill(pid, SIGSTOP);
#endif
		break;
	}
	printf ("PID = %d\n", pid);

	return pid;
}

static int __handle_open(struct r_io_t *io, const char *file) {
	if (!memcmp(file, "dbg://", 6))
		return R_TRUE;
	return R_FALSE;
}

static int __open(struct r_io_t *io, const char *file, int rw, int mode) {
	char uri[1024];
	if (__handle_open(io, file)) {
		int pid = atoi(file+6);
		if (pid == 0) {
			pid = fork_and_ptraceme(file+6);
			if (pid==-1)
				return -1;
#if __APPLE__
			sprintf (uri, "mach://%d", pid);
#elif __linux__
			sprintf (uri, "ptrace://%d", pid);
#else
			// XXX
			sprintf (uri, "ptrace://%d", pid);
#endif
			r_io_redirect (io, uri);
			return -1;
		} else {
			char foo[1024];
			sprintf (uri, "attach://%d", pid);
			r_io_redirect (io, foo);
			return -1;
		}
	}
	r_io_redirect (io, NULL);
	return -1;
}

static int __init(struct r_io_t *io) {
	eprintf ("dbg init\n");
	return R_TRUE;
}

struct r_io_handle_t r_io_plugin_debug = {
        //void *handle;
	.name = "io.debug",
        .desc = "Debug a program or pid. dbg:///bin/ls, dbg://1388",
        .open = __open,
        .handle_open = __handle_open,
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

#else // DEBUGGER

struct r_io_handle_t r_io_plugin_debug = {
        //void *handle;
	.name = "io.debug",
        .desc = "Debug a program or pid. (NOT SUPPORTED FOR THIS PLATFORM)",
	.debug = (void *)1,
};

#endif // DEBUGGER


#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_debug
};
#endif
