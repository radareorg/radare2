/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#include <errno.h>
#include <sys/wait.h>

typedef struct {
	pid_t pid;
	int stdout_fd;
	int stderr_fd;
} R2RSubprocess;

R_API R2RSubprocess *r2r_subprocess_start(const char *file, const char *args[], size_t args_size) {
	char **argv = calloc (args_size + 2, sizeof (char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	// done by calloc: argv[args_size + 1] = NULL;

	R2RSubprocess *proc = R_NEW0 (R2RSubprocess);
	if (!proc) {
		goto error;
	}

	int stdout_pipe[2] = { -1, -1 };
	if (pipe (stdout_pipe) == -1) {
		perror ("pipe");
		goto error;
	}

	int stderr_pipe[2] = { -1, -1 };
	if (pipe (stderr_pipe) == -1) {
		perror ("pipe");
		goto error;
	}

	proc->pid = r_sys_fork ();
	if (proc->pid == -1) {
		// fail
		perror ("fork");
		free (proc);
		free (argv);
		return NULL;
	} else if (proc->pid == 0) {
		// child
		while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
		close (stdout_pipe[1]);
		close (stdout_pipe[0]);
		while ((dup2(stderr_pipe[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
		close (stderr_pipe[1]);
		close (stderr_pipe[0]);

		execvp (file, argv);
		perror ("exec");
		goto error;
	}
	free (argv);

	// parent
	close (stdout_pipe[1]);
	close (stderr_pipe[1]);

	return proc;
error:
	free (argv);
	free (proc);
	if (stderr_pipe[0] == -1) {
		close (stderr_pipe [0]);
	}
	if (stderr_pipe[1] == -1) {
		close (stderr_pipe [1]);
	}
	if (stdout_pipe[0] == -1) {
		close (stdout_pipe [0]);
	}
	if (stdout_pipe[1] == -1) {
		close (stdout_pipe [1]);
	}
	return NULL;
}

R_API void r2r_subprocess_wait(R2RSubprocess *proc) {
	// TODO: use SIGCHLD and stuff, read stdout/stderr, ...
	int ret = 0;
	waitpid (proc->pid, &ret, 0);
}

R_API R2RTestResult *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test) {
	// TODO
	return NULL;
}
