/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#include <errno.h>
#include <sys/wait.h>

typedef struct {
	pid_t pid;
	int stdout_fd;
	int stderr_fd;
	int killpipe[2];
	int ret;
	RStrBuf out;
	RStrBuf err;
} R2RSubprocess;

static RPVector subprocs;
static RThreadLock *subprocs_mutex;

static void subprocs_lock(sigset_t *old_sigset) {
	sigset_t block_sigset;
	sigemptyset (&block_sigset);
	sigaddset (&block_sigset, SIGWINCH);
	r_signal_sigmask (SIG_BLOCK, &block_sigset, old_sigset);
	r_th_lock_enter (subprocs_mutex);
}

static void subprocs_unlock(sigset_t *old_sigset) {
	r_th_lock_leave (subprocs_mutex);
	r_signal_sigmask (SIG_SETMASK, old_sigset, NULL);
}

static void handle_sigchld() {
	while (true) {
		int wstat;
		pid_t pid = waitpid (-1, &wstat, WNOHANG);
		if (pid <= 0)
			return;

		void **it;
		R2RSubprocess *proc = NULL;
		r_pvector_foreach (&subprocs, it) {
			R2RSubprocess *p = *it;
			if (p->pid == pid) {
				proc = p;
				break;
			}
		}
		if (!proc) {
			continue;
		}

		if (WIFEXITED (wstat)) {
			proc->ret = WEXITSTATUS (wstat);
		} else {
			proc->ret = -1;
		}
		ut8 r = 0;
		write (proc->killpipe[1], &r, 1);
	}
}

R_API bool r2r_subprocess_init() {
	r_pvector_init(&subprocs, NULL);
	subprocs_mutex = r_th_lock_new (false);
	if (!subprocs_mutex) {
		return false;
	}
	if (r_sys_signal (SIGCHLD, handle_sigchld) < 0) {
		return false;
	}
	return true;
}

R_API void r2r_subprocess_fini() {
	r_pvector_clear (&subprocs);
	r_th_lock_free (subprocs_mutex);
}

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
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	r_strbuf_init (&proc->out);
	r_strbuf_init (&proc->err);

	if (pipe (proc->killpipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}

	int stdout_pipe[2] = { -1, -1 };
	if (pipe (stdout_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stdout_fd = stdout_pipe[0];

	int stderr_pipe[2] = { -1, -1 };
	if (pipe (stderr_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	if (fcntl(stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}
	proc->stderr_fd = stderr_pipe[0];

	sigset_t old_sigset;
	subprocs_lock (&old_sigset);
	proc->pid = r_sys_fork ();
	if (proc->pid == -1) {
		// fail
		subprocs_unlock (&old_sigset);
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

	r_pvector_push (&subprocs, proc);

	subprocs_unlock (&old_sigset);

	return proc;
error:
	free (argv);
	if (proc->killpipe[0] == -1) {
		close (proc->killpipe[0]);
	}
	if (proc->killpipe[1] == -1) {
		close (proc->killpipe[1]);
	}
	free (proc);
	if (stderr_pipe[0] == -1) {
		close (stderr_pipe[0]);
	}
	if (stderr_pipe[1] == -1) {
		close (stderr_pipe[1]);
	}
	if (stdout_pipe[0] == -1) {
		close (stdout_pipe[0]);
	}
	if (stdout_pipe[1] == -1) {
		close (stdout_pipe[1]);
	}
	return NULL;
}

R_API void r2r_subprocess_wait(R2RSubprocess *proc) {
	int r;
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;
	while (!stdout_eof || !stderr_eof || !child_dead) {
		fd_set rfds;
		FD_ZERO (&rfds);
		int nfds = 0;
		if (!stdout_eof) {
			FD_SET (proc->stdout_fd, &rfds);
			if (proc->stdout_fd > nfds) {
				nfds = proc->stdout_fd;
			}
		}
		if (!stderr_eof) {
			FD_SET (proc->stderr_fd, &rfds);
			if (proc->stderr_fd > nfds) {
				nfds = proc->stderr_fd;
			}
		}
		if (!child_dead) {
			FD_SET (proc->killpipe[0], &rfds);
			if (proc->killpipe[0] > nfds) {
				nfds = proc->killpipe[0];
			}
		}
		nfds++;
		r = select (nfds, &rfds, NULL, NULL, NULL);
		if (r < 0) {
			if (errno == EINTR) {
				printf ("cont\n");
				continue;
			}
			break;
		}

		if (FD_ISSET (proc->stdout_fd, &rfds)) {
			char buf[0x500];
			ssize_t sz = read (proc->stdout_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
			} else if (sz == 0) {
				stdout_eof = true;
			} else {
				r_strbuf_append_n (&proc->out, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->stderr_fd, &rfds)) {
			char buf[0x500];
			ssize_t sz = read (proc->stderr_fd, buf, sizeof (buf));
			if (sz < 0) {
				perror ("read");
				continue;
			} else if (sz == 0) {
				stderr_eof = true;
			} else {
				r_strbuf_append_n (&proc->err, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->killpipe[0], &rfds)) {
			child_dead = true;
		}
	}
	if (r < 0) {
		perror ("select");
	}
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (!proc) {
		return;
	}
	r_strbuf_fini (&proc->out);
	r_strbuf_fini (&proc->err);;
	close (proc->killpipe[0]);;
	close (proc->killpipe[1]);
	close (proc->stdout_fd);
	close (proc->stderr_fd);
	free (proc);
}

R_API R2RTestResult *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test) {
	const char *args[] = { "-h" };
	R2RSubprocess *proc = r2r_subprocess_start (config->r2_cmd, args, 1);
	r2r_subprocess_wait (proc);
	printf ("subproc exited with %d\n", proc->ret);
	printf ("stdout: %s\n", r_strbuf_get (&proc->out));
	printf ("stderr: %s\n", r_strbuf_get (&proc->err));
	r2r_subprocess_free (proc);
	return NULL;
}
