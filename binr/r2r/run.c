/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

#define NSEC_PER_SEC  1000000000
#define NSEC_PER_MSEC 1000000
#define USEC_PER_SEC  1000000
#define NSEC_PER_USEC 1000
#define USEC_PER_MSEC 1000

#if __WINDOWS__
struct r2r_subprocess_t {
	HANDLE stdin_write;
	HANDLE stdout_read;
	HANDLE stderr_read;
	HANDLE proc;
	int ret;
	RStrBuf out;
	RStrBuf err;
};

R_API bool r2r_subprocess_init(void) { return true; }
R_API void r2r_subprocess_fini(void) {}

R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
	LPWSTR wappname = NULL;
	LPWSTR wcmdline = NULL;
	R2RSubprocess *proc = NULL;
	HANDLE stdin_read = NULL;
	HANDLE stdout_write = NULL;
	HANDLE stderr_write = NULL;

	char **argv = calloc (args_size + 1, sizeof (char *));
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	char *cmdline = r_str_format_msvc_argv (args_size + 1, argv);
	free (argv);
	if (!cmdline) {
		return NULL;
	}
	size_t wcmdline_count = strlen (cmdline) * 1;
	wcmdline = calloc (wcmdline_count, sizeof (wchar_t));
	if (!MultiByteToWideChar (CP_UTF8, MB_PRECOMPOSED, cmdline, -1, wcmdline, wcmdline_count)) {
		free (cmdline);
		goto error;
	}
	free (cmdline);
	size_t wappname_count = strlen (file) + 1;
	wappname = calloc (wappname_count, sizeof (wchar_t));
	if (!wappname) {
		goto error;
	}
	if (!MultiByteToWideChar (CP_UTF8, MB_PRECOMPOSED, file, -1, wappname, wappname_count)) {
		goto error;
	}

	proc = R_NEW0 (R2RSubprocess);
	if (!proc) {
		goto error;
	}

	SECURITY_ATTRIBUTES sattrs;
	sattrs.nLength = sizeof (sattrs);
	sattrs.bInheritHandle = TRUE;
	sattrs.lpSecurityDescriptor = NULL;

	if (!CreatePipe (&proc->stdout_read, &stdout_write, &sattrs, 0)) {
		proc->stdout_read = stdout_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stdout_read, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}
	if (!CreatePipe (&proc->stderr_read, &stderr_write, &sattrs, 0)) {
		proc->stdout_read = stderr_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stderr_read, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}
	if (!CreatePipe (&stdin_read, &proc->stdin_write, &sattrs, 0)) {
		stdin_read = proc->stdin_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stdin_write, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}

	PROCESS_INFORMATION proc_info = { 0 };
	STARTUPINFOW start_info = { 0 };
	start_info.cb = sizeof (start_info);
	start_info.hStdError = stderr_write;
	start_info.hStdOutput = stdout_write;
	start_info.hStdInput = stdin_read;
	start_info.dwFlags |= STARTF_USESTDHANDLES;

	if (!CreateProcessW(wappname, wcmdline,
			NULL, NULL, TRUE, 0,
			NULL, // TODO: env
			NULL, &start_info, &proc_info)) {
		goto error;
	}

	CloseHandle (proc_info.hThread);
	proc->proc = proc_info.hProcess;

beach:
	if (stdin_read) {
		CloseHandle (stdin_read);
	}
	if (stdout_write) {
		CloseHandle (stdout_write);
	}
	if (stderr_write) {
		CloseHandle (stderr_write);
	}
	free (wcmdline);
	free (wappname);
	return proc;
error:
	if (proc) {
		if (proc->stdin_write) {
			CloseHandle (proc->stdin_write);
		}
		if (proc->stdout_read) {
			CloseHandle (proc->stdout_read);
		}
		if (proc->stderr_read) {
			CloseHandle (proc->stderr_read);
		}
		free (proc);
		proc = NULL;
	}
	goto beach;
}

static ut64 now_us() {
	LARGE_INTEGER f;
	if (!QueryPerformanceFrequency(&f)) {
		return 0;
	}
	LARGE_INTEGER v;
	if (!QueryPerformanceCounter(&v)) {
		return 0;
	}
	v.QuadPart *= 1000000;
	v.QuadPart /= f.QuadPart;
	return v.QuadPart;
}

R_API bool r2r_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms) {
	OVERLAPPED stdout_overlapped = { 0 };
	stdout_overlapped.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!stdout_overlapped.hEvent) {
		return false;
	}
	OVERLAPPED stderr_overlapped = { 0 };
	stderr_overlapped.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);
	if (!stderr_overlapped.hEvent) {
		CloseHandle (stdout_overlapped.hEvent);
		return false;
	}

	HANDLE handles[] = { stdout_overlapped.hEvent, stderr_overlapped.hEvent, proc->proc };
	ut64 timeout_us_abs = UT64_MAX;
	if (timeout_ms != UT64_MAX) {
		timeout_us_abs = now_us () + timeout_ms * USEC_PER_MSEC;
	}

	ut8 stdout_buf[0x500];
	ut8 stderr_buf[0x500];

	ReadFile (proc->stdout_read, stdout_buf, sizeof (stdout_buf), NULL, &stdout_overlapped);
	ReadFile (proc->stderr_read, stderr_buf, sizeof (stderr_buf), NULL, &stderr_overlapped);

	// TODO: finish all this

	while (true) {
		DWORD timeout = INFINITE;
		if (timeout_us_abs != UT64_MAX) {
			ut64 now = now_us ();
			if (now >= timeout_us_abs) {
				return false;
			}
			timeout = (DWORD)((timeout_us_abs - now) / USEC_PER_MSEC);
		}
		DWORD signaled = WaitForMultipleObjects (3, handles, FALSE, timeout);
		switch (signaled) {
		case 0: // stdout
			break;
		case 1: // stderr
			break;
		case 2: // proc
			break;
		case 3: // timeout or error
			return false;
		}
	}
}

R_API void r2r_subprocess_kill(R2RSubprocess *proc) {
	TerminateProcess (proc->proc, 255);
}

R_API void r2r_subprocess_stdin_write(R2RSubprocess *proc, const ut8 *buf, size_t buf_size) {
	DWORD read;
	WriteFile (proc->stdin_write, buf, buf_size, &read, NULL);
}


R_API R2RProcessOutput *r2r_subprocess_drain(R2RSubprocess *proc) {
	R2RProcessOutput *out = R_NEW (R2RProcessOutput);
	if (!out) {
		return NULL;
	}
	out->out = r_strbuf_drain_nofree (&proc->out);
	out->err = r_strbuf_drain_nofree (&proc->err);
	out->ret = proc->ret;
	return out;
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (!proc) {
		return;
	}
	CloseHandle (proc->stdin_write);
	CloseHandle (proc->stdout_read);
	CloseHandle (proc->stderr_read);
	CloseHandle (proc->proc);
	free (proc);
}
#else

#include <errno.h>
#include <sys/wait.h>

struct r2r_subprocess_t {
	pid_t pid;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
	int killpipe[2];
	int ret;
	RStrBuf out;
	RStrBuf err;
};

static RPVector subprocs;
static RThreadLock *subprocs_mutex;
static int sigchld_pipe[2];
static RThread *sigchld_thread;

static void handle_sigchld(int sig) {
	ut8 b = 1;
	write (sigchld_pipe[1], &b, 1);
}

static RThreadFunctionRet sigchld_th(RThread *th) {
	while (true) {
		ut8 b;
		ssize_t rd = read (sigchld_pipe[0], &b, 1);
		if (rd <= 0) {
			if (rd < 0) {
				if (errno == EINTR) {
					continue;
				}
				perror ("read");
			}
			break;
		}
		if (!b) {
			break;
		}
		while (true) {
			int wstat;
			pid_t pid = waitpid (-1, &wstat, WNOHANG);
			if (pid <= 0)
				break;

			r_th_lock_enter (subprocs_mutex);
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
				r_th_lock_leave (subprocs_mutex);
				continue;
			}

			if (WIFEXITED (wstat)) {
				proc->ret = WEXITSTATUS (wstat);
			} else {
				proc->ret = -1;
			}
			ut8 r = 0;
			write (proc->killpipe[1], &r, 1);
			r_th_lock_leave (subprocs_mutex);
		}
	}
	return R_TH_STOP;
}

R_API bool r2r_subprocess_init(void) {
	r_pvector_init(&subprocs, NULL);
	subprocs_mutex = r_th_lock_new (false);
	if (!subprocs_mutex) {
		return false;
	}
	if (pipe (sigchld_pipe) == -1) {
		perror ("pipe");
		r_th_lock_free (subprocs_mutex);
		return false;
	}
	sigchld_thread = r_th_new (sigchld_th, NULL, 0);
	if (!sigchld_thread) {
		close (sigchld_pipe [0]);
		close (sigchld_pipe [1]);
		r_th_lock_free (subprocs_mutex);
		return false;
	}
	if (r_sys_signal (SIGCHLD, handle_sigchld) < 0) {
		close (sigchld_pipe [0]);
		close (sigchld_pipe [1]);
		r_th_lock_free (subprocs_mutex);
		return false;
	}
	return true;
}

R_API void r2r_subprocess_fini(void) {
	r_sys_signal (SIGCHLD, SIG_IGN);
	ut8 b = 0;
	write (sigchld_pipe[1], &b, 1);
	close (sigchld_pipe [1]);
	r_th_wait (sigchld_thread);
	close (sigchld_pipe [0]);
	r_th_free (sigchld_thread);
	r_pvector_clear (&subprocs);
	r_th_lock_free (subprocs_mutex);
}

R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
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
	if (fcntl (proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		perror ("fcntl");
		goto error;
	}

	int stdin_pipe[2] = { -1, -1 };
	if (pipe (stdin_pipe) == -1) {
		perror ("pipe");
		goto error;
	}
	proc->stdin_fd = stdin_pipe[1];

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

	r_th_lock_enter (subprocs_mutex);
	proc->pid = r_sys_fork ();
	if (proc->pid == -1) {
		// fail
		r_th_lock_leave (subprocs_mutex);
		perror ("fork");
		free (proc);
		free (argv);
		return NULL;
	} else if (proc->pid == 0) {
		// child
		while ((dup2(stdin_pipe[0], STDIN_FILENO) == -1) && (errno == EINTR)) {}
		close (stdin_pipe[0]);
		close (stdin_pipe[1]);
		while ((dup2(stdout_pipe[1], STDOUT_FILENO) == -1) && (errno == EINTR)) {}
		close (stdout_pipe[1]);
		close (stdout_pipe[0]);
		while ((dup2(stderr_pipe[1], STDERR_FILENO) == -1) && (errno == EINTR)) {}
		close (stderr_pipe[1]);
		close (stderr_pipe[0]);

		size_t i;
		for (i = 0; i < env_size; i++) {
			setenv (envvars[i], envvals[i], 1);
		}
		execvp (file, argv);
		perror ("exec");
		goto error;
	}
	free (argv);

	// parent
	close (stdin_pipe[0]);
	close (stdout_pipe[1]);
	close (stderr_pipe[1]);

	r_pvector_push (&subprocs, proc);

	r_th_lock_leave (subprocs_mutex);

	return proc;
error:
	free (argv);
	if (proc && proc->killpipe[0] == -1) {
		close (proc->killpipe[0]);
	}
	if (proc && proc->killpipe[1] == -1) {
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
	if (stdin_pipe[0] == -1) {
		close (stdin_pipe[0]);
	}
	if (stdin_pipe[1] == -1) {
		close (stdin_pipe[1]);
	}
	return NULL;
}

R_API bool r2r_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms) {
	struct timespec timeout_abs;
	if (timeout_ms != UT64_MAX) {
		clock_gettime (CLOCK_MONOTONIC, &timeout_abs);
		timeout_abs.tv_nsec += timeout_ms * NSEC_PER_MSEC;
		timeout_abs.tv_sec += timeout_abs.tv_nsec / NSEC_PER_SEC;
		timeout_abs.tv_nsec = timeout_abs.tv_nsec % NSEC_PER_SEC;
	}

	int r = 0;
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

		struct timeval timeout_s;
		struct timeval *timeout = NULL;
		if (timeout_ms != UT64_MAX) {
			struct timespec now;
			clock_gettime (CLOCK_MONOTONIC, &now);
			st64 usec_diff = ((st64)timeout_abs.tv_sec - now.tv_sec) * USEC_PER_SEC
					+ ((st64)timeout_abs.tv_nsec - now.tv_nsec) / NSEC_PER_USEC;
			if (usec_diff <= 0) {
				break;
			}
			timeout_s.tv_sec = usec_diff / USEC_PER_SEC;
			timeout_s.tv_usec = usec_diff % USEC_PER_SEC;
			timeout = &timeout_s;
		}
		r = select (nfds, &rfds, NULL, NULL, timeout);
		if (r < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		}

		bool timedout = true;
		if (FD_ISSET (proc->stdout_fd, &rfds)) {
			timedout = false;
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
			timedout = false;
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
			timedout = false;
			child_dead = true;
		}
		if (timedout) {
			break;
		}
	}
	if (r < 0) {
		perror ("select");
	}
	return child_dead;
}

R_API void r2r_subprocess_kill(R2RSubprocess *proc) {
	kill (proc->pid, SIGKILL);
}

R_API void r2r_subprocess_stdin_write(R2RSubprocess *proc, const ut8 *buf, size_t buf_size) {
	write (proc->stdin_fd, buf, buf_size);
	close (proc->stdin_fd);
	proc->stdin_fd = -1;
}

R_API R2RProcessOutput *r2r_subprocess_drain(R2RSubprocess *proc) {
	r_th_lock_enter (subprocs_mutex);
	R2RProcessOutput *out = R_NEW (R2RProcessOutput);
	if (out) {
		out->out = r_strbuf_drain_nofree (&proc->out);
		out->err = r_strbuf_drain_nofree (&proc->err);
		out->ret = proc->ret;
		out->timeout = false;
	}
	r_th_lock_leave (subprocs_mutex);
	return out;
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (!proc) {
		return;
	}
	r_th_lock_enter (subprocs_mutex);
	r_pvector_remove_data (&subprocs, proc);
	r_th_lock_leave (subprocs_mutex);
	r_strbuf_fini (&proc->out);
	r_strbuf_fini (&proc->err);
	close (proc->killpipe[0]);
	close (proc->killpipe[1]);
	if (proc->stdin_fd != -1) {
		close (proc->stdin_fd);
	}
	close (proc->stdout_fd);
	close (proc->stderr_fd);
	free (proc);
}
#endif

R_API void r2r_process_output_free(R2RProcessOutput *out) {
	if (!out) {
		return;
	}
	free (out->out);
	free (out->err);
	free (out);
}

static R2RProcessOutput *subprocess_runner(const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size, void *user) {
	R2RRunConfig *config = user;
	R2RSubprocess *proc = r2r_subprocess_start (file, args, args_size, envvars, envvals, env_size);
	bool timeout = !r2r_subprocess_wait (proc, config->timeout_ms);
	if (timeout) {
		r2r_subprocess_kill (proc);
	}
	R2RProcessOutput *out = r2r_subprocess_drain (proc);
	if (out) {
		out->timeout = timeout;
	}
	r2r_subprocess_free (proc);
	return out;
}

static R2RProcessOutput *run_r2_test(R2RRunConfig *config, const char *cmds, RList *files, RList *extra_args, bool load_plugins, R2RCmdRunner runner, void *user) {
	RPVector args;
	r_pvector_init (&args, NULL);
	r_pvector_push (&args, "-escr.utf8=0");
	r_pvector_push (&args, "-escr.color=0");
	r_pvector_push (&args, "-escr.interactive=0");
	r_pvector_push (&args, "-N");
	RListIter *it;
	void *extra_arg, *file_arg;
	r_list_foreach (extra_args, it, extra_arg) {
		r_pvector_push (&args, extra_arg);
	}
	r_pvector_push (&args, "-Qc");
	r_pvector_push (&args, (void *)cmds);
	r_list_foreach (files, it, file_arg) {
		r_pvector_push (&args, file_arg);
	}

	const char *envvars[] = {
		"R2_NOPLUGINS"
	};
	const char *envvals[] = {
		"1"
	};
	size_t env_size = load_plugins ? 0 : 1;
	R2RProcessOutput *out = runner (config->r2_cmd, args.v.a, r_pvector_len (&args), envvars, envvals, env_size, user);
	r_pvector_clear (&args);
	return out;
}

R_API R2RProcessOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test, R2RCmdRunner runner, void *user) {
	RList *extra_args = test->args.value ? r_str_split_duplist (test->args.value, " ") : NULL;
	RList *files = r_str_split_duplist (test->file.value, "\n");
	RListIter *it;
	RListIter *tmpit;
	char *token;
	r_list_foreach_safe (extra_args, it, tmpit, token) {
		if (!*token) {
			r_list_delete (extra_args, it);
		}
	}
	r_list_foreach_safe (files, it, tmpit, token) {
		if (!*token) {
			r_list_delete (files, it);
		}
	}
	if (r_list_empty (files)) {
		if (!files) {
			files = r_list_new ();
		} else {
			files->free = NULL;
		}
		r_list_push (files, "-");
	}
	R2RProcessOutput *out = run_r2_test (config, test->cmds.value, files, extra_args, test->load_plugins, runner, user);
	r_list_free (extra_args);
	r_list_free (files);
	return out;
}

R_API bool r2r_check_cmd_test(R2RProcessOutput *out, R2RCmdTest *test) {
	if (out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *expect_out = test->expect.value;
	if (expect_out && strcmp (out->out, expect_out) != 0) {
		return false;
	}
	const char *expect_err = test->expect_err.value;
	if (expect_err && strcmp (out->err, expect_err) != 0) {
		return false;
	}
	return true;
}

#define JQ_CMD "jq"

R_API bool r2r_check_jq_available(void) {
	const char *invalid_json = "this is not json lol";
	R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, NULL, 0, NULL, NULL, 0);
	r2r_subprocess_stdin_write (proc, (const ut8 *)invalid_json, strlen (invalid_json));
	r2r_subprocess_wait (proc, UT64_MAX);
	bool invalid_detected = proc->ret != 0;
	r2r_subprocess_free (proc);

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	proc = r2r_subprocess_start (JQ_CMD, NULL, 0, NULL, NULL, 0);
	r2r_subprocess_stdin_write (proc, (const ut8 *)valid_json, strlen (valid_json));
	r2r_subprocess_wait (proc, UT64_MAX);
	bool valid_detected = proc->ret == 0;
	r2r_subprocess_free (proc);

	return invalid_detected && valid_detected;
}

R_API R2RProcessOutput *r2r_run_json_test(R2RRunConfig *config, R2RJsonTest *test, R2RCmdRunner runner, void *user) {
	RList *files = r_list_new ();
	r_list_push (files, (void *)config->json_test_file);
	R2RProcessOutput *ret = run_r2_test (config, test->cmd, files, NULL, test->load_plugins, runner, user);
	r_list_free (files);
	return ret;
}

R_API bool r2r_check_json_test(R2RProcessOutput *out, R2RJsonTest *test) {
	if (out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, NULL, 0, NULL, NULL, 0);
	r2r_subprocess_stdin_write (proc, (const ut8 *)out->out, strlen (out->out));
	r2r_subprocess_wait (proc, UT64_MAX);
	bool ret = proc->ret == 0;
	r2r_subprocess_free (proc);
	return ret;
}

R_API R2RAsmTestOutput *r2r_run_asm_test(R2RRunConfig *config, R2RAsmTest *test) {
	R2RAsmTestOutput *out = R_NEW0 (R2RAsmTestOutput);
	if (!out) {
		return NULL;
	}

	RPVector args;
	r_pvector_init (&args, NULL);

	if (test->arch) {
		r_pvector_push (&args, "-a");
		r_pvector_push (&args, (void *)test->arch);
	}

	if (test->cpu) {
		r_pvector_push (&args, "-c");
		r_pvector_push (&args, (void *)test->cpu);
	}

	char bits[0x20];
	if (test->bits) {
		snprintf (bits, sizeof (bits), "%d", test->bits);
		r_pvector_push (&args, "-b");
		r_pvector_push (&args, bits);
	}

	if (test->mode & R2R_ASM_TEST_MODE_BIG_ENDIAN) {
		r_pvector_push (&args, "-e");
	}

	char offset[0x20];
	if (test->offset) {
		r_snprintf (offset, sizeof (offset), "0x%"PFMT64x, test->offset);
		r_pvector_push (&args, "-o");
		r_pvector_push (&args, offset);
	}

	RStrBuf cmd_buf;
	r_strbuf_init (&cmd_buf);
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		r_pvector_push (&args, test->disasm);
		R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, args.v.a, r_pvector_len (&args), NULL, NULL, 0);
		if (!r2r_subprocess_wait (proc, config->timeout_ms)) {
			r2r_subprocess_kill (proc);
			out->as_timeout = true;
			goto rip;
		}
		if (proc->ret != 0) {
			goto rip;
		}
		char *hex = r_strbuf_get (&proc->out);
		size_t hexlen = strlen (hex);
		if (!hexlen) {
			goto rip;
		}
		ut8 *bytes = malloc (hexlen);
		int byteslen = r_hex_str2bin (hex, bytes);
		if (byteslen <= 0) {
			free (bytes);
			goto rip;
		}
		out->bytes = bytes;
		out->bytes_size = (size_t)byteslen;
rip:
		r_pvector_pop (&args);
		r2r_subprocess_free (proc);
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		char *hex = r_hex_bin2strdup (test->bytes, test->bytes_size);
		if (!hex) {
			goto beach;
		}
		r_pvector_push (&args, "-d");
		r_pvector_push (&args, hex);
		R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, args.v.a, r_pvector_len (&args), NULL, NULL, 0);
		if (!r2r_subprocess_wait (proc, config->timeout_ms)) {
			r2r_subprocess_kill (proc);
			out->disas_timeout = true;
			goto ship;
		}
		if (proc->ret != 0) {
			goto ship;
		}
		free (hex);
		char *disasm = r_strbuf_drain_nofree (&proc->out);
		r_str_trim (disasm);
		out->disasm = disasm;
ship:
		r_pvector_pop (&args);
		r_pvector_pop (&args);
		r2r_subprocess_free (proc);
	}

beach:
	r_pvector_clear (&args);
	r_strbuf_fini (&cmd_buf);
	return out;
}

R_API bool r2r_check_asm_test(R2RAsmTestOutput *out, R2RAsmTest *test) {
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		if (!out->bytes || !test->bytes || out->bytes_size != test->bytes_size || out->as_timeout) {
			return false;
		}
		if (memcmp (out->bytes, test->bytes, test->bytes_size) != 0) {
			return false;
		}
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm || out->as_timeout) {
			return false;
		}
		if (strcmp (out->disasm, test->disasm) != 0) {
			return false;
		}
	}
	return true;
}

R_API void r2r_asm_test_output_free(R2RAsmTestOutput *out) {
	if (!out) {
		return;
	}
	free (out->disasm);
	free (out->bytes);
	free (out);
}

R_API char *r2r_test_name(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup (test->cmd_test->name.value);
		}
		return strdup ("<unnamed>");
	case R2R_TEST_TYPE_ASM:
		return r_str_newf ("<asm> %s", test->asm_test->disasm ? test->asm_test->disasm : "");
	case R2R_TEST_TYPE_JSON:
		return r_str_newf ("<json> %s", test->json_test->cmd ? test->json_test->cmd: "");
	}
	return NULL;
}

R_API bool r2r_test_broken(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		return test->cmd_test->broken.value;
	case R2R_TEST_TYPE_ASM:
		return test->asm_test->mode & R2R_ASM_TEST_MODE_BROKEN ? true : false;
	case R2R_TEST_TYPE_JSON:
		return test->json_test->broken;
	}
	return false;
}

R_API R2RTestResultInfo *r2r_run_test(R2RRunConfig *config, R2RTest *test) {
	R2RTestResultInfo *ret = R_NEW0 (R2RTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	switch (test->type) {
	case R2R_TEST_TYPE_CMD: {
		R2RCmdTest *cmd_test = test->cmd_test;
		R2RProcessOutput *out = r2r_run_cmd_test (config, cmd_test, subprocess_runner, config);
		success = r2r_check_cmd_test (out, cmd_test);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		break;
	}
	case R2R_TEST_TYPE_ASM: {
		R2RAsmTest *asm_test = test->asm_test;
		R2RAsmTestOutput *out = r2r_run_asm_test (config, asm_test);
		success = r2r_check_asm_test (out, asm_test);
		ret->asm_out = out;
		ret->timeout = out->as_timeout || out->disas_timeout;
		break;
	}
	case R2R_TEST_TYPE_JSON: {
		R2RJsonTest *json_test = test->json_test;
		R2RProcessOutput *out = r2r_run_json_test (config, json_test, subprocess_runner, config);
		success = r2r_check_json_test (out, json_test);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		break;
	}
	}
	bool broken = r2r_test_broken (test);
	if (!success) {
		ret->result = broken ? R2R_TEST_RESULT_BROKEN : R2R_TEST_RESULT_FAILED;
	} else {
		ret->result = broken ? R2R_TEST_RESULT_FIXED : R2R_TEST_RESULT_OK;
	}
	return ret;
}

R_API void r2r_test_result_info_free(R2RTestResultInfo *result) {
	if (!result) {
		return;
	}
	if (result->test) {
		switch (result->test->type) {
		case R2R_TEST_TYPE_CMD:
		case R2R_TEST_TYPE_JSON:
			r2r_process_output_free (result->proc_out);
			break;
		case R2R_TEST_TYPE_ASM:
			r2r_asm_test_output_free (result->asm_out);
			break;
		}
	}
	free (result);
}
