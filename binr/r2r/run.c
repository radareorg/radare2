/* radare - LGPL - Copyright 2020-2025 - pancake, thestr4ng3r */

#include "r2r.h"

#if R2__WINDOWS__
#include <windows.h>
#endif

#if __wasi__
static int pipe(int fildes[2]) {
	return -1;
}
static int dup2(int a, int b) {
	return -1;
}
static int waitpid(int a, void *b, int c) {
	return -1;
}
static int kill(int a, int b) {
	return -1;
}
static int execvp(const char *a, char **b) {
	return -1;
}
static int setpgid(int, int) {
	return -1;
}
#define WNOHANG 0
#define WIFEXITED(x) 0
#define WEXITSTATUS(x) 0
#define __SIG_IGN 0
#endif

#if R2__WINDOWS__
struct r2r_subprocess_t {
	HANDLE stdin_write;
	HANDLE stdout_read;
	HANDLE stderr_read;
	HANDLE proc;
	int ret;
	RStrBuf out;
	RStrBuf err;
	RThreadLock *lock;
};

static volatile long pipe_id = 0;

static bool create_pipe_overlap(HANDLE *pipe_read, HANDLE *pipe_write, LPSECURITY_ATTRIBUTES attrs, DWORD sz, DWORD read_mode, DWORD write_mode) {
	// see https://stackoverflow.com/a/419736
	if (!sz) {
		sz = 4096;
	}
	r_strf_var (name, MAX_PATH, "\\\\.\\pipe\\r2r-subproc.%d.%ld", (int)GetCurrentProcessId (), (long)InterlockedIncrement (&pipe_id));
	*pipe_read = CreateNamedPipeA (name, PIPE_ACCESS_INBOUND | read_mode, PIPE_TYPE_BYTE | PIPE_WAIT, 1, sz, sz, 120 * 1000, attrs);
	if (!*pipe_read) {
		return false;
	}
	*pipe_write = CreateFileA (name, GENERIC_WRITE, 0, attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | write_mode, NULL);
	if (*pipe_write == INVALID_HANDLE_VALUE) {
		CloseHandle (*pipe_read);
		return false;
	}
	return true;
}

R_DEPRECATE R_API bool r2r_subprocess_init(void) {
	return true;
}

R_DEPRECATE R_API void r2r_subprocess_fini(void) {
	// nothing to do
}

static inline bool append_wchars(LPWCH buf, size_t *pos, size_t cap, const wchar_t *src, size_t len) {
	if (*pos + len > cap) {
		return false;
	}
	memcpy (buf + *pos, src, len * sizeof (wchar_t));
	*pos += len;
	return true;
}

static inline bool append_wchar(LPWCH buf, size_t *pos, size_t cap, wchar_t c) {
	if (*pos + 1 > cap) {
		return false;
	}
	buf[(*pos)++] = c;
	return true;
}

#define ENV_BUF_CAP 32768

// Create an env block that inherits the current vars but overrides the given ones
static LPWCH override_env(const char *envvars[], const char *envvals[], size_t env_size) {
	LPWCH ret = NULL;
	LPWCH parent_env = NULL;
	size_t i;
	LPWSTR *wenvvars = calloc (env_size, sizeof (LPWSTR));
	LPWSTR *wenvvals = calloc (env_size, sizeof (LPWSTR));
	parent_env = GetEnvironmentStringsW ();
	if (!wenvvars || !wenvvals || !parent_env) {
		goto error;
	}

	for (i = 0; i < env_size; i++) {
		wenvvars[i] = r_utf8_to_utf16 (envvars[i]);
		wenvvals[i] = r_utf8_to_utf16 (envvals[i]);
		if (!wenvvars[i] || !wenvvals[i]) {
			goto error;
		}
	}

	// Preallocate a reasonable size for environment variables (Windows limit is ~32KB)
	LPWCH buf = calloc (ENV_BUF_CAP, sizeof (wchar_t));
	if (!buf) {
		goto error;
	}
	size_t buf_pos = 0;
	LPWCH cur = parent_env;
	while (true) {
		LPWCH var_begin = cur;
		// wprintf (L"ENV: %s\n", cur);
		while (*cur && *cur != L'=') {
			cur++;
		}
		if (!*cur) {
			cur++;
			if (!*cur) {
				break;
			}
			continue;
		}
		bool overridden = false;
		for (i = 0; i < env_size; i++) {
			size_t overlen = lstrlenW (wenvvars[i]);
			size_t curlen = cur - var_begin;
			if (overlen == curlen && !memcmp (var_begin, wenvvars[i], overlen)) {
				overridden = true;
				break;
			}
		}
		while (*cur) {
			cur++;
		}
		if (!overridden) {
			size_t count = cur - var_begin + 1;
			if (!append_wchars (buf, &buf_pos, ENV_BUF_CAP, var_begin, count)) {
				free (buf);
				goto error;
			}
		}
		cur++;
		if (!*cur) {
			// \0\0 marks the end
			break;
		}
	}

	wchar_t c;
	for (i = 0; i < env_size; i++) {
		size_t len = lstrlenW (wenvvars[i]);
		if (!append_wchars (buf, &buf_pos, ENV_BUF_CAP, wenvvars[i], len)) {
			free (buf);
			goto error;
		}
		c = L'=';
		if (!append_wchar (buf, &buf_pos, ENV_BUF_CAP, c)) {
			free (buf);
			goto error;
		}
		len = lstrlenW (wenvvals[i]);
		if (!append_wchars (buf, &buf_pos, ENV_BUF_CAP, wenvvals[i], len)) {
			free (buf);
			goto error;
		}
		c = L'\0';
		if (!append_wchar (buf, &buf_pos, ENV_BUF_CAP, c)) {
			free (buf);
			goto error;
		}
	}
	if (!append_wchar (buf, &buf_pos, ENV_BUF_CAP, L'\0')) {
		free (buf);
		goto error;
	}
	ret = buf;
	return ret;

error:
	if (parent_env) {
		FreeEnvironmentStringsW (parent_env);
	}
	for (i = 0; i < env_size; i++) {
		if (wenvvars) {
			free (wenvvars[i]);
		}
		if (wenvvals) {
			free (wenvvals[i]);
		}
	}
	free (wenvvars);
	free (wenvvals);
	free (buf);
	return NULL;
}

R_API R2RSubprocess *r2r_subprocess_start(
	const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size) {
	char **argv = calloc (args_size + 1, sizeof (char *));
	R2RSubprocess *proc = NULL;
	HANDLE stdin_read = NULL, stdout_write = NULL, stderr_write = NULL;
	if (!argv) {
		return NULL;
	}
	argv[0] = (char *)file;
	if (args_size) {
		memcpy (argv + 1, args, sizeof (char *) * args_size);
	}
	char *cmdline = r_str_format_msvc_argv (args_size + 1, (const char **)argv);
	free (argv);
	if (!cmdline) {
		return NULL;
	}

	proc = R_NEW0 (R2RSubprocess);
	if (!proc) {
		goto error;
	}
	proc->ret = -1;
	proc->lock = r_th_lock_new (false);

	SECURITY_ATTRIBUTES sattrs;
	sattrs.nLength = sizeof (sattrs);
	sattrs.bInheritHandle = TRUE;
	sattrs.lpSecurityDescriptor = NULL;

	if (!create_pipe_overlap (&proc->stdout_read, &stdout_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
		proc->stdout_read = stdout_write = NULL;
		goto error;
	}
	if (!SetHandleInformation (proc->stdout_read, HANDLE_FLAG_INHERIT, 0)) {
		goto error;
	}
	if (!create_pipe_overlap (&proc->stderr_read, &stderr_write, &sattrs, 0, FILE_FLAG_OVERLAPPED, 0)) {
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
	STARTUPINFOA start_info = { 0 };
	start_info.cb = sizeof (start_info);
	start_info.hStdError = stderr_write;
	start_info.hStdOutput = stdout_write;
	start_info.hStdInput = stdin_read;
	start_info.dwFlags |= STARTF_USESTDHANDLES;

	LPWSTR env = override_env (envvars, envvals, env_size);
	if (!CreateProcessA (NULL, cmdline,
		NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT, env,
		NULL, &start_info, &proc_info)) {
		free (env);
		R_LOG_ERROR ("CreateProcess failed: %#x", (int)GetLastError ());
		goto error;
	}
	free (env);

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
	free (cmdline);
	return proc;
error:
	if (proc->stdin_write) {
		CloseHandle (proc->stdin_write);
	}
	if (proc->stdout_read) {
		CloseHandle (proc->stdout_read);
	}
	if (proc->stderr_read) {
		CloseHandle (proc->stderr_read);
	}
	R_FREE (proc);
	goto beach;
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

	ut64 timeout_us_abs = UT64_MAX;
	if (timeout_ms != UT64_MAX) {
		timeout_us_abs = r_time_now_mono () + timeout_ms * R_USEC_PER_MSEC;
	}

	ut8 stdout_buf[0x500];
	ut8 stderr_buf[0x500];
	bool stdout_eof = false;
	bool stderr_eof = false;
	bool child_dead = false;

#define DO_READ(which) \
	if (!ReadFile (proc->which ## _read, which ## _buf, sizeof (which ## _buf) - 1, NULL, &(which ## _overlapped))) { \
		if (GetLastError () != ERROR_IO_PENDING) { \
			/* EOF or some other error */ \
			which ## _eof = true; \
		} \
	}

	DO_READ (stdout)
	DO_READ (stderr)

	HANDLE handles[3];
	while (true) {
		size_t stdout_index = 0;
		size_t stderr_index = 0;
		size_t proc_index = 0;
		size_t handles_count = 0;
		if (!stdout_eof) {
			stdout_index = handles_count;
			handles[handles_count++] = stdout_overlapped.hEvent;
		}
		if (!stderr_eof) {
			stderr_index = handles_count;
			handles[handles_count++] = stderr_overlapped.hEvent;
		}
		if (!child_dead) {
			proc_index = handles_count;
			handles[handles_count++] = proc->proc;
		}

		DWORD timeout = INFINITE;
		if (timeout_us_abs != UT64_MAX) {
			ut64 now = r_time_now_mono ();
			if (now >= timeout_us_abs) {
				return false;
			}
			timeout = (DWORD) ((timeout_us_abs - now) / R_USEC_PER_MSEC);
		}
		DWORD signaled = WaitForMultipleObjects (handles_count, handles, FALSE, timeout);
		if (!stdout_eof && signaled == stdout_index) {
			DWORD r;
			BOOL res = GetOverlappedResult (proc->stdout_read, &stdout_overlapped, &r, TRUE);
			if (!res) {
				stdout_eof = true;
				continue;
			}
			stdout_buf[r] = '\0';
			r_str_remove_char ((char *)stdout_buf, '\r');
			r_strbuf_append (&proc->out, (const char *)stdout_buf);
			ResetEvent (stdout_overlapped.hEvent);
			DO_READ (stdout)
			continue;
		}
		if (!stderr_eof && signaled == stderr_index) {
			DWORD read;
			BOOL res = GetOverlappedResult (proc->stderr_read, &stderr_overlapped, &read, TRUE);
			if (!res) {
				stderr_eof = true;
				continue;
			}
			stderr_buf[read] = '\0';
			r_str_remove_char ((char *)stderr_buf, '\r');
			r_strbuf_append (&proc->err, (const char *)stderr_buf);
			ResetEvent (stderr_overlapped.hEvent);
			DO_READ (stderr);
			continue;
		}
		if (!child_dead && signaled == proc_index) {
			child_dead = true;
			DWORD exit_code;
			if (GetExitCodeProcess (proc->proc, &exit_code)) {
				proc->ret = exit_code;
			}
			continue;
		}
		break;
	}
	CloseHandle (stdout_overlapped.hEvent);
	CloseHandle (stderr_overlapped.hEvent);
	return stdout_eof && stderr_eof && child_dead;
}

R_API void r2r_subprocess_kill(R2RSubprocess *proc) {
	TerminateProcess (proc->proc, 255);
}

R_API void r2r_subprocess_stdin_write(R2RSubprocess *proc, const ut8 *buf, size_t buf_size) {
	DWORD read;
	WriteFile (proc->stdin_write, buf, buf_size, &read, NULL);
}

R_API R2RProcessOutput *r2r_subprocess_drain(R2RSubprocess *proc) {
	// XXX, duplicate from the unix path
	R2RProcessOutput *out = R_NEW (R2RProcessOutput);
	out->out = r_strbuf_drain_nofree (&proc->out);
	out->err = r_strbuf_drain_nofree (&proc->err);
	out->ret = proc->ret;
	return out;
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (R_LIKELY (proc)) {
		CloseHandle (proc->stdin_write);
		CloseHandle (proc->stdout_read);
		CloseHandle (proc->stderr_read);
		CloseHandle (proc->proc);
		r_strbuf_fini (&proc->out);
		r_strbuf_fini (&proc->err);
		free (proc);
	}
}
#else

#include <errno.h>
#ifndef __wasi__
#include <sys/wait.h>
#else
#define WNOHANG 0
#endif

struct r2r_subprocess_t {
	pid_t pid;
	int stdin_fd;
	int stdout_fd;
	int stderr_fd;
	int killpipe[2];
	int ret;
	RStrBuf out;
	RStrBuf err;
	RThreadLock *lock;
};

/// XXX remove globals!
static RVecR2RSubprocessPtr subprocs;
static RThreadLock *subprocs_mutex = NULL;
static int sigchld_pipe[2];
static RThread *sigchld_thread;

static void handle_sigchld(int sig) {
	ut8 b = 1;
	if (write (sigchld_pipe[1], &b, 1) != 1) {
		return;
	}
}

static R2RSubprocess *pid_to_proc(int pid) {
	R2RSubprocess **it;
	R_VEC_FOREACH (&subprocs, it) {
		R2RSubprocess *p = *it;
		if (p->pid == pid) {
			return p;
		}
	}
	return NULL;
}

static void subprocs_remove(R2RSubprocess *proc) {
	R2RSubprocess **it;
	ut64 idx = 0;
	R_VEC_FOREACH (&subprocs, it) {
		if (*it == proc) {
			RVecR2RSubprocessPtr_remove (&subprocs, idx);
			return;
		}
		idx++;
	}
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
				r_sys_perror ("sigchld- read");
			}
			break;
		}
		if (!b) {
			break;
		}
		while (true) {
			int wstat;
			// pid_t pid = wait (&wstat);
			pid_t pid = waitpid (-1, &wstat, 0);
			if (pid <= 0) {
				// 	r_sys_perror ("waitpid failed");
				break;
			}
			r_th_lock_enter (subprocs_mutex);
			R2RSubprocess *proc = pid_to_proc (pid);
			if (!proc) {
				r_th_lock_leave (subprocs_mutex);
				continue;
			}
			// Capture exit status while holding only one lock
			int exit_status = -1;
#if !__wasi__
			if (WIFSIGNALED (wstat)) {
				const int signal_number = WTERMSIG (wstat);
				R_LOG_ERROR ("Child signal %d", signal_number);
				exit_status = -1;
			} else if (WIFEXITED (wstat)) {
				exit_status = WEXITSTATUS (wstat);
			}
#endif

			// Update process status before signaling
			r_th_lock_enter (proc->lock);
			proc->ret = exit_status;
			r_th_lock_leave (proc->lock);
			// Signal process completion through killpipe
			int ret = write (proc->killpipe[1], "", 1);
			if (ret != 1) {
				r_sys_perror ("write killpipe-");
				r_th_lock_leave (subprocs_mutex);
				break;
			}
			r_th_lock_leave (subprocs_mutex);
		}
	}
	return R_TH_STOP;
}

R_API bool r2r_subprocess_init(void) {
	RVecR2RSubprocessPtr_init (&subprocs);
	subprocs_mutex = r_th_lock_new (false);
	if (!subprocs_mutex) {
		return false;
	}
	if (pipe (sigchld_pipe) == -1) {
		r_sys_perror ("subprocess-init pipe");
		r_th_lock_free (subprocs_mutex);
		return false;
	}
	if (fcntl (sigchld_pipe[1], F_SETFL, O_NONBLOCK) < 0) {
		r_sys_perror ("fcntl sigchld_pipe");
		goto error;
	}
	sigchld_thread = r_th_new (sigchld_th, NULL, 0);
	if (!r_th_start (sigchld_thread)) {
		goto error;
	}
	if (r_sys_signal (SIGCHLD, handle_sigchld) < 0) {
		goto error;
	}
	return true;

error:
	if (sigchld_thread) {
		r_th_free (sigchld_thread);
		sigchld_thread = NULL;
	}
	close (sigchld_pipe[0]);
	close (sigchld_pipe[1]);
	r_th_lock_free (subprocs_mutex);
	return false;
}

R_API void r2r_subprocess_fini(void) {
	r_sys_signal (SIGCHLD, SIG_IGN);
	ut8 b = 0;
	if (write (sigchld_pipe[1], &b, 1) != 1) {
		// nothing relevant here
	}
	close (sigchld_pipe[1]);
	r_th_wait (sigchld_thread);
	close (sigchld_pipe[0]);
	r_th_free (sigchld_thread);
	R2RSubprocess **it;
	R_VEC_FOREACH (&subprocs, it) {
		r2r_subprocess_free (*it);
	}
	RVecR2RSubprocessPtr_clear (&subprocs);
	r_th_lock_free (subprocs_mutex);
}

static inline void dup_retry(int fds[2], int n, int b) {
	while ((dup2 (fds[n], b) == -1) && (errno == EINTR)) {
		;
	}
	close (fds[0]);
	close (fds[1]);
}

R_API R2RSubprocess *r2r_subprocess_start(
	const char *file, const char *args[], size_t args_size,
	const char *envvars[], const char *envvals[], size_t env_size) {
	int stdin_pipe[2] = { -1, -1 };
	int stdout_pipe[2] = { -1, -1 };
	int stderr_pipe[2] = { -1, -1 };

	r_th_lock_enter (subprocs_mutex);
	R2RSubprocess *proc = R_NEW0 (R2RSubprocess);
	proc->killpipe[0] = proc->killpipe[1] = -1;
	proc->ret = -1;
	proc->lock = r_th_lock_new (false);
	r_strbuf_init (&proc->out);
	r_strbuf_init (&proc->err);
#if 0
	r_strbuf_reserve (&proc->out, 32768);
	r_strbuf_reserve (&proc->err, 32768);
#endif
	if (pipe (proc->killpipe) == -1) {
		r_sys_perror ("subproc-start pipe");
		goto error;
	}
	if (fcntl (proc->killpipe[1], F_SETFL, O_NONBLOCK) < 0) {
		r_sys_perror ("subproc-start fcntl");
		goto error;
	}
	/* Prevent these internal notif pipes from being inherited by children */
	(void)fcntl (proc->killpipe[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl (proc->killpipe[1], F_SETFD, FD_CLOEXEC);

	if (pipe (stdin_pipe) == -1) {
		r_sys_perror ("subproc-start pipe");
		goto error;
	}
	proc->stdin_fd = stdin_pipe[1];

	if (pipe (stdout_pipe) == -1) {
		r_sys_perror ("subproc-start pipe");
		goto error;
	}
	if (fcntl (stdout_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		r_sys_perror ("subproc-start fcntl");
		goto error;
	}
	proc->stdout_fd = stdout_pipe[0];

	if (pipe (stderr_pipe) == -1) {
		r_sys_perror ("subproc-start pipe");
		goto error;
	}
	if (fcntl (stderr_pipe[0], F_SETFL, O_NONBLOCK) < 0) {
		r_sys_perror ("subproc-start fcntl");
		goto error;
	}
	proc->stderr_fd = stderr_pipe[0];

	proc->pid = r_sys_fork ();
	if (proc->pid == -1) {
		// fail
		r_th_lock_leave (subprocs_mutex);
		r_sys_perror ("subproc-start fork");
		free (proc);
		return NULL;
	}
	if (proc->pid == 0) {
		/* Ensure child is leader of a new process group so the whole
		 * subtree can be killed by signaling the group. */
		(void)setpgid (0, 0);
		dup_retry (stdin_pipe, 0, STDIN_FILENO);
		dup_retry (stdout_pipe, 1, STDOUT_FILENO);
		dup_retry (stderr_pipe, 1, STDERR_FILENO);
		char **argv = calloc (args_size + 2, sizeof (char *));
		if (!argv) {
			free (proc);
			return NULL;
		}
		argv[0] = (char *)file;
		if (args_size) {
			memcpy (argv + 1, args, sizeof (char *) * args_size);
		}
		size_t i;
		for (i = 0; i < env_size; i++) {
			setenv (envvars[i], envvals[i], 1);
		}
		execvp (file, argv);
		free (argv);
		r_sys_perror ("subproc-start exec");
		r_sys_exit (-1, true);
	}

	// parent
	/* Best-effort: set the child's pgid from the parent side too. It may
	 * fail if the child already changed pgid, so ignore errors. */
	if (proc->pid > 0) {
		(void)setpgid (proc->pid, proc->pid);
	}
	close (stdin_pipe[0]);
	close (stdout_pipe[1]);
	close (stderr_pipe[1]);

	RVecR2RSubprocessPtr_push_back (&subprocs, &proc);

	r_th_lock_leave (subprocs_mutex);

	return proc;
error:
	if (proc->killpipe[0] != -1) {
		close (proc->killpipe[0]);
	}
	if (proc->killpipe[1] != -1) {
		close (proc->killpipe[1]);
	}
	free (proc);
	if (stderr_pipe[0] != -1) {
		close (stderr_pipe[0]);
	}
	if (stderr_pipe[1] != -1) {
		close (stderr_pipe[1]);
	}
	if (stdout_pipe[0] != -1) {
		close (stdout_pipe[0]);
	}
	if (stdout_pipe[1] != -1) {
		close (stdout_pipe[1]);
	}
	if (stdin_pipe[0] != -1) {
		close (stdin_pipe[0]);
	}
	if (stdin_pipe[1] != -1) {
		close (stdin_pipe[1]);
	}
	r_th_lock_leave (subprocs_mutex);
	return NULL;
}

R_API bool r2r_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms) {
	ut64 timeout_abs = 0;
	if (timeout_ms != UT64_MAX) {
		timeout_abs = r_time_now_mono () + timeout_ms * R_USEC_PER_MSEC;
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
			ut64 now = r_time_now_mono ();
			if (now >= timeout_abs) {
				break;
			}
			ut64 usec_diff = timeout_abs - r_time_now_mono ();
			timeout_s.tv_sec = usec_diff / R_USEC_PER_SEC;
			timeout_s.tv_usec = usec_diff % R_USEC_PER_SEC;
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
			char buf[4096];
			ssize_t sz = read (proc->stdout_fd, buf, sizeof (buf));
			if (sz < 0) {
				r_sys_perror ("sp-wait read 1");
				child_dead = true;
				stdout_eof = true;
			} else if (sz == 0) {
				stdout_eof = true;
			} else {
				r_strbuf_append_n (&proc->out, buf, (int)sz);
			}
		}
		if (FD_ISSET (proc->stderr_fd, &rfds)) {
			timedout = false;
			char buf[4096];
			ssize_t sz = read (proc->stderr_fd, buf, sizeof (buf));
			if (sz < 0) {
				r_sys_perror ("sp-wait read 2");
				child_dead = true;
				break;
			}
			if (sz == 0) {
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
		r_sys_perror ("sp-wait select");
	}
	return child_dead;
}

R_API void r2r_subprocess_kill(R2RSubprocess *proc) {
	/* Kill the whole process group to ensure grandchildren are terminated */
	if (kill (-proc->pid, SIGKILL) == -1) {
		r_sys_perror ("killpg");
	}
}

R_API void r2r_subprocess_stdin_write(R2RSubprocess *proc, const ut8 *buf, size_t buf_size) {
	if (write (proc->stdin_fd, buf, buf_size) != buf_size) {
		// another ignored result
	}
	close (proc->stdin_fd);
	proc->stdin_fd = -1;
}

R_API R2RProcessOutput *r2r_subprocess_drain(R2RSubprocess *proc) {
	R_RETURN_VAL_IF_FAIL (proc, NULL);
	if (proc->lock && r_th_lock_enter (proc->lock)) {
		R2RProcessOutput *out = R_NEW0 (R2RProcessOutput);
// XXX for some reason strdup handles memory better than drain_nofree
//		out->out = r_strbuf_drain_nofree (&proc->out);
//		out->err = r_strbuf_drain_nofree (&proc->err);
		out->out = strdup (r_strbuf_get (&proc->out));
		out->err = strdup (r_strbuf_get (&proc->err));
		out->ret = proc->ret;
		out->timeout = false;
		r_th_lock_leave (proc->lock);
		return out;
	}
	R_LOG_ERROR ("Cannot acquire the lock wtf");
	return NULL;
}

R_API void r2r_subprocess_free(R2RSubprocess *proc) {
	if (!proc) {
		return;
	}
	// Take mutex to safely modify the subprocs vector
	if (!r_th_lock_enter (subprocs_mutex)) {
		// If we can't take the lock, still try to free resources
		// to avoid leaking, but don't modify shared data structures
		goto cleanup_without_vector;
	}
	// Remove from global vector of subprocesses
	subprocs_remove (proc);
	r_th_lock_leave (subprocs_mutex);
	// Now safely clean up process resources
cleanup_without_vector:
	// Acquire the process lock to ensure no one is currently
	// writing to or reading from its buffers
	if (proc->lock) {
		r_th_lock_enter (proc->lock);
		// Free buffers - only reinitialize them if they haven't been drained
		// This prevents double frees when r2r_subprocess_drain has been called
		if (proc->out.ptr) {
			r_strbuf_fini (&proc->out);
		//	r_strbuf_init (&proc->out); // Reinitialize to avoid issues with subsequent r_strbuf_fini
		}
		if (proc->err.ptr) {
			r_strbuf_fini (&proc->err);
		//	r_strbuf_init (&proc->err); // Reinitialize to avoid issues with subsequent r_strbuf_fini
		}
		// Release the process lock before freeing it
		r_th_lock_leave (proc->lock);
		r_th_lock_free (proc->lock);
	} else {
		R_LOG_ERROR ("We couldnt get the lock wtf");
		// Even if we can't get the lock, we need to safely clean up buffers
		// If buffers have been drained, ptr would be NULL and this is safe
		r_strbuf_fini (&proc->out);
		r_strbuf_fini (&proc->err);
	}
	// Close all open file descriptors
	if (proc->killpipe[0] != -1) {
		close (proc->killpipe[0]);
	}
	if (proc->killpipe[1] != -1) {
		close (proc->killpipe[1]);
	}
	if (proc->stdin_fd != -1) {
		close (proc->stdin_fd);
	}
	if (proc->stdout_fd != -1) {
		close (proc->stdout_fd);
	}
	if (proc->stderr_fd != -1) {
		close (proc->stderr_fd);
	}
	// Finally free the process struct itself
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
	const char *envvars[], const char *envvals[], size_t env_size, ut64 timeout_ms, void *user) {
	R2RSubprocess *proc = r2r_subprocess_start (file, args, args_size, envvars, envvals, env_size);
	if (!proc) {
		return NULL;
	}
	bool timeout = !r2r_subprocess_wait (proc, timeout_ms);
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

#if R2__WINDOWS__
static char *convert_win_cmds(const char *cmds) {
	char *r = malloc (strlen (cmds) + 1);
	if (!r) {
		return NULL;
	}
	char *p = r;
	while (*cmds) {
		if (*cmds == '!' || (*cmds == '\"' && cmds[1] == '!')) {
			// Adjust shell syntax for Windows,
			// only for lines starting with ! or "!
			char c;
			for (; c = *cmds, c; cmds++) {
				if (c == '\\') {
					// replace \$ by $
					c = *++cmds;
					if (c == '$') {
						*p++ = '$';
					} else {
						*p++ = '\\';
						*p++ = c;
					}
				} else if (c == '$') {
					// replace ${VARNAME} by %VARNAME%
					c = *++cmds;
					if (c == '{') {
						*p++ = '%';
						cmds++;
						for (; c = *cmds, c && c != '}'; *++cmds) {
							*p++ = c;
						}
						if (c) { // must check c to prevent overflow
							*p++ = '%';
						}
					} else {
						*p++ = '$';
						*p++ = c;
					}
				} else {
					*p++ = c;
					if (c == '\n') {
						cmds++;
						break;
					}
				}
			}
			continue;
		}

		// Nothing to do, just copy the line
		char *lend = strchr (cmds, '\n');
		size_t llen;
		if (lend) {
			llen = lend - cmds + 1;
		} else {
			llen = strlen (cmds);
		}
		memcpy (p, cmds, llen);
		cmds += llen;
		p += llen;
	}
	*p = '\0';
	return r_str_replace (r, "/dev/null", "nul", true);
}
#endif

static const char **rlist_to_argv(RList *list, size_t *size) {
	size_t len = r_list_length (list);
	*size = len;
	const char **arr = calloc (len, sizeof (const char *));
	if (!arr) {
		return NULL;
	}
	size_t i = 0;
	RListIter *it;
	void *elem;
	r_list_foreach (list, it, elem) {
		arr[i++] = elem;
	}
	return arr;
}

static R2RProcessOutput *run_r2_test(R2RRunConfig *config, ut64 timeout_ms, int repeat, const char *cmds, RList *files, RList *extra_args, RList *extra_env, bool load_plugins, R2RCmdRunner runner, void *user) {
	RList *args = r_list_new ();
	RList *envvars = r_list_new ();
	RList *envvals = r_list_new ();

	r_list_append (args, (void *)"-escr.utf8=0");
	r_list_append (args, (void *)"-escr.color=0");
	r_list_append (args, (void *)"-escr.interactive=0");

	if (!load_plugins) {
		r_list_append (args, (void *)"-NN");
	}
	RListIter *it;
	void *extra_arg, *file_arg;
	if (extra_args) {
		r_list_foreach (extra_args, it, extra_arg) {
			r_list_append (args, extra_arg);
		}
	}
	r_list_append (args, (void *)"-Qc");
#if R2__WINDOWS__
	char *wcmds = convert_win_cmds (cmds);
	r_list_append (args, wcmds);
#else
	r_list_append (args, (void *)cmds);
#endif
	r_list_foreach (files, it, file_arg) {
		r_list_append (args, file_arg);
	}

#if R2__WINDOWS__
	r_list_append (envvars, (void *)"ANSICON");
	r_list_append (envvals, (void *)"1");
#endif
	if (!load_plugins) {
		r_list_append (envvars, (void *)"R2_NOPLUGINS");
		r_list_append (envvals, (void *)"1");
	}
	if (extra_env) {
		char *kv;
		r_list_foreach (extra_env, it, kv) {
			char *equal = strstr (kv, "=");
			if (equal) {
				*equal = 0;
				r_list_append (envvars, (void *)kv);
				r_list_append (envvals, (void *) (equal + 1));
			}
		}
	}

	size_t args_size, env_size;
	const char **argv = rlist_to_argv (args, &args_size);
	const char **envk = rlist_to_argv (envvars, &env_size);
	const char **envv = rlist_to_argv (envvals, &env_size);

	R2RProcessOutput *out;
	if (repeat > 1) {
		int rep = repeat;
		while (rep-- > 0) {
			out = runner (config->r2_cmd, argv, args_size, envk, envv, env_size, timeout_ms, user);
		}
	} else {
		out = runner (config->r2_cmd, argv, args_size, envk, envv, env_size, timeout_ms, user);
	}

#if R2__WINDOWS__
	free (wcmds);
#endif
	free (argv);
	free (envk);
	free (envv);
	r_list_free (args);
	r_list_free (envvars);
	r_list_free (envvals);
	return out;
}

R_API R2RProcessOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test, R2RCmdRunner runner, void *user) {
	RList *extra_args = test->args.value? r_str_split_duplist (test->args.value, " ", true): NULL;
	RList *files = test->file.value? r_str_split_duplist (test->file.value, "\n", true): NULL;
	RListIter *it;
	RListIter *tmpit;
	RList *extra_env = NULL;
	char *token;
	if (extra_args) {
		r_list_foreach_safe (extra_args, it, tmpit, token) {
			if (!*token) {
				r_list_delete (extra_args, it);
			}
		}
	}
	if (!files) {
		files = r_list_newf (free);
		r_list_append (files, strdup ("-"));
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
	if (test->env.value) {
		extra_env = r_str_split_duplist (test->env.value, ";", true);
	}
	int repeat = test->repeat.value;
	const ut64 timeout_ms = test->timeout.set? test->timeout.value * 1000: config->timeout_ms;
	R2RProcessOutput *out = run_r2_test (config, timeout_ms, repeat,
		test->cmds.value, files, extra_args, extra_env, test->load_plugins, runner, user);
	r_list_free (extra_args);
	r_list_free (files);
	r_list_free (extra_env);
	return out;
}

R_API bool r2r_check_cmd_test(R2RProcessOutput *out, R2RCmdTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
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
	const char *regexp_out = test->regexp_out.value;
	if (regexp_out && !r_regex_match (regexp_out, "e", out->out)) {
		return false;
	}
	const char *regexp_err = test->regexp_err.value;
	if (regexp_err && !r_regex_match (regexp_err, "e", out->err)) {
		return false;
	}
	return true;
}

#define JQ_CMD "jq"

R_API bool r2r_check_jq_available(void) {
	const char *args[] = { "." };
	const char *invalid_json = "this is not json lol";
	R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (!proc) {
		R_LOG_ERROR ("Cannot start subprocess");
		return false;
	}
	r2r_subprocess_stdin_write (proc, (const ut8 *)invalid_json, strlen (invalid_json));
	r2r_subprocess_wait (proc, UT64_MAX);
	r_th_lock_enter (proc->lock);
	bool invalid_detected = proc && proc->ret != 0;
	r_th_lock_leave (proc->lock);
	r2r_subprocess_free (proc);
	proc = NULL;

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	bool valid_detected = false;
	proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		r2r_subprocess_stdin_write (proc, (const ut8 *)valid_json, strlen (valid_json));
		r2r_subprocess_wait (proc, UT64_MAX);
		r_th_lock_enter (proc->lock);
		valid_detected = proc->ret == 0;
		r_th_lock_leave (proc->lock);
	}
	r2r_subprocess_free (proc);

	return invalid_detected && valid_detected;
}

R_API R2RProcessOutput *r2r_run_json_test(R2RRunConfig *config, R2RJsonTest *test, R2RCmdRunner runner, void *user) {
	RList *files = r_list_new ();
	r_list_push (files, (void *)config->json_test_file);
	// TODO: config->timeout_ms is already inside config, no need to pass it twice! chk other calls
	R2RProcessOutput *ret = run_r2_test (config, config->timeout_ms, 1, test->cmd, files, NULL, NULL, test->load_plugins, runner, user);
	r_list_free (files);
	return ret;
}

R_API R2RProcessOutput *r2r_run_json_test_nofile(R2RRunConfig *config, R2RJsonTest *test, R2RCmdRunner runner, void *user) {
	RList *files = r_list_new ();
	r_list_push (files, "--");
	// TODO: config->timeout_ms is already inside config, no need to pass it twice! chk other calls
	R2RProcessOutput *ret = run_r2_test (config, config->timeout_ms, 1, test->cmd, files, NULL, NULL, test->load_plugins, runner, user);
	r_list_free (files);
	return ret;
}

static bool r2r_empty_json_check(R2RProcessOutput *out) {
	char *s = r_str_trim_dup (out->out);
	const bool is_not_empty = (R_STR_ISNOTEMPTY (s));
	free (s);
	return is_not_empty;
}

R_API bool r2r_check_json_test(R2RProcessOutput *out, R2RJsonTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *args[] = { "." };
	bool ret = false;
	if (r2r_empty_json_check (out)) {
		R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
		r2r_subprocess_stdin_write (proc, (const ut8 *)out->out, strlen (out->out));
		r2r_subprocess_wait (proc, UT64_MAX);
		ret = proc->ret == 0;
		r2r_subprocess_free (proc);
	} else {
		eprintf ("\n");
		R_LOG_ERROR ("[XX] Empty json for %s", test->cmd);
	}
	return ret;
}

R_API R2RAsmTestOutput *r2r_run_asm_test(R2RRunConfig *config, R2RAsmTest *test) {
	R2RAsmTestOutput *out = R_NEW0 (R2RAsmTestOutput);
	RList *args = r_list_new ();

	if (test->arch) {
		r_list_append (args, (void *)"-a");
		r_list_append (args, (void *)test->arch);
	}

	if (test->cpu) {
		r_list_append (args, (void *)"-c");
		r_list_append (args, (void *)test->cpu);
	}

	char *bits_str = NULL;
	if (test->bits) {
		bits_str = r_str_newf ("%d", test->bits);
		r_list_append (args, (void *)"-b");
		r_list_append (args, bits_str);
	}

	if (test->mode & R2R_ASM_TEST_MODE_BIG_ENDIAN) {
		r_list_append (args, (void *)"-e");
	}

	char *offset_str = NULL;
	if (test->offset) {
		offset_str = r_str_newf ("0x%" PFMT64x, test->offset);
		r_list_append (args, (void *)"-s");
		r_list_append (args, offset_str);
	}

	size_t args_size;
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		r_list_append (args, (void *)test->disasm);
		const char **argv = rlist_to_argv (args, &args_size);
		R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, argv, args_size, NULL, NULL, 0);
		if (!r2r_subprocess_wait (proc, config->timeout_ms)) {
			r2r_subprocess_kill (proc);
			out->as_timeout = true;
		} else if (proc->ret == 0) {
			char *hex = r_strbuf_get (&proc->out);
			size_t hexlen = strlen (hex);
			if (hexlen > 0) {
				ut8 *bytes = malloc (hexlen);
				if (bytes) {
					const int byteslen = r_hex_str2bin (hex, bytes);
					if (byteslen > 0) {
						out->bytes = bytes;
						out->bytes_size = (size_t)byteslen;
					} else {
						free (bytes);
					}
				}
			}
		}
		free (argv);
		r2r_subprocess_free (proc);
		r_list_pop (args);
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		if (test->bytes_size > 0) {
			char *hex = r_hex_bin2strdup (test->bytes, test->bytes_size);
			if (hex) {
				r_list_append (args, (void *)"-d");
				r_list_append (args, hex);
				const char **argv = rlist_to_argv (args, &args_size);
				R2RSubprocess *proc = r2r_subprocess_start (config->rasm2_cmd, argv, args_size, NULL, NULL, 0);
				if (!r2r_subprocess_wait (proc, config->timeout_ms)) {
					r2r_subprocess_kill (proc);
					out->disas_timeout = true;
				} else if (proc->ret == 0) {
					char *disasm = r_strbuf_drain_nofree (&proc->out);
					r_str_trim (disasm);
					out->disasm = disasm;
				}
				free (argv);
				r2r_subprocess_free (proc);
				free (hex);
			}
		}
	}

	r_list_free (args);
	free (bits_str);
	free (offset_str);
	return out;
}

R_API bool r2r_check_asm_test(R2RAsmTestOutput *out, R2RAsmTest *test) {
	if (!out) {
		return false;
	}
	if (test->mode & R2R_ASM_TEST_MODE_ASSEMBLE) {
		if (!out->bytes || !test->bytes || out->bytes_size != test->bytes_size || out->as_timeout) {
			return false;
		}
		if (memcmp (out->bytes, test->bytes, test->bytes_size)) {
			return false;
		}
	}
	if (test->mode & R2R_ASM_TEST_MODE_DISASSEMBLE) {
		if (!out->disasm || !test->disasm || out->as_timeout) {
			return false;
		}
		if (strcmp (out->disasm, test->disasm)) {
			return false;
		}
	}
	return true;
}

R_API void r2r_asm_test_output_free(R2RAsmTestOutput *out) {
	if (out) {
		free (out->disasm);
		free (out->bytes);
		free (out);
	}
}

R_API R2RProcessOutput *r2r_run_fuzz_test(R2RRunConfig *config, const char *file, R2RCmdRunner runner, void *user) {
	const char *cmd = "aaa";
	RList *files = r_list_new ();
	r_list_push (files, (void *)file);
	R2RProcessOutput *ret = run_r2_test (config, config->timeout_ms, 1, cmd, files, NULL, NULL, false, runner, user);
	r_list_free (files);
	return ret;
}

R_API bool r2r_check_fuzz_test(R2RProcessOutput *out) {
	return out && out->ret == 0 && out->out && out->err && !out->timeout;
}

R_API char *r2r_test_name(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		if (test->cmd_test->name.value) {
			return strdup (test->cmd_test->name.value);
		}
		return strdup ("<unnamed>");
	case R2R_TEST_TYPE_ASM:
		return r_str_newf ("<asm> %s", r_str_get (test->asm_test->disasm));
	case R2R_TEST_TYPE_JSON:
		return r_str_newf ("<json> %s", r_str_get (test->json_test->cmd));
	case R2R_TEST_TYPE_FUZZ:
		return r_str_newf ("<fuzz> %s", test->path);
	}
	return NULL;
}

// -1 = oldabi, 0 = no abi specific test, 1 = new abi required
R_API int r2r_test_needsabi(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		// TODO only cmd tests cant have newabi mode
		if (test->cmd_test->newabi.value) {
			return 1;
		}
		if (test->cmd_test->oldabi.value) {
			return -1;
		}
		break;
	case R2R_TEST_TYPE_ASM:
	case R2R_TEST_TYPE_JSON:
	case R2R_TEST_TYPE_FUZZ:
		break;
	}
	return 0;
}

R_API bool r2r_test_broken(R2RTest *test) {
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		return test->cmd_test->broken.value;
	case R2R_TEST_TYPE_ASM:
		return test->asm_test->mode & R2R_ASM_TEST_MODE_BROKEN? true: false;
	case R2R_TEST_TYPE_JSON:
		return test->json_test->broken;
	case R2R_TEST_TYPE_FUZZ:
		return false;
	}
	return false;
}

#if ASAN
static bool check_cmd_asan_result(R2RProcessOutput *out) {
	bool stdout_success = !out->out || (!strstr (out->out, "WARNING:") && !strstr (out->out, "ERROR:") && !strstr (out->out, "FATAL:"));
	bool stderr_success = !out->err || (!strstr (out->err, "Sanitizer")
			&& !strstr (out->err, "runtime error:");
	return stdout_success && stderr_success;
}
#endif

static bool require_check(const char *require) {
	if (R_STR_ISEMPTY (require)) {
		return true;
	}
	bool res = true;
	if (strstr (require, "gas")) {
		char *as_bin = r_file_path ("as");
		res &= (bool)as_bin;
		free (as_bin);
	}
	if (strstr (require, "unix")) {
#if R2__UNIX__
		res &= true;
#else
		res = false;
#endif
	}
	if (strstr (require, "windows")) {
#if R2__WINDOWS__
		res &= true;
#else
		res = false;
#endif
	}
	if (strstr (require, "linux")) {
#if __linux__
		res &= true;
#else
		res = false;
#endif
	}
	if (strstr (require, "arm")) {
#if __arm64__ || __arm__
		res &= true;
#else
		res &= false;
#endif
	}
	if (strstr (require, "x86")) {
#if __i386__ || __x86_64__
		res &= true;
#else
		res &= false;
#endif
	}
	return res;
}

R_API R2RTestResultInfo *r2r_run_test(R2RRunConfig *config, R2RTest *test) {
	R2RTestResultInfo *ret = R_NEW0 (R2RTestResultInfo);
	if (!ret) {
		return NULL;
	}
	ret->test = test;
	bool success = false;
	ut64 start_time = r_time_now_mono ();
	int needsabi = r2r_test_needsabi (test);
	switch (test->type) {
	case R2R_TEST_TYPE_CMD:
		if (config->skip_cmd) {
			success = true;
			ret->run_failed = false;
		} else {
			R2RCmdTest *cmd_test = test->cmd_test;
			const char *require = cmd_test->require.value;
			if (!require_check (require)) {
				R_LOG_WARN ("Skipping because of %s", require);
				success = true;
				ret->run_failed = false;
				break;
			}
#if WANT_V35 == 0
			if (cmd_test->args.value && strstr (cmd_test->args.value, "arm.v35")) {
				R_LOG_WARN ("Skipping test because it requires arm.v35");
				success = true;
				ret->run_failed = false;
				break;
			}
#endif
#if R2_USE_NEW_ABI
			bool mustrun = !needsabi || (needsabi > 0);
#else
			bool mustrun = !needsabi || (needsabi < 0);
#endif
			if (mustrun) {
				R2RProcessOutput *out = r2r_run_cmd_test (config, cmd_test, subprocess_runner, NULL);
				success = r2r_check_cmd_test (out, cmd_test);
				ret->proc_out = out;
				ret->timeout = out? out->timeout: false;
				ret->run_failed = !out;
			} else {
				success = true;
				ret->proc_out = NULL;
				ret->timeout = false;
				ret->run_failed = false;
			}
		}
		break;
	case R2R_TEST_TYPE_ASM:
		if (config->skip_asm) {
			success = true;
			ret->run_failed = false;
		} else {
			R2RAsmTest *at = test->asm_test;
			R2RAsmTestOutput *out = r2r_run_asm_test (config, at);
			success = r2r_check_asm_test (out, at);
			const bool is_broken = at->mode & R2R_ASM_TEST_MODE_BROKEN;
			if (!success && !is_broken) {
				if (at->bytes_size < 1 || out->bytes_size < 1) {
					eprintf ("\n" Color_RED "- %s" Color_RESET " # bytes_size = %d\n", at->disasm, (int)at->bytes_size);
					eprintf (Color_GREEN "+ %s" Color_RESET " # bytes_size = %d\n", out->disasm, (int)out->bytes_size);
				} else {
					char *b0 = r_hex_bin2strdup (at->bytes, at->bytes_size);
					char *b1 = r_hex_bin2strdup (out->bytes, out->bytes_size);
					eprintf ("\n" Color_RED "- %s" Color_RESET " # %s\n", at->disasm, b0);
					eprintf (Color_GREEN "+ %s" Color_RESET " # %s\n", out->disasm, b1);
					free (b0);
					free (b1);
				}
			}
			// TODO: show more details of the failed assembled instruction
			ret->asm_out = out;
			ret->timeout = out->as_timeout || out->disas_timeout;
			ret->run_failed = !out;
		}
		break;
	case R2R_TEST_TYPE_JSON:
		if (config->skip_json) {
			success = true;
			ret->run_failed = false;
		} else {
			R2RJsonTest *json_test = test->json_test;
			R2RProcessOutput *out = r2r_run_json_test (config, json_test, subprocess_runner, NULL);
			success = r2r_check_json_test (out, json_test);
			if (strchr (json_test->cmd, '@')) {
				// ignore json tests with @ when running r2 with no files
			} else {
				// test output of commands when no file is provided
				r2r_process_output_free (out);
				out = r2r_run_json_test_nofile (config, json_test, subprocess_runner, NULL);
				if (!r2r_check_json_test (out, json_test)) {
					success = false;
				}
			}
			ret->proc_out = out;
			ret->timeout = out->timeout;
			ret->run_failed = !out;
		}
		break;
	case R2R_TEST_TYPE_FUZZ:
		if (config->skip_fuzz) {
			success = true;
			ret->run_failed = false;
		} else {
			R2RProcessOutput *out = r2r_run_fuzz_test (config, test->path, subprocess_runner, NULL);
			success = r2r_check_fuzz_test (out);
			ret->proc_out = out;
			ret->timeout = out->timeout;
			ret->run_failed = !out;
		}
		break;
	}
	ret->time_elapsed = r_time_now_mono () - start_time;
	bool broken = r2r_test_broken (test);
#if ASAN
#if !R2_ASSERT_STDOUT
#error R2_ASSERT_STDOUT undefined or 0
#endif
	R2RProcessOutput *out = ret->proc_out;
	if (!success && test->type == R2R_TEST_TYPE_CMD && strstr (test->path, "/dbg")) {
		broken = check_cmd_asan_result (out);
	}
#endif
	if (success) {
		ret->result = broken? R2R_TEST_RESULT_FIXED: R2R_TEST_RESULT_OK;
	} else {
		ret->result = broken? R2R_TEST_RESULT_BROKEN: R2R_TEST_RESULT_FAILED;
	}
	return ret;
}

R_API void r2r_test_result_info_free(R2RTestResultInfo *result) {
	if (result && result->test) {
		switch (result->test->type) {
		case R2R_TEST_TYPE_CMD:
		case R2R_TEST_TYPE_JSON:
		case R2R_TEST_TYPE_FUZZ:
			r2r_process_output_free (result->proc_out);
			break;
		case R2R_TEST_TYPE_ASM:
			r2r_asm_test_output_free (result->asm_out);
			break;
		}
	}
	free (result);
}
