/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "r2r.h"

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

static volatile long pipe_id = 0;

static bool create_pipe_overlap(HANDLE *pipe_read, HANDLE *pipe_write, LPSECURITY_ATTRIBUTES attrs, DWORD sz, DWORD read_mode, DWORD write_mode) {
	// see https://stackoverflow.com/a/419736
	if (!sz) {
		sz = 4096;
	}
	char name[MAX_PATH];
	snprintf (name, sizeof (name), "\\\\.\\pipe\\r2r-subproc.%d.%ld", (int)GetCurrentProcessId (), (long)InterlockedIncrement (&pipe_id));
	*pipe_read = CreateNamedPipeA (name, PIPE_ACCESS_INBOUND | read_mode, PIPE_TYPE_BYTE | PIPE_WAIT, 1, sz, sz, 120 * 1000, attrs);
	if (!*pipe_read) {
		return FALSE;
	}
	*pipe_write = CreateFileA (name, GENERIC_WRITE, 0, attrs, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | write_mode, NULL);
	if (*pipe_write == INVALID_HANDLE_VALUE) {
		CloseHandle (*pipe_read);
		return FALSE;
	}
	return true;
}

R_API bool r2r_subprocess_init(void) { return true; }
R_API void r2r_subprocess_fini(void) {}

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

	RVector buf;
	r_vector_init (&buf, sizeof (wchar_t), NULL, NULL);
	LPWCH cur = parent_env;
	while (true) {
		LPWCH var_begin = cur;
		//wprintf (L"ENV: %s\n", cur);
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
			r_vector_insert_range (&buf, buf.len, var_begin, cur - var_begin + 1);
		}
		cur++;
		if (!*cur) {
			// \0\0 marks the end
			break;
		}
	}

	wchar_t c;
	for (i = 0; i < env_size; i++) {
		r_vector_insert_range (&buf, buf.len, wenvvars[i], lstrlenW (wenvvars[i]));
		c = L'=';
		r_vector_push (&buf, &c);
		r_vector_insert_range (&buf, buf.len, wenvvals[i], lstrlenW (wenvvals[i]));
		c = L'\0';
		r_vector_push (&buf, &c);
	}
	c = '\0';
	r_vector_push (&buf, &c);
	ret = buf.a;

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
	return ret;
}

R_API R2RSubprocess *r2r_subprocess_start(
		const char *file, const char *args[], size_t args_size,
		const char *envvars[], const char *envvals[], size_t env_size) {
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

	proc = R_NEW0 (R2RSubprocess);
	if (!proc) {
		goto error;
	}
	proc->ret = -1;

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
		eprintf ("CreateProcess failed: %#x\n", (int)GetLastError ());
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
	if (!ReadFile (proc->which##_read, which##_buf, sizeof (which##_buf) - 1, NULL, &(which##_overlapped))) { \
		if (GetLastError () != ERROR_IO_PENDING) { \
			/* EOF or some other error */ \
			which##_eof = true; \
		} \
	}

	DO_READ (stdout)
	DO_READ (stderr)

	RVector handles;
	r_vector_init (&handles, sizeof (HANDLE), NULL, NULL);
	while (true) {
		r_vector_clear (&handles);
		size_t stdout_index = 0;
		size_t stderr_index = 0;
		size_t proc_index = 0;
		if (!stdout_eof) {
			stdout_index = handles.len;
			r_vector_push (&handles, &stdout_overlapped.hEvent);
		}
		if (!stderr_eof) {
			stderr_index = handles.len;
			r_vector_push (&handles, &stderr_overlapped.hEvent);
		}
		if (!child_dead) {
			proc_index = handles.len;
			r_vector_push (&handles, &proc->proc);
		}
		
		DWORD timeout = INFINITE;
		if (timeout_us_abs != UT64_MAX) {
			ut64 now = r_time_now_mono ();
			if (now >= timeout_us_abs) {
				return false;
			}
			timeout = (DWORD)((timeout_us_abs - now) / R_USEC_PER_MSEC);
		}
		DWORD signaled = WaitForMultipleObjects (handles.len, handles.a, FALSE, timeout);
		if (!stdout_eof && signaled == stdout_index) {
			DWORD r;
			BOOL res = GetOverlappedResult (proc->stdout_read, &stdout_overlapped, &r, TRUE);
			if (!res) {
				stdout_eof = true;
				continue;
			}
			stdout_buf[r] = '\0';
			r_str_remove_char (stdout_buf, '\r');
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
			r_str_remove_char (stderr_buf, '\r');
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
	r_vector_clear (&handles);
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
	r_th_lock_enter (subprocs_mutex);
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
		r_sys_exit (-1, true);
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
	r_th_lock_leave (subprocs_mutex);
	return NULL;
}

R_API bool r2r_subprocess_wait(R2RSubprocess *proc, ut64 timeout_ms) {
	ut64 timeout_abs;
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

#if __WINDOWS__
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
						for (; c = *cmds, c && c != '}'; *cmds++) {
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

static R2RProcessOutput *run_r2_test(R2RRunConfig *config, ut64 timeout_ms, const char *cmds, RList *files, RList *extra_args, bool load_plugins, R2RCmdRunner runner, void *user) {
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
#if __WINDOWS__
	char *wcmds = convert_win_cmds (cmds);
	r_pvector_push (&args, wcmds);
#else
	r_pvector_push (&args, (void *)cmds);
#endif
	r_list_foreach (files, it, file_arg) {
		r_pvector_push (&args, file_arg);
	}

	const char *envvars[] = {
#if __WINDOWS__
		"ANSICON",
#endif
		"R2_NOPLUGINS"
	};
	const char *envvals[] = {
#if __WINDOWS__
		"1",
#endif
		"1"
	};
#if __WINDOWS__
	size_t env_size = load_plugins ? 1 : 2;
#else
	size_t env_size = load_plugins ? 0 : 1;
#endif
	R2RProcessOutput *out = runner (config->r2_cmd, args.v.a, r_pvector_len (&args), envvars, envvals, env_size, timeout_ms, user);
	r_pvector_clear (&args);
#if __WINDOWS__
	free (wcmds);
#endif
	return out;
}

R_API R2RProcessOutput *r2r_run_cmd_test(R2RRunConfig *config, R2RCmdTest *test, R2RCmdRunner runner, void *user) {
	RList *extra_args = test->args.value ? r_str_split_duplist (test->args.value, " ", true) : NULL;
	RList *files = r_str_split_duplist (test->file.value, "\n", true);
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
	ut64 timeout_ms = test->timeout.set? test->timeout.value * 1000: config->timeout_ms;
	R2RProcessOutput *out = run_r2_test (config, timeout_ms, test->cmds.value, files, extra_args, test->load_plugins, runner, user);
	r_list_free (extra_args);
	r_list_free (files);
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
	const char *args[] = {"."};
	const char *invalid_json = "this is not json lol";
	R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		r2r_subprocess_stdin_write (proc, (const ut8 *)invalid_json, strlen (invalid_json));
		r2r_subprocess_wait (proc, UT64_MAX);
	}
	bool invalid_detected = proc && proc->ret != 0;
	r2r_subprocess_free (proc);

	const char *valid_json = "{\"this is\":\"valid json\",\"lol\":true}";
	proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
	if (proc) {
		r2r_subprocess_stdin_write (proc, (const ut8 *)valid_json, strlen (valid_json));
		r2r_subprocess_wait (proc, UT64_MAX);
	}
	bool valid_detected = proc && proc->ret == 0;
	r2r_subprocess_free (proc);

	return invalid_detected && valid_detected;
}

R_API R2RProcessOutput *r2r_run_json_test(R2RRunConfig *config, R2RJsonTest *test, R2RCmdRunner runner, void *user) {
	RList *files = r_list_new ();
	r_list_push (files, (void *)config->json_test_file);
	R2RProcessOutput *ret = run_r2_test (config, config->timeout_ms, test->cmd, files, NULL, test->load_plugins, runner, user);
	r_list_free (files);
	return ret;
}

R_API bool r2r_check_json_test(R2RProcessOutput *out, R2RJsonTest *test) {
	if (!out || out->ret != 0 || !out->out || !out->err || out->timeout) {
		return false;
	}
	const char *args[] = {"."};
	R2RSubprocess *proc = r2r_subprocess_start (JQ_CMD, args, 1, NULL, NULL, 0);
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
		char *disasm = r_strbuf_drain_nofree (&proc->out);
		r_str_trim (disasm);
		out->disasm = disasm;
ship:
		free (hex);
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
	if (!out) {
		return false;
	}
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

R_API R2RProcessOutput *r2r_run_fuzz_test(R2RRunConfig *config, R2RFuzzTest *test, R2RCmdRunner runner, void *user) {
	const char *cmd = "aaa";
	RList *files = r_list_new ();
	r_list_push (files, test->file);
#if ASAN
	if (r_str_endswith (test->file, "/swift_read")) {
		cmd = "?F";
	}
#endif
	R2RProcessOutput *ret = run_r2_test (config, config->timeout_ms, cmd, files, NULL, false, runner, user);
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
		return r_str_newf ("<fuzz> %s", test->fuzz_test->file);
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
	case R2R_TEST_TYPE_FUZZ:
		return false;
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
	ut64 start_time = r_time_now_mono ();
	switch (test->type) {
	case R2R_TEST_TYPE_CMD: {
		R2RCmdTest *cmd_test = test->cmd_test;
		R2RProcessOutput *out = r2r_run_cmd_test (config, cmd_test, subprocess_runner, NULL);
		success = r2r_check_cmd_test (out, cmd_test);
		ret->proc_out = out;
		ret->timeout = out && out->timeout;
		ret->run_failed = !out;
		break;
	}
	case R2R_TEST_TYPE_ASM: {
		R2RAsmTest *asm_test = test->asm_test;
		R2RAsmTestOutput *out = r2r_run_asm_test (config, asm_test);
		success = r2r_check_asm_test (out, asm_test);
		ret->asm_out = out;
		ret->timeout = out->as_timeout || out->disas_timeout;
		ret->run_failed = !out;
		break;
	}
	case R2R_TEST_TYPE_JSON: {
		R2RJsonTest *json_test = test->json_test;
		R2RProcessOutput *out = r2r_run_json_test (config, json_test, subprocess_runner, NULL);
		success = r2r_check_json_test (out, json_test);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
		break;
	}
	case R2R_TEST_TYPE_FUZZ: {
		R2RFuzzTest *fuzz_test = test->fuzz_test;
		R2RProcessOutput *out = r2r_run_fuzz_test (config, fuzz_test, subprocess_runner, NULL);
		success = r2r_check_fuzz_test (out);
		ret->proc_out = out;
		ret->timeout = out->timeout;
		ret->run_failed = !out;
	}
	}
	ret->time_elapsed = r_time_now_mono () - start_time;
	bool broken = r2r_test_broken (test);
#if ASAN
# if !R2_ASSERT_STDOUT
# error R2_ASSERT_STDOUT undefined or 0
# endif
	R2RProcessOutput *out = ret->proc_out;
	if (!success && test->type == R2R_TEST_TYPE_CMD && strstr (test->path, "/dbg")
	    && (!out->out ||
	        (!strstr (out->out, "WARNING:") && !strstr (out->out, "ERROR:") && !strstr (out->out, "FATAL:")))
	    && (!out->err ||
	        (!strstr (out->err, "Sanitizer") && !strstr (out->err, "runtime error:")))) {
		broken = true;
	}
#endif
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
