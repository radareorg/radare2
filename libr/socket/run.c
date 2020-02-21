/* radare - LGPL - Copyright 2014-2017 - pancake */

/* this helper api is here because it depends on r_util and r_socket */
/* we should find a better place for it. r_io? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <r_socket.h>
#include <r_util.h>
#include <r_lib.h>
#include <sys/stat.h>
#include <sys/types.h>

#if __APPLE__ && LIBC_HAVE_FORK
#if !__POWERPC__
#include <spawn.h>
#endif
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
#endif

#if __UNIX__
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <grp.h>
#include <errno.h>
#if defined(__sun)
#include <sys/filio.h>
#endif
#if __linux__ && !__ANDROID__
#include <sys/personality.h>
#include <pty.h>
#include <utmp.h>
#endif
#if defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#include <libutil.h>
#endif
#endif
#ifdef _MSC_VER
#include <direct.h>   // to compile chdir in msvc windows
#include <process.h>  // to compile execv in msvc windows
#endif

#define HAVE_PTY __UNIX__ && !__ANDROID__ && LIBC_HAVE_FORK && !__sun

#if EMSCRIPTEN
#undef HAVE_PTY
#define HAVE_PTY 0
#endif

R_API RRunProfile *r_run_new(const char *str) {
	RRunProfile *p = R_NEW0 (RRunProfile);
	if (p) {
		r_run_reset (p);
		r_run_parsefile (p, str);
	}
	return p;
}

R_API void r_run_reset(RRunProfile *p) {
	memset (p, 0, sizeof (RRunProfile));
	p->_aslr = -1;
}

R_API bool r_run_parse(RRunProfile *pf, const char *profile) {
	if (!pf || !profile) {
		return false;
	}
	char *p, *o, *str = strdup (profile);
	if (!str) {
		return false;
	}
	r_str_replace_char (str, '\r',0);
	for (p = str; (o = strchr (p, '\n')); p = o) {
		*o++ = 0;
		r_run_parseline (pf, p);
	}
	free (str);
	return true;
}

R_API void r_run_free (RRunProfile *r) {
	free (r->_system);
	free (r->_program);
	free (r->_runlib);
	free (r->_runlib_fcn);
	free (r->_stdio);
	free (r->_stdin);
	free (r->_stdout);
	free (r->_stderr);
	free (r->_chgdir);
	free (r->_chroot);
	free (r->_libpath);
	free (r->_preload);
	free (r);
}

#if __UNIX__
static void set_limit(int n, int a, ut64 b) {
	if (n) {
		struct rlimit cl = {b, b};
		setrlimit (RLIMIT_CORE, &cl);
	} else {
		struct rlimit cl = {0, 0};
		setrlimit (a, &cl);
	}
}
#endif

static char *getstr(const char *src) {
	int len;
	char *ret = NULL;

	switch (*src) {
	case '\'':
		ret = strdup (src+1);
		if (ret) {
			len = strlen (ret);
			if (len > 0) {
				len--;
				if (ret[len] == '\'') {
					ret[len] = 0;
					return ret;
				}
				eprintf ("Missing \"\n");
			}
			free (ret);
		}
		return NULL;
	case '"':
		ret = strdup (src + 1);
		if (ret) {
			len = strlen (ret);
			if (len > 0) {
				len--;
				if (ret[len] == '"') {
					ret[len] = 0;
					r_str_unescape (ret);
					return ret;
				}
				eprintf ("Missing \"\n");
			}
			free (ret);
		}
		return NULL;
	case '@':
		{
			char *pat = strchr (src + 1, '@');
			if (pat) {
				int i, len, rep;
				*pat++ = 0;
				rep = atoi (src + 1);
				len = strlen (pat);
				if (rep > 0) {
					char *buf = malloc (rep);
					if (buf) {
						for (i = 0; i < rep; i++) {
							buf[i] = pat[i%len];
						}
					}
					return buf;
				}
			}
			// slurp file
			return r_file_slurp (src + 1, NULL);
		}
	case '`':
		{
		char *msg = strdup (src + 1);
		int msg_len = strlen (msg);
		if (msg_len > 0) {
			msg [msg_len - 1] = 0;
			char *ret = r_sys_cmd_str (msg, NULL, NULL);
			r_str_trim_tail (ret);
			free (msg);
			return ret;
		}
		free (msg);
		return strdup ("");
		}
	case '!':
		{
		char *a = r_sys_cmd_str (src + 1, NULL, NULL);
		r_str_trim_tail (a);
		return a;
		}
	case ':':
		if (src[1] == '!') {
			ret = r_sys_cmd_str (src + 1, NULL, NULL);
			r_str_trim_tail (ret); // why no head :?
		} else {
			ret = strdup (src);
		}
		len = r_hex_str2bin (src + 1, (ut8*)ret);
		if (len > 0) {
			ret[len] = 0;
			return ret;
		}
		eprintf ("Invalid hexpair string\n");
		free (ret);
		return NULL;
#if 0
	// what is this for??
	case '%':
		return (char *) strtoul (src + 1, NULL, 0);
#endif
	}
	r_str_unescape ((ret = strdup (src)));
	return ret;
}

static int parseBool(const char *e) {
	return (strcmp (e, "yes")?
		(strcmp (e, "on")?
		(strcmp (e, "true")?
		(strcmp (e, "1")?
		0: 1): 1): 1): 1);
}

// TODO: move into r_util? r_run_... ? with the rest of funcs?
static void setASLR(RRunProfile *r, int enabled) {
#if __linux__
	r_sys_aslr (enabled);
#if HAVE_DECL_ADDR_NO_RANDOMIZE && !__ANDROID__
	if (personality (ADDR_NO_RANDOMIZE) == -1) {
#endif
		r_sys_aslr (0);
#if HAVE_DECL_ADDR_NO_RANDOMIZE && !__ANDROID__
	}
#endif
#elif __APPLE__
	// TOO OLD setenv ("DYLD_NO_PIE", "1", 1);
	// disable this because its
	const char *argv0 = r->_system ? r->_system
		: r->_program ? r->_program
		: r->_args[0] ? r->_args[0]
		: "/path/to/exec";
	eprintf ("To disable aslr patch mach0.hdr.flags with:\n"
		"r2 -qwnc 'wx 000000 @ 0x18' %s\n", argv0);
	// f MH_PIE=0x00200000; wB-MH_PIE @ 24\n");
	// for osxver>=10.7
	// "unset the MH_PIE bit in an already linked executable" with --no-pie flag of the script
	// the right way is to disable the aslr bit in the spawn call
#elif __FreeBSD__
	r_sys_aslr (enabled);
#else
	// not supported for this platform
#endif
}

#if HAVE_PTY
static void restore_saved_fd(int saved, bool restore, int fd) {
	if (saved == -1) {
		return;
	}
	if (restore) {
		dup2 (saved, fd);
	}
	close (saved);
}
#endif

static int handle_redirection_proc(const char *cmd, bool in, bool out, bool err) {
#if HAVE_PTY
	// use PTY to redirect I/O because pipes can be problematic in
	// case of interactive programs.
	int saved_stdin = dup (STDIN_FILENO);
	if (saved_stdin == -1) {
		return -1;
	}
	int saved_stdout = dup (STDOUT_FILENO);
	if (saved_stdout== -1) {
		close (saved_stdin);
		return -1;
	}
	int fdm, pid = forkpty (&fdm, NULL, NULL, NULL);
	if (pid == -1) {
		close (saved_stdin);
		close (saved_stdout);
		return -1;
	}
	const char *tn = ttyname (fdm);
	if (!tn) {
		close (saved_stdin);
		close (saved_stdout);
		return -1;
	}
	int fds = open (tn, O_RDWR);
	if (fds == -1) {
		close (saved_stdin);
		close (saved_stdout);
		return -1;
	}
	if (pid == 0) {
		close (fdm);
		// child process
		if (in) {
			dup2 (fds, STDIN_FILENO);
		}
		if (out) {
			dup2 (fds, STDOUT_FILENO);
		}
		// child - program to run

		// necessary because otherwise you can read the same thing you
		// wrote on fdm.
		struct termios t;
		tcgetattr (fds, &t);
		cfmakeraw (&t);
		tcsetattr (fds, TCSANOW, &t);

		int code = r_sys_cmd (cmd);
		restore_saved_fd (saved_stdin, in, STDIN_FILENO);
		restore_saved_fd (saved_stdout, out, STDOUT_FILENO);
		exit (code);
	} else {
		close (fds);
		if (in) {
			dup2 (fdm, STDIN_FILENO);
		}
		if (out) {
			dup2 (fdm, STDOUT_FILENO);
		}
		// parent process
		int status;
		waitpid (pid, &status, 0);
	}

	// parent
	close (saved_stdin);
	close (saved_stdout);
	return 0;
#else
#ifdef _MSC_VER
#pragma message ("TODO: handle_redirection_proc: Not implemented for this platform")
#else
#warning handle_redirection_proc : unimplemented for this platform
#endif
	return -1;
#endif
}

static int handle_redirection(const char *cmd, bool in, bool out, bool err) {
	if (!cmd || cmd[0] == '\0') {
		return 0;
	}

#if __APPLE__ && !__POWERPC__
	//XXX handle this in other layer since things changes a little bit
	//this seems like a really good place to refactor stuff
	return 0;
#endif
	if (cmd[0] == '"') {
#if __UNIX__
		if (in) {
			int pipes[2];
			if (pipe (pipes) != -1) {
				size_t cmdl = strlen (cmd)-2;
				if (write (pipes[1], cmd + 1, cmdl) != cmdl) {
					eprintf ("[ERROR] rarun2: Cannot write to the pipe\n");
					close (0);
					return 1;
				}
				if (write (pipes[1], "\n", 1) != 1) {
					eprintf ("[ERROR] rarun2: Cannot write to the pipe\n");
					close (0);
					return 1;
				}
				close (0);
				dup2 (pipes[0], 0);
			} else {
				eprintf ("[ERROR] rarun2: Cannot create pipe\n");
			}
		}
#else
#ifdef _MSC_VER
#pragma message ("string redirection handle not yet done")
#else
#warning quoted string redirection handle not yet done
#endif
#endif
		return 0;
	} else if (cmd[0] == '!') {
		// redirection to a process
		return handle_redirection_proc (cmd + 1, in, out, err);
	} else {
		// redirection to a file
		int f, flag = 0, mode = 0;
		flag |= in ? O_RDONLY : 0;
		flag |= out ? O_WRONLY | O_CREAT : 0;
		flag |= err ? O_WRONLY | O_CREAT : 0;
#ifdef __WINDOWS__
		mode = _S_IREAD | _S_IWRITE;
#else
		mode = S_IRUSR | S_IWUSR;
#endif
		f = open (cmd, flag, mode);
		if (f < 0) {
			eprintf ("[ERROR] rarun2: Cannot open: %s\n", cmd);
			return 1;
		}
#define DUP(x) { close(x); dup2(f,x); }
		if (in) {
			DUP(0);
		}
		if (out) {
			DUP(1);
		}
		if (err) {
			DUP(2);
		}
		close (f);
		return 0;
	}
}

R_API int r_run_parsefile(RRunProfile *p, const char *b) {
	char *s = r_file_slurp (b, NULL);
	if (s) {
		int ret = r_run_parse (p, s);
		free (s);
		return ret;
	}
	return 0;
}

R_API bool r_run_parseline(RRunProfile *p, char *b) {
	int must_free = false;
	char *e = strchr (b, '=');
	if (!e || *b == '#') {
		return 0;
	}
	*e++ = 0;
	if (*e=='$') {
		must_free = true;
		e = r_sys_getenv (e);
	}
	if (!e) {
		return 0;
	}
	if (!strcmp (b, "program")) {
		p->_args[0] = p->_program = strdup (e);
	} else if (!strcmp (b, "system")) {
		p->_system = strdup (e);
	} else if (!strcmp (b, "runlib")) {
		p->_runlib = strdup (e);
	} else if (!strcmp (b, "runlib.fcn")) {
		p->_runlib_fcn = strdup (e);
	} else if (!strcmp (b, "aslr")) {
		p->_aslr = parseBool (e);
	} else if (!strcmp (b, "pid")) {
		p->_pid = atoi (e);
	} else if (!strcmp (b, "pidfile")) {
		p->_pidfile = strdup (e);
	} else if (!strcmp (b, "connect")) {
		p->_connect = strdup (e);
	} else if (!strcmp (b, "listen")) {
		p->_listen = strdup (e);
	} else if (!strcmp (b, "pty")) {
		p->_pty = parseBool (e);
	} else if (!strcmp (b, "stdio")) {
		if (e[0] == '!') {
			p->_stdio = strdup (e);
		} else {
			p->_stdout = strdup (e);
			p->_stderr = strdup (e);
			p->_stdin = strdup (e);
		}
	} else if (!strcmp (b, "stdout")) {
		p->_stdout = strdup (e);
	} else if (!strcmp (b, "stdin")) {
		p->_stdin = strdup (e);
	} else if (!strcmp (b, "stderr")) {
		p->_stderr = strdup (e);
	} else if (!strcmp (b, "input")) {
		p->_input = strdup (e);
	} else if (!strcmp (b, "chdir")) {
		p->_chgdir = strdup (e);
	} else if (!strcmp (b, "core")) {
		p->_docore = parseBool (e);
	} else if (!strcmp (b, "fork")) {
		p->_dofork = parseBool (e);
	} else if (!strcmp (b, "sleep")) {
		p->_r2sleep = atoi (e);
	} else if (!strcmp (b, "maxstack")) {
		p->_maxstack = atoi (e);
	} else if (!strcmp (b, "maxproc")) {
		p->_maxproc = atoi (e);
	} else if (!strcmp (b, "maxfd")) {
		p->_maxfd = atoi (e);
	} else if (!strcmp (b, "bits")) {
		p->_bits = atoi (e);
	} else if (!strcmp (b, "chroot")) {
		p->_chroot = strdup (e);
	} else if (!strcmp (b, "libpath")) {
		p->_libpath = strdup (e);
	} else if (!strcmp (b, "preload")) {
		p->_preload = strdup (e);
	} else if (!strcmp (b, "r2preload")) {
		p->_r2preload = parseBool (e);
	} else if (!strcmp (b, "r2preweb")) {
		r_sys_setenv ("RARUN2_WEB", "yes");
	} else if (!strcmp (b, "setuid")) {
		p->_setuid = strdup (e);
	} else if (!strcmp (b, "seteuid")) {
		p->_seteuid = strdup (e);
	} else if (!strcmp (b, "setgid")) {
		p->_setgid = strdup (e);
	} else if (!strcmp (b, "setegid")) {
		p->_setegid = strdup (e);
	} else if (!strcmp (b, "nice")) {
		p->_nice = atoi (e);
	} else if (!strcmp (b, "timeout")) {
		p->_timeout = atoi (e);
	} else if (!strcmp (b, "timeoutsig")) {
		p->_timeout_sig = r_signal_from_string (e);
	} else if (!memcmp (b, "arg", 3)) {
		int n = atoi (b + 3);
		if (n >= 0 && n < R_RUN_PROFILE_NARGS) {
			p->_args[n] = getstr (e);
			p->_argc++;
		} else {
			eprintf ("Out of bounds args index: %d\n", n);
		}
	} else if (!strcmp (b, "envfile")) {
		char *p, buf[1024];
		size_t len;
		FILE *fd = r_sandbox_fopen (e, "r");
		if (!fd) {
			eprintf ("Cannot open '%s'\n", e);
			if (must_free == true) {
				free (e);
			}
			return false;
		}
		for (;;) {
			if (!fgets (buf, sizeof (buf) - 1, fd)) {
				break;
			}
			if (feof (fd)) {
				break;
			}
			p = strchr (buf, '=');
			if (p) {
				*p++ = 0;
				len = strlen (p);
				if (len > 0 && p[len - 1] == '\n') {
					p[len - 1] = 0;
				}
				if (len > 1 && p[len - 2] == '\r') {
					p[len - 2] = 0;
				}
				r_sys_setenv (buf, p);
			}
		}
		fclose (fd);
	} else if (!strcmp (b, "unsetenv")) {
		r_sys_setenv (e, NULL);
	} else if (!strcmp (b, "setenv")) {
		char *V, *v = strchr (e, '=');
		if (v) {
			*v++ = 0;
			V = getstr (v);
			r_sys_setenv (e, V);
			free (V);
		}
	} else if (!strcmp(b, "clearenv")) {
		r_sys_clearenv ();
	}
	if (must_free == true) {
		free (e);
	}
	return true;
}

R_API const char *r_run_help() {
	return
	"program=/bin/ls\n"
	"arg1=/bin\n"
	"# arg2=hello\n"
	"# arg3=\"hello\\nworld\"\n"
	"# arg4=:048490184058104849\n"
	"# arg5=:!ragg2 -p n50 -d 10:0x8048123\n"
	"# arg6=@arg.txt\n"
	"# arg7=@300@ABCD # 300 chars filled with ABCD pattern\n"
	"# system=r2 -\n"
	"# aslr=no\n"
	"setenv=FOO=BAR\n"
	"# unsetenv=FOO\n"
	"# clearenv=true\n"
	"# envfile=environ.txt\n"
	"timeout=3\n"
	"# timeoutsig=SIGTERM # or 15\n"
	"# connect=localhost:8080\n"
	"# listen=8080\n"
	"# pty=false\n"
	"# fork=true\n"
	"# bits=32\n"
	"# pid=0\n"
	"# pidfile=/tmp/foo.pid\n"
	"# #sleep=0\n"
	"# #maxfd=0\n"
	"# #execve=false\n"
	"# #maxproc=0\n"
	"# #maxstack=0\n"
	"# #core=false\n"
	"# #stdio=blah.txt\n"
	"# #stderr=foo.txt\n"
	"# stdout=foo.txt\n"
	"# stdin=input.txt # or !program to redirect input from another program\n"
	"# input=input.txt\n"
	"# chdir=/\n"
	"# chroot=/mnt/chroot\n"
	"# libpath=$PWD:/tmp/lib\n"
	"# r2preload=yes\n"
	"# preload=/lib/libfoo.so\n"
	"# setuid=2000\n"
	"# seteuid=2000\n"
	"# setgid=2001\n"
	"# setegid=2001\n"
	"# nice=5\n";
}

#if HAVE_PTY
static int fd_forward(int in_fd, int out_fd, char **buff) {
	int size = 0;

	if (ioctl (in_fd, FIONREAD, &size) == -1) {
		perror ("ioctl");
		return -1;
	}
	if (!size) { // child process exited or socket is closed
		return -1;
	}

	char *new_buff = realloc (*buff, size);
	if (!new_buff) {
		eprintf ("Failed to allocate buffer for redirection");
		return -1;
	}
	*buff = new_buff;
	if (read (in_fd, *buff, size) != size) {
		perror ("read");
		return -1;
	}
	if (write (out_fd, *buff, size) != size) {
		perror ("write");
		return -1;
	}

	return 0;
}
#endif

static int redirect_socket_to_stdio(RSocket *sock) {
	close (0);
	close (1);
	close (2);

	dup2 (sock->fd, 0);
	dup2 (sock->fd, 1);
	dup2 (sock->fd, 2);

	return 0;
}

static int redirect_socket_to_pty(RSocket *sock) {
#if HAVE_PTY
	// directly duplicating the fds using dup2() creates problems
	// in case of interactive applications
	int fdm, fds;

	if (openpty (&fdm, &fds, NULL, NULL, NULL) == -1) {
		perror ("opening pty");
		return -1;
	}

	pid_t child_pid = r_sys_fork ();

	if (child_pid == -1) {
		eprintf ("cannot fork\n");
		close(fdm);
		close(fds);
		return -1;
	}

	if (child_pid == 0) {
		// child process
		close (fds);

		char *buff = NULL;
		int sockfd = sock->fd;
		int max_fd = fdm > sockfd ? fdm : sockfd;

		while (true) {
			fd_set readfds;
			FD_ZERO (&readfds);
			FD_SET (fdm, &readfds);
			FD_SET (sockfd, &readfds);

			if (select (max_fd + 1, &readfds, NULL, NULL, NULL) == -1) {
				perror ("select error");
				break;
			}

			if (FD_ISSET (fdm, &readfds)) {
				if (fd_forward (fdm, sockfd, &buff) != 0) {
					break;
				}
			}

			if (FD_ISSET (sockfd, &readfds)) {
				if (fd_forward (sockfd, fdm, &buff) != 0) {
					break;
				}
			}
		}

		free (buff);
		close (fdm);
		r_socket_free (sock);
		exit (0);
	}

	// parent
	r_socket_close_fd (sock);
	login_tty (fds);
	close (fdm);

	// disable the echo on slave stdin
	struct termios t;
	tcgetattr (0, &t);
	cfmakeraw (&t);
	tcsetattr (0, TCSANOW, &t);

	return 0;
#else
	// Fallback to socket to I/O redirection
	return redirect_socket_to_stdio (sock);
#endif
}

R_API int r_run_config_env(RRunProfile *p) {
	int ret;

	if (!p->_program && !p->_system && !p->_runlib) {
		printf ("No program, system or runlib rule defined\n");
		return 1;
	}
	// when IO is redirected to a process, handle them together
	if (handle_redirection (p->_stdio, true, true, false) != 0) {
		return 1;
	}
	if (handle_redirection (p->_stdin, true, false, false) != 0) {
		return 1;
	}
	if (handle_redirection (p->_stdout, false, true, false) != 0) {
		return 1;
	}
	if (handle_redirection (p->_stderr, false, false, true) != 0) {
		return 1;
	}
	if (p->_aslr != -1) {
		setASLR (p, p->_aslr);
	}
#if __UNIX__
	set_limit (p->_docore, RLIMIT_CORE, RLIM_INFINITY);
	if (p->_maxfd) {
		set_limit (p->_maxfd, RLIMIT_NOFILE, p->_maxfd);
	}
#ifdef RLIMIT_NPROC
	if (p->_maxproc) {
		set_limit (p->_maxproc, RLIMIT_NPROC, p->_maxproc);
	}
#endif
	if (p->_maxstack) {
		set_limit (p->_maxstack, RLIMIT_STACK, p->_maxstack);
	}
#else
	if (p->_docore || p->_maxfd || p->_maxproc || p->_maxstack)
		eprintf ("Warning: setrlimits not supported for this platform\n");
#endif
	if (p->_connect) {
		char *q = strchr (p->_connect, ':');
		if (q) {
			RSocket *fd = r_socket_new (0);
			*q = 0;
			if (!r_socket_connect_tcp (fd, p->_connect, q+1, 30)) {
				eprintf ("Cannot connect\n");
				return 1;
			}
			if (p->_pty) {
				if (redirect_socket_to_pty (fd) != 0) {
					eprintf ("socket redirection failed\n");
					r_socket_free (fd);
					return 1;
				}
			} else {
				redirect_socket_to_stdio (fd);
			}
		} else {
			eprintf ("Invalid format for connect. missing ':'\n");
			return 1;
		}
	}
	if (p->_listen) {
		RSocket *child, *fd = r_socket_new (0);
		bool is_child = false;
		if (!r_socket_listen (fd, p->_listen, NULL)) {
			eprintf ("rarun2: cannot listen\n");
			r_socket_free (fd);
			return 1;
		}
		while (true) {
			child = r_socket_accept (fd);
			if (child) {
				is_child = true;

				if (p->_dofork && !p->_dodebug) {
#ifdef _MSC_VER
					int child_pid = r_sys_fork ();
#else
					pid_t child_pid = r_sys_fork ();
#endif
					if (child_pid == -1) {
						eprintf("rarun2: cannot fork\n");
						r_socket_free (child);
						r_socket_free (fd);
						return 1;
					} else if (child_pid != 0){
						// parent code
						is_child = false;
					}
				}

				if (is_child) {
					r_socket_close_fd (fd);
					eprintf ("connected\n");
					if (p->_pty) {
						if (redirect_socket_to_pty (child) != 0) {
							eprintf ("socket redirection failed\n");
							r_socket_free (child);
							r_socket_free (fd);
							return 1;
						}
					} else {
						redirect_socket_to_stdio (child);
					}
					break;
				} else {
					r_socket_close_fd (child);
				}
			}
		}
		if (!is_child) {
			r_socket_free (child);
		}
		r_socket_free (fd);
	}
	if (p->_r2sleep != 0) {
		r_sys_sleep (p->_r2sleep);
	}
#if __UNIX__
	if (p->_chroot) {
		if (chdir (p->_chroot) == -1) {
			eprintf ("Cannot chdir to chroot in %s\n", p->_chroot);
			return 1;
		} else {
			if (chroot (".") == -1) {
				eprintf ("Cannot chroot to %s\n", p->_chroot);
				return 1;
			} else {
				// Silenting pedantic meson flags...
				if (chdir ("/") == -1) {
					eprintf ("Cannot chdir to /\n");
					return 1;
				}
				if (p->_chgdir) {
					if (chdir (p->_chgdir) == -1) {
						eprintf ("Cannot chdir after chroot to %s\n", p->_chgdir);
						return 1;
					}
				}
			}
		}
	} else if (p->_chgdir) {
		if (chdir (p->_chgdir) == -1) {
			eprintf ("Cannot chdir after chroot to %s\n", p->_chgdir);
			return 1;
		}
	}
#else
	if (p->_chgdir) {
		ret = chdir (p->_chgdir);
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_chroot) {
		ret = chdir (p->_chroot);
		if (ret < 0) {
			return 1;
		}
	}
#endif
#if __UNIX__
	if (p->_setuid) {
		ret = setgroups (0, NULL);
		if (ret < 0) {
			return 1;
		}
		ret = setuid (atoi (p->_setuid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_seteuid) {
		ret = seteuid (atoi (p->_seteuid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_setgid) {
		ret = setgid (atoi (p->_setgid));
		if (ret < 0) {
			return 1;
		}
	}
	if (p->_input) {
		char *inp;
		int f2[2];
		if (pipe (f2) != -1) {
			close (0);
			dup2 (f2[0], 0);
		} else {
			eprintf ("[ERROR] rarun2: Cannot create pipe\n");
			return 1;
		}
		inp = getstr (p->_input);
		if (inp) {
			size_t inpl = strlen (inp);
			if  (write (f2[1], inp, inpl) != inpl) {
				eprintf ("[ERROR] rarun2: Cannot write to the pipe\n");
			}
			close (f2[1]);
			free (inp);
		} else {
			eprintf ("Invalid input\n");
		}
	}
#endif
	if (p->_r2preload) {
		if (p->_preload) {
			eprintf ("WARNING: Only one library can be opened at a time\n");
		}
#ifdef __WINDOWS__
		p->_preload = r_str_r2_prefix (R_JOIN_2_PATHS (R2_LIBDIR, "libr2."R_LIB_EXT));
#else
		p->_preload = strdup (R2_LIBDIR"/libr2."R_LIB_EXT);
#endif
	}
	if (p->_libpath) {
#if __WINDOWS__
		eprintf ("rarun2: libpath unsupported for this platform\n");
#elif __HAIKU__
		r_sys_setenv ("LIBRARY_PATH", p->_libpath);
#elif __APPLE__
		r_sys_setenv ("DYLD_LIBRARY_PATH", p->_libpath);
#else
		r_sys_setenv ("LD_LIBRARY_PATH", p->_libpath);
#endif
	}
	if (p->_preload) {
#if __APPLE__
		// 10.6
#ifndef __MAC_10_7
		r_sys_setenv ("DYLD_PRELOAD", p->_preload);
#endif
		r_sys_setenv ("DYLD_INSERT_LIBRARIES", p->_preload);
		// 10.8
		r_sys_setenv ("DYLD_FORCE_FLAT_NAMESPACE", "1");
#else
		r_sys_setenv ("LD_PRELOAD", p->_preload);
#endif
	}
	if (p->_timeout) {
#if __UNIX__
		int mypid = getpid ();
		if (!r_sys_fork ()) {
			int use_signal = p->_timeout_sig;
			if (use_signal < 1) {
				use_signal = SIGKILL;
			}
			sleep (p->_timeout);
			if (!kill (mypid, 0)) {
				eprintf ("\nrarun2: Interrupted by timeout\n");
			}
			kill (mypid, use_signal);
			exit (0);
		}
#else
		eprintf ("timeout not supported for this platform\n");
#endif
	}
	return 0;
}

R_API int r_run_start(RRunProfile *p) {
#if LIBC_HAVE_FORK
	if (p->_execve) {
		exit (execv (p->_program, (char* const*)p->_args));
	}
#endif
#if __APPLE__ && !__POWERPC__ && LIBC_HAVE_FORK
	posix_spawnattr_t attr = {0};
	pid_t pid = -1;
	int ret;
	posix_spawnattr_init (&attr);
	if (p->_args[0]) {
		char **envp = r_sys_get_environ();
		ut32 spflags = 0; //POSIX_SPAWN_START_SUSPENDED;
		spflags |= POSIX_SPAWN_SETEXEC;
		if (p->_aslr == 0) {
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
			spflags |= _POSIX_SPAWN_DISABLE_ASLR;
		}
		(void)posix_spawnattr_setflags (&attr, spflags);
		if (p->_bits) {
			size_t copied = 1;
			cpu_type_t cpu;
#if __i386__ || __x86_64__
			cpu = CPU_TYPE_I386;
			if (p->_bits == 64) {
				cpu |= CPU_ARCH_ABI64;
			}
#else
			cpu = CPU_TYPE_ANY;
#endif
			posix_spawnattr_setbinpref_np (
					&attr, 1, &cpu, &copied);
		}
		ret = posix_spawnp (&pid, p->_args[0],
			NULL, &attr, p->_args, envp);
		switch (ret) {
		case 0:
			break;
		case 22:
			eprintf ("posix_spawnp: Invalid argument\n");
			break;
		case 86:
			eprintf ("posix_spawnp: Unsupported architecture\n");
			break;
		default:
			eprintf ("posix_spawnp: unknown error %d\n", ret);
			perror ("posix_spawnp");
			break;
		}
		exit (ret);
	}
#endif
	if (p->_system) {
		if (p->_pid) {
			eprintf ("PID: Cannot determine pid with 'system' directive. Use 'program'.\n");
		}
		exit (r_sys_cmd (p->_system));
	}
	if (p->_program) {
		if (!r_file_exists (p->_program)) {
			char *progpath = r_file_path (p->_program);
			if (progpath && *progpath) {
				free (p->_program);
				p->_program = progpath;
			} else {
				free (progpath);
				eprintf ("rarun2: %s: file not found\n", p->_program);
				return 1;
			}
		}
#if __UNIX__
		// XXX HACK close all non-tty fds
		{ int i;
			for (i = 3; i < 10; i++) {
				close (i);
			}
		}
		// TODO: use posix_spawn
		if (p->_setgid) {
			int ret = setgid (atoi (p->_setgid));
			if (ret < 0) {
				return 1;
			}
		}
		if (p->_pid) {
			eprintf ("PID: %d\n", getpid ());
		}
		if (p->_pidfile) {
			char pidstr[32];
			snprintf (pidstr, sizeof (pidstr), "%d\n", getpid ());
			r_file_dump (p->_pidfile,
				(const ut8*)pidstr,
				strlen (pidstr), 0);
		}
#endif

		if (p->_nice) {
#if __UNIX__ && !defined(__HAIKU__)
			if (nice (p->_nice) == -1) {
				return 1;
			}
#else
			eprintf ("nice not supported for this platform\n");
#endif
		}
// TODO: must be HAVE_EXECVE
#if LIBC_HAVE_FORK
		exit (execv (p->_program, (char* const*)p->_args));
#endif
	}
	if (p->_runlib) {
		if (!p->_runlib_fcn) {
			eprintf ("No function specified. Please set runlib.fcn\n");
			return 1;
		}
		void *addr = r_lib_dl_open (p->_runlib);
		if (!addr) {
			eprintf ("Could not load the library '%s'\n", p->_runlib);
			return 1;
		}
		void (*fcn)(void) = r_lib_dl_sym (addr, p->_runlib_fcn);
		if (!fcn) {
			eprintf ("Could not find the function '%s'\n", p->_runlib_fcn);
			return 1;
		}
		switch (p->_argc) {
		case 0:
			fcn ();
			break;
		case 1:
			r_run_call1 (fcn, p->_args[1]);
			break;
		case 2:
			r_run_call2 (fcn, p->_args[1], p->_args[2]);
			break;
		case 3:
			r_run_call3 (fcn, p->_args[1], p->_args[2], p->_args[3]);
			break;
		case 4:
			r_run_call4 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4]);
			break;
		case 5:
			r_run_call5 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5]);
			break;
		case 6:
			r_run_call6 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6]);
			break;
		case 7:
			r_run_call7 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7]);
			break;
		case 8:
			r_run_call8 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8]);
			break;
		case 9:
			r_run_call9 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8], p->_args[9]);
			break;
		case 10:
			r_run_call10 (fcn, p->_args[1], p->_args[2], p->_args[3], p->_args[4],
				p->_args[5], p->_args[6], p->_args[7], p->_args[8], p->_args[9], p->_args[10]);
			break;
		default:
			eprintf ("Too many arguments.\n");
			return 1;
		}
		r_lib_dl_close (addr);
	}
	return 0;
}
