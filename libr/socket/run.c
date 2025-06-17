/* radare - LGPL - Copyright 2014-2025 - pancake */

/* this helper api is here because it depends on r_util and r_socket */
/* we should find a better place for it. r_io? */
#define R_LOG_ORIGIN "socket.run"

#include <fcntl.h>
#include <r_socket.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_cons.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

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

#if R2__UNIX__
#include <sys/ioctl.h>
#ifndef __wasi__
#include <sys/resource.h>
#include <grp.h>
#endif
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
#define pid_t int
#endif

#if HAVE_PTY
static int(*dyn_openpty)(int *amaster, int *aslave, char *name, struct termios *termp, struct winsize *winp) = NULL;
static int(*dyn_login_tty)(int fd) = NULL;
static id_t(*dyn_forkpty)(int *amaster, char *name, struct termios *termp, struct winsize *winp) = NULL;
static void dyn_init(void) {
	if (!dyn_openpty) {
		dyn_openpty = r_lib_dl_sym (NULL, "openpty");
	}
	if (!dyn_login_tty) {
		dyn_login_tty = r_lib_dl_sym (NULL, "login_tty");
	}
	if (!dyn_forkpty) {
		dyn_forkpty = r_lib_dl_sym (NULL, "forkpty");
	}
#if R2__UNIX__
	// attempt to fall back on libutil if we failed to load anything
	if (!(dyn_openpty && dyn_login_tty && dyn_forkpty)) {
		void *libutil;
		if (!(libutil = r_lib_dl_open ("libutil." R_LIB_EXT))) {
			R_LOG_ERROR ("rarun2: Could not find PTY utils, failed to load libutil" R_LIB_EXT);
			return;
		}
		if (!dyn_openpty) {
			dyn_openpty = r_lib_dl_sym (libutil, "openpty");
		}
		if (!dyn_login_tty) {
			dyn_login_tty = r_lib_dl_sym (libutil, "login_tty");
		}
		if (!dyn_forkpty) {
			dyn_forkpty = r_lib_dl_sym (libutil, "forkpty");
		}
		r_lib_dl_close (libutil);
	}
#endif
}

#endif

R_API RRunProfile *r_run_new(const char * R_NULLABLE str) {
	RRunProfile *p = R_NEW0 (RRunProfile);
	r_run_reset (p); // TODO: rename to r_run_init
	if (str) {
		r_run_parsefile (p, str);
	}
	return p;
}

R_API void r_run_reset(RRunProfile *p) {
	R_RETURN_IF_FAIL (p);
	int i;
	for (i = 0; i < R_RUN_PROFILE_NARGS; i++) {
		R_FREE (p->_args[i]);
	}
	R_FREE (p->_system);
	R_FREE (p->_program);
	R_FREE (p->_runlib);
	R_FREE (p->_runlib_fcn);
	R_FREE (p->_stdio);
	R_FREE (p->_stdin);
	R_FREE (p->_stdout);
	R_FREE (p->_stderr);
	R_FREE (p->_chgdir);
	R_FREE (p->_chroot);
	R_FREE (p->_libpath);
	R_FREE (p->_preload);
	R_FREE (p->_pidfile);
	R_FREE (p->_connect);
	R_FREE (p->_listen);
	R_FREE (p->_input);
	R_FREE (p->_setuid);
	R_FREE (p->_seteuid);
	R_FREE (p->_setgid);
	R_FREE (p->_setegid);
	memset (p, 0, sizeof (RRunProfile));
	p->_aslr = -1;
}

R_API bool r_run_parse(RRunProfile *pf, const char *profile) {
	R_RETURN_VAL_IF_FAIL (pf && profile, false);
	char *p, *o, *str = strdup (profile);
	if (!str) {
		return false;
	}
	r_str_replace_char (str, '\r',0);
	p = str;
	while (p) {
		if ((o = strchr (p, '\n'))) {
			*o++ = 0;
		}
		r_run_parseline (pf, p);
		p = o;
	}
	free (str);
	return true;
}

R_API void r_run_free(RRunProfile *r) {
	int i;
	if (r) {
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
		r_list_free (r->_preload);
		free (r->_pidfile);
		free (r->_connect);
		free (r->_listen);
		free (r->_input);
		free (r->_setuid);
		free (r->_seteuid);
		free (r->_setgid);
		free (r->_setegid);
		for (i = 0; i < R_RUN_PROFILE_NARGS; i++) {
			free (r->_args[i]);
		}
		free (r);
	}
}

#if R2__UNIX__ && !__wasi__ && !defined(__serenity__)
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

static char *getstr(const char *src, size_t * R_NULLABLE out_len) {
	size_t len = 0;
	char *ret = NULL;

	switch (*(src++)) {
	case '\'':
		ret = strdup (src);
		if (ret) {
			len = strlen (ret);
			if (len > 0) {
				len--;
				if (ret[len] == '\'') {
					ret[len] = 0;
					goto beach;
				}
				R_LOG_ERROR ("Unterminated string literal in input: ' expected");
			}
			free (ret);
		}
		return NULL;
	case '"':
		ret = strdup (src);
		if (ret) {
			len = strlen (ret);
			if (len > 0) {
				len--;
				if (ret[len] == '"') {
					ret[len] = 0;
					r_str_unescape (ret);
					goto beach;
				}
				R_LOG_ERROR ("Unterminated string literal in input: \" expected");
			}
			free (ret);
		}
		return NULL;
	case '@':
		{
			char *pat, *endptr;
			if ((pat = strchr (src, '@'))) {
				size_t i, pat_len;
				*pat++ = 0;
				len = strtoul (src, &endptr, 10);
				if (*endptr != 0) {
					R_LOG_ERROR ("Invalid num in @<num>@<pattern> expr");
					return NULL;
				}
				if (errno == EINVAL || errno == ERANGE || len > 64000000) {
					R_LOG_ERROR ("Out-of-bounds num in @<num>@<pattern> expr");
					return NULL;
				}
				pat_len = strlen (pat);
				if (pat_len == 0) {
					R_LOG_ERROR ("Missing pattern in @<num>@<pattern> expr");
					return NULL;
				}
				if (len > 0) {
					ret = malloc (len + 1);
					if (ret) {
						for (i = 0; i < len; i++) {
							ret[i] = pat[i % pat_len];
						}
						ret[len] = 0;
					}
					goto beach;
				}
			}
			// slurp file
			ret = r_file_slurp (src, &len);
			break;
		}
	case '`':
		{
		size_t msg_len = strlen (src);
		if (msg_len == 0) {
			R_LOG_ERROR ("Invalid backtick expression in input");
			return NULL;
		}
		if (src [msg_len - 1] != '`') {
			R_LOG_ERROR ("Unterminated backtick expr in input");
			return NULL;
		}
		char *msg = strdup (src);
		if (!msg) {
			return NULL;
		}
		msg [msg_len - 1] = 0;
		int cmd_len = 0;
		ret = r_sys_cmd_str (msg, NULL, &cmd_len);
		len = (size_t)cmd_len;
		r_str_trim_tail (ret);
		free (msg);
		break;
		}
	case '!':
		{
		ret = r_sys_cmd_str (src, NULL, NULL);
		if (!ret) {
			return NULL;
		}
		r_str_trim_tail (ret);
		len = strlen (ret);
		break;
		}
	case ':':
		{
		char *hex = getstr (src, NULL);
		if (!hex) {
			return NULL;
		}
		int hexlen = r_hex_str2bin (hex, NULL);
		if (hexlen <= 0) {
			R_LOG_ERROR ("Invalid hexpair string");
			free (hex);
			return NULL;
		}
		len = (size_t)hexlen;
		ret = malloc (len + 1);
		if (ret) {
			ret[len] = 0;
			r_hex_str2bin (hex, (ut8*)ret);
		}
		free (hex);
		}
		break;
	default:
		len = r_str_unescape ((ret = strdup (src - 1)));
		break;
	}
beach:
	if (out_len) {
		*out_len = len;
	}
	return ret;
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
	R_LOG_INFO ("To disable aslr patch mach0.hdr.flags with: r2 -qwnc 'wx 000000 @ 0x18' %s", argv0);
	// f MH_PIE=0x00200000; wB-MH_PIE @ 24\n");
	// for osxver>=10.7
	// "unset the MH_PIE bit in an already linked executable" with --no-pie flag of the script
	// the right way is to disable the aslr bit in the spawn call
#elif __FreeBSD__ || __NetBSD__ || __DragonFly__
	r_sys_aslr (enabled);
#else
	// not supported for this platform
#endif
}

#if __APPLE__ && !__POWERPC__
#else
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
	if (!dyn_forkpty) {
		// No forkpty api found, maybe we should fallback to just fork without any pty allocated
		return -1;
	}
	// use PTY to redirect I/O because pipes can be problematic in
	// case of interactive programs.
	int saved_stdin = dup (STDIN_FILENO);
	if (saved_stdin == -1) {
		return -1;
	}
	int saved_stdout = dup (STDOUT_FILENO);
	if (saved_stdout == -1) {
		close (saved_stdin);
		return -1;
	}
	int fdm, pid = dyn_forkpty (&fdm, NULL, NULL, NULL);
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
#endif

static bool handle_redirection(const char *cmd, bool in, bool out, bool err) {
#if __APPLE__ && !__POWERPC__
	//XXX handle this in other layer since things changes a little bit
	//this seems like a really good place to refactor stuff
	return true;
#else
	if (R_STR_ISEMPTY (cmd)) {
		return true;
	}
	if (cmd[0] == '"') {
#ifdef __wasi__
		R_LOG_ERROR ("Cannot create pipe");
#elif R2__UNIX__
		if (in) {
			int pipes[2] = { -1, -1 };
			if (pipe (pipes) != -1) {
				size_t cmdl = strlen (cmd)-2;
				if (write (pipes[1], cmd + 1, cmdl) != cmdl) {
					R_LOG_ERROR ("Cannot write to the pipe");
					close (0);
					return false;
				}
				if (write (pipes[1], "\n", 1) != 1) {
					R_LOG_ERROR ("Cannot write to the pipe");
					close (0);
					return false;
				}
				close (0);
				dup2 (pipes[0], 0);
			} else {
				R_LOG_ERROR ("Cannot create pipe");
			}
		}
#else
#ifdef _MSC_VER
#pragma message ("string redirection handle not yet done")
#else
#warning quoted string redirection handle not yet done
#endif
#endif
	} else if (cmd[0] == '!') {
		// redirection to a process
		return handle_redirection_proc (cmd + 1, in, out, err);
	} else {
		// redirection to a file
		int f, flag = 0, mode = 0;
		flag |= in ? O_RDONLY : 0;
		flag |= out ? O_WRONLY | O_CREAT : 0;
		flag |= err ? O_WRONLY | O_CREAT : 0;
#ifdef R2__WINDOWS__
		mode = _S_IREAD | _S_IWRITE;
#else
		mode = S_IRUSR | S_IWUSR;
#endif
		f = open (cmd, flag, mode);
		if (f < 0) {
			R_LOG_ERROR ("Cannot open: %s", cmd);
			return false;
		}
#ifndef __wasi__
#define DUP(x) { close(x); dup2(f,x); }
		if (in) {
			DUP (0);
		}
		if (out) {
			DUP (1);
		}
		if (err) {
			DUP (2);
		}
#endif
		close (f);
	}
	return true;
#endif
}

R_API bool r_run_parsefile(RRunProfile *p, const char *b) {
	R_RETURN_VAL_IF_FAIL (p && b, false);
	if (r_str_startswith (b, "base64:")) {
		int len;
		char *s = (char *)r_base64_decode_dyn (b + 7, -1, &len);
		char *res = r_str_ndup (s, len);
		free (s);
		return res;
	}
	char *s = r_file_slurp (b, NULL);
	if (s) {
		bool ret = r_run_parse (p, s);
		free (s);
		return ret;
	}
	return 0;
}

R_API bool r_run_parseline(RRunProfile *p, const char *b) {
	int must_free = false;
	char *e = strchr (b, '=');
	if (!e || *b == '#') {
		return 0;
	}
	*e++ = 0;
	if (*e == '$') {
		must_free = true;
		e = r_sys_getenv (e);
	}
	if (!e) {
		return 0;
	}
	if (!strcmp (b, "program")) {
		p->_args[0] = strdup (e);
		p->_program = strdup (e);
	} else if (!strcmp (b, "noprogram")) {
		p->_noprogram = true;
	} else if (!strcmp (b, "daemon")) {
		p->_daemon = true;
	} else if (!strcmp (b, "system")) {
		p->_system = strdup (e);
	} else if (!strcmp (b, "runlib")) {
		p->_runlib = strdup (e);
	} else if (!strcmp (b, "runlib.fcn")) {
		p->_runlib_fcn = strdup (e);
	} else if (!strcmp (b, "aslr")) {
		p->_aslr = r_str_is_true (e);
	} else if (!strcmp (b, "pid") || !strcmp (b, "getpid")) {
		p->_pid = atoi (e);
		if (!p->_pid) {
			p->_pid = r_str_is_true (e);
		}
	} else if (!strcmp (b, "pidfile")) {
		p->_pidfile = strdup (e);
	} else if (!strcmp (b, "connect")) {
		p->_connect = strdup (e);
	} else if (!strcmp (b, "listen")) {
		p->_listen = strdup (e);
	} else if (!strcmp (b, "pty")) {
		p->_pty = r_str_is_true (e);
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
		p->_docore = r_str_is_true (e);
	} else if (!strcmp (b, "fork")) {
		p->_dofork = r_str_is_true (e);
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
	} else if (!strcmp (b, "time")) {
		p->_time = true;
	} else if (!strcmp (b, "chroot")) {
		p->_chroot = strdup (e);
	} else if (!strcmp (b, "libpath")) {
		p->_libpath = strdup (e);
	} else if (!strcmp (b, "preload")) {
		if (!p->_preload) {
			p->_preload = r_list_newf (free);
		}
		r_list_append (p->_preload, strdup (e));
	} else if (!strcmp (b, "r2preload")) {
		p->_r2preload = r_str_is_true (e);
	} else if (!strcmp (b, "r2preweb")) {
		r_sys_setenv ("RARUN2_WEB", "yes");
	} else if (!strcmp (b, "setuid")) {
		p->_setuid = strdup (e);
	} else if (!strcmp (b, "seteuid")) {
		p->_seteuid = strdup (e);
	} else if (!strcmp (b, "setgid")) {
		p->_setgid = strdup (e);
	} else if (!strcmp (b, "stderrout")) {
		p->_stderrout = r_str_is_true (e);
	} else if (!strcmp (b, "setegid")) {
		p->_setegid = strdup (e);
	} else if (!strcmp (b, "nice")) {
		p->_nice = atoi (e);
	} else if (!strcmp (b, "timeout")) {
		p->_timeout = atoi (e);
	} else if (!strcmp (b, "timeoutsig")) {
		p->_timeout_sig = r_signal_from_string (e);
	} else if (r_str_startswith (b, "arg")) {
		int n = atoi (b + 3);
		if (n >= 0 && n < R_RUN_PROFILE_NARGS) {
			free (p->_args[n]);
			p->_args[n] = getstr (e, NULL);
			p->_argc++;
		} else {
			R_LOG_ERROR ("Out of bounds args index: %d", n);
		}
	} else if (!strcmp (b, "envfile")) {
		char *p, buf[1024];
		size_t len;
		FILE *fd = r_sandbox_fopen (e, "r");
		if (!fd) {
			R_LOG_ERROR ("Cannot open '%s'", e);
			if (must_free == true) {
				free (e);
			}
			return false;
		}
		for (;;) {
			if (!fgets (buf, sizeof (buf), fd)) {
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
		char *v = strchr (e, '=');
		if (v) {
			*v++ = 0;
#if 0
			char *V = getstr (v, NULL);
			r_sys_setenv (e, V);
#else
			size_t len;
			ut8 *V = (ut8*)getstr (v, &len);
			r_sys_setenv2 (e, V, len);
#endif
			free (V);
		}
	} else if (!strcmp (b, "clearenv")) {
		r_sys_clearenv ();
	} else {
		R_LOG_DEBUG ("Unknown directive %s", b);
	}
	if (must_free == true) {
		free (e);
	}
	return true;
}

R_API const char *r_run_help(void) {
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
	"# daemon=false\n"
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
	"# #stderrout=false\n"
	"# stdout=foo.txt\n"
	"# stdin=input.txt # or !program to redirect input from another program\n"
	"# input=input.txt\n"
	"# chdir=/\n"
	"# chroot=/mnt/chroot\n"
	"# libpath=$PWD:/tmp/lib\n"
	"# r2preload=yes\n"
	"# preload=/lib/libfoo.so # you can load more than one lib by using this directive many times\n"
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
		r_sys_perror ("ioctl");
		return -1;
	}
	if (!size) { // child process exited or socket is closed
		return -1;
	}

	char *new_buff = realloc (*buff, size);
	if (!new_buff) {
		R_LOG_ERROR ("Failed to allocate buffer for redirection");
		return -1;
	}
	*buff = new_buff;
	if (read (in_fd, *buff, size) != size) {
		r_sys_perror ("read");
		return -1;
	}
	if (write (out_fd, *buff, size) != size) {
		r_sys_perror ("write");
		return -1;
	}

	return 0;
}
#endif

static int redirect_socket_to_stdio(RSocket *sock) {
	close (0);
	close (1);
	close (2);
#ifndef __wasi__
	dup2 (sock->fd, 0);
	dup2 (sock->fd, 1);
	dup2 (sock->fd, 2);
#endif
	return 0;
}

#if R2__WINDOWS__
static RThreadFunctionRet exit_process(RThread *th) {
	exit (0);
}
#endif

static bool redirect_socket_to_pty(RSocket *sock) {
#if HAVE_PTY
	// directly duplicating the fds using dup2() creates problems
	// in case of interactive applications
	int fdm = -1, fds = -1;

	if (dyn_openpty && dyn_openpty (&fdm, &fds, NULL, NULL, NULL) == -1) {
		r_sys_perror ("opening pty");
		return false;
	}

	pid_t child_pid = r_sys_fork ();

	if (child_pid == -1) {
		R_LOG_ERROR ("cannot fork");
		if (fdm != -1) {
			close (fdm);
		}
		if (fds != -1) {
			close (fds);
		}
		return false;
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
				r_sys_perror ("select error");
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
		if (fdm != -1) {
			close (fdm);
			fdm = -1;
		}
		r_socket_free (sock);
		exit (0);
	}

	// parent
	r_socket_close_fd (sock);
	if (dyn_login_tty) {
		dyn_login_tty (fds);
	}
	if (fdm != -1) {
		close (fdm);
	}

	// disable the echo on slave stdin
	struct termios t;
	tcgetattr (0, &t);
	cfmakeraw (&t);
	tcsetattr (0, TCSANOW, &t);

	return true;
#else
	// Fallback to socket to I/O redirection
	return redirect_socket_to_stdio (sock);
#endif
}

R_API bool r_run_config_env(RRunProfile *p) {
#if HAVE_PTY
	dyn_init ();
#endif
	if (!p->_noprogram) {
		if (!p->_program && !p->_system && !p->_runlib) {
			R_LOG_ERROR ("No program, system or runlib rule defined");
			return false;
		}
	}
	// when IO is redirected to a process, handle them together
	if (!handle_redirection (p->_stdio, true, true, false)) {
		R_LOG_WARN ("cannot handle stdio redirection");
		return false;
	}
	if (!handle_redirection (p->_stdin, true, false, false)) {
		R_LOG_WARN ("cannot handle stdin redirection");
		return false;
	}
	if (!handle_redirection (p->_stdout, false, true, false)) {
		R_LOG_WARN ("cannot handle stdout redirection");
		return false;
	}
	if (!handle_redirection (p->_stderr, false, false, true)) {
		R_LOG_WARN ("cannot handle stderr redirection");
		return false;
	}
	if (p->_aslr != -1) {
		setASLR (p, p->_aslr);
	}
#if R2__UNIX__ && !__wasi__ && !defined(__serenity__)
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
		R_LOG_WARN ("setrlimits not supported for this platform");
#endif
	if (p->_connect) {
		char *q = strchr (p->_connect, ':');
		if (q) {
			RSocket *fd = r_socket_new (0);
			*q = 0;
			if (!r_socket_connect_tcp (fd, p->_connect, q+1, 30)) {
				R_LOG_ERROR ("Cannot connect");
				r_socket_free (fd);
				return false;
			}
			if (p->_pty) {
				if (!redirect_socket_to_pty (fd)) {
					R_LOG_ERROR ("socket redirection failed");
					r_socket_free (fd);
					return false;
				}
			} else {
				redirect_socket_to_stdio (fd);
			}
		} else {
			R_LOG_ERROR ("Invalid format for connect. missing ':'");
			return false;
		}
	}
	if (p->_listen) {
		RSocket *child, *fd = r_socket_new (0);
		bool is_child = false;
		if (!r_socket_listen (fd, p->_listen, NULL)) {
			R_LOG_ERROR ("Cannot listen");
			r_socket_free (fd);
			return false;
		}
		while (true) {
			child = r_socket_accept (fd);
			if (child) {
				is_child = true;

				if (p->_dofork) {
					pid_t child_pid = r_sys_fork ();
					if (child_pid == -1) {
						R_LOG_ERROR ("Cannot fork");
						r_socket_free (child);
						r_socket_free (fd);
						return false;
					}
					if (child_pid != 0) {
						// parent code
						is_child = false;
						if (p->_pid) {
							R_LOG_INFO ("pid = %d", child_pid);
						}
					}
				}

				if (is_child) {
					r_socket_close_fd (fd);
					R_LOG_INFO ("connected");
					if (p->_pty) {
						if (!redirect_socket_to_pty (child)) {
							R_LOG_ERROR ("socket redirection failed");
							r_socket_free (child);
							r_socket_free (fd);
							return false;
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
#if R2__UNIX__ && !__wasi__
	if (p->_chroot) {
		if (chdir (p->_chroot) == -1) {
			R_LOG_ERROR ("Cannot chdir to chroot in %s", p->_chroot);
			return false;
		}
		if (chroot (".") == -1) {
			R_LOG_ERROR ("Cannot chroot to %s", p->_chroot);
			return false;
		}
		// Silenting pedantic meson flags...
		if (chdir ("/") == -1) {
			R_LOG_ERROR ("Cannot chdir to /");
			return false;
		}
		if (p->_chgdir && chdir (p->_chgdir) == -1) {
			R_LOG_ERROR ("Cannot chdir after chroot to %s", p->_chgdir);
			return false;
		}
	} else if (p->_chgdir) {
		if (chdir (p->_chgdir) == -1) {
			R_LOG_ERROR ("Cannot chdir after chroot to %s", p->_chgdir);
			return false;
		}
	}
#else
	if (p->_chgdir) {
		int ret = chdir (p->_chgdir);
		if (ret < 0) {
			return false;
		}
	}
	if (p->_chroot) {
		int ret = chdir (p->_chroot);
		if (ret < 0) {
			return false;
		}
	}
#endif
#if R2__UNIX__ && !__wasi__
	if (p->_setuid) {
		int ret = setgroups (0, NULL);
		if (ret < 0) {
			return false;
		}
		ret = setuid (atoi (p->_setuid));
		if (ret < 0) {
			return false;
		}
	}
	if (p->_seteuid) {
		int ret = seteuid (atoi (p->_seteuid));
		if (ret < 0) {
			return false;
		}
	}
	if (p->_stderrout) {
#if __wasi__
		R_LOG_WARN ("Directive 'stderrout' not supported in wasm");
#else
		if (dup2 (1, 2) == -1) {
			return false;
		}
#endif
	}
	if (p->_setgid) {
#if __wasi__
		R_LOG_WARN ("Directive 'setgid' not supported in wasm");
#else
		int ret = setgid (atoi (p->_setgid));
		if (ret < 0) {
			return false;
		}
#endif
	}
	if (p->_input) {
		char *inp;
		int f2[2] = { -1, -1 };
		if (pipe (f2) != -1) {
			close (0);
#if !__wasi__
			dup2 (f2[0], 0);
#endif
		} else {
			R_LOG_ERROR ("Cannot create pipe");
			return false;
		}
		size_t inpl;
		inp = getstr (p->_input, &inpl);
		if (inp) {
			if  (write (f2[1], inp, inpl) != inpl) {
				R_LOG_ERROR ("Cannot write to the pipe");
			}
			free (inp);
		} else {
			R_LOG_ERROR ("Invalid input");
		}
		close (f2[1]);
	}
#endif
	if (p->_r2preload) {
#if R2__WINDOWS__
		R_LOG_ERROR ("r2preload is not supported in this platform");
#else
		if (!p->_preload) {
			p->_preload = r_list_newf (free);
		}
		r_list_append (p->_preload, strdup (R2_LIBDIR"/libr2."R_LIB_EXT));
#endif
	}
	if (p->_libpath) {
#if R2__WINDOWS__
		R_LOG_ERROR ("libpath is not supported in this platform");
#elif __HAIKU__
		char *orig = r_sys_getenv ("LIBRARY_PATH");
		char *newlib = r_str_newf ("%s:%s", p->_libpath, orig);
		r_sys_setenv ("LIBRARY_PATH", newlib);
		free (newlib);
		free (orig);
#elif __APPLE__
		r_sys_setenv ("DYLD_LIBRARY_PATH", p->_libpath);
#else
		r_sys_setenv ("LD_LIBRARY_PATH", p->_libpath);
#endif
	}
	if (p->_preload) {
		char *ps = r_str_list_join (p->_preload, ":");
#if R2__WINDOWS__
		R_LOG_WARN ("The preload directive doesn't work on windows");
#elif __APPLE__
		// 10.6
#ifndef __MAC_10_7
		r_sys_setenv ("DYLD_PRELOAD", ps);
#endif
		r_sys_setenv ("DYLD_INSERT_LIBRARIES", ps);
		// 10.8
		r_sys_setenv ("DYLD_FORCE_FLAT_NAMESPACE", "1");
#else
		r_sys_setenv ("LD_PRELOAD", ps);
#endif
		free (ps);
	}
	if (p->_timeout) {
#if __wasi__
		// do nothing
#elif R2__UNIX__
		int mypid = r_sys_getpid ();
		if (!r_sys_fork ()) {
			int use_signal = p->_timeout_sig;
			if (use_signal < 1) {
				use_signal = SIGKILL;
			}
			sleep (p->_timeout);
			if (!kill (mypid, 0)) {
				// eprintf ("\nrarun2: Interrupted by timeout\n");
			}
			kill (mypid, use_signal);
			exit (0);
		}
#else
		if (p->_timeout_sig < 1 || p->_timeout_sig == 9) {
			r_th_new (exit_process, NULL, p->_timeout);
		} else {
			R_LOG_ERROR ("timeout with signal not supported for this platform");
		}
#endif
	}
	return true;
}

static void time_end(bool chk, ut64 time_begin) {
	if (chk) {
		ut64 now = r_time_now ();
		R_LOG_INFO ("%"PFMT64d, now - time_begin);
	}
}

// NOTE: return value is like in unix return code (0 = ok, 1 = not ok)
R_API bool r_run_start(RRunProfile *p) {
	R_RETURN_VAL_IF_FAIL (p, false);
	if (p->_noprogram) {
		if (p->_pid) {
			R_LOG_INFO ("pid = %d", r_sys_getpid ());
		}
		while (true) {
#if R2__UNIX__ && !__wasi__
			pause ();
#else
			r_sys_sleep (1);
#endif
		}
		return true;
	}
#if LIBC_HAVE_FORK
	if (p->_execve) {
		exit (execv (p->_program, (char* const*)p->_args));
	}
#endif
	ut64 time_begin = 0;
	if (p->_time) {
		time_begin = r_time_now ();
	}
#if __APPLE__ && !__POWERPC__ && LIBC_HAVE_FORK
	posix_spawnattr_t attr = {0};
	pid_t pid = -1;
	int ret;
	posix_spawnattr_init (&attr);
	if (p->_args[0]) {
		char **envp = r_sys_get_environ ();
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
		if (p->_pid) {
			R_LOG_INFO ("pid = %d", r_sys_getpid ());
		}
		ret = posix_spawnp (&pid, p->_args[0], NULL, &attr, p->_args, envp);
		if (p->_pid) {
			R_LOG_INFO ("pid = %d", pid);
		}
		switch (ret) {
		case 0:
			break;
		case 22:
			R_LOG_ERROR ("posix_spawnp: Invalid argument");
			break;
		case 86:
			R_LOG_ERROR ("posix_spawnp: Unsupported architecture");
			break;
		default:
			R_LOG_ERROR ("posix_spawnp: unknown error %d", ret);
			r_sys_perror ("posix_spawnp");
			break;
		}
		exit (ret);
	}
#endif
	if (p->_system) {
		int rc = 0;
		if (p->_pid) {
			R_LOG_ERROR ("PID: Cannot determine pid with 'system' directive. Use 'program'");
		}
		if (p->_daemon) {
#if R2__WINDOWS__
	//		eprintf ("PID: Cannot determine pid with 'system' directive. Use 'program'.\n");
#else
			pid_t child = r_sys_fork ();
			if (child == -1) {
				r_sys_perror ("fork");
				exit (1);
			}
			if (child) {
				if (p->_pid) {
					R_LOG_INFO ("pid = %d", child);
				}
				if (p->_pidfile) {
					r_strf_var (pidstr, 32, "%d\n", (int)child);
					r_file_dump (p->_pidfile, (const ut8*)pidstr,
						strlen (pidstr), 0);
				}
				exit (0);
			}
#if !__wasi__
			setsid ();
#endif
			// setvbuf (stdout, NULL, _IONBF, 0);
			if (p->_timeout) {
#if R2__UNIX__
#if !__wasi__
				int mypid = r_sys_getpid ();
#endif
				if (!r_sys_fork ()) {
					int use_signal = p->_timeout_sig;
					if (use_signal < 1) {
						use_signal = SIGKILL;
					}
					sleep (p->_timeout);
#if !__wasi__
					if (!kill (mypid, 0)) {
						// eprintf ("\nrarun2: Interrupted by timeout\n");
					}
					kill (mypid, use_signal);
#endif
					time_end (p->_time, time_begin);
					exit (0);
				}
#else
				R_LOG_ERROR ("timeout not supported for this platform");
#endif
			}
#endif
#if R2__UNIX__ && !__wasi__
			close (0);
			close (1);
			char *bin_sh = r_file_binsh ();
			if (bin_sh) {
				rc = execl (bin_sh, bin_sh, "-c", p->_system, NULL);
			} else {
				rc = r_sys_cmd (p->_system);
			}
			free (bin_sh);
#else
			rc = r_sys_cmd (p->_system);
#endif
		} else {
			if (p->_pidfile) {
				R_LOG_WARN ("pidfile doesnt work with 'system'");
			}
			if (p->_pid) {
				R_LOG_WARN ("Use 'program' instead of 'system' to show the pid");
			}
			rc = r_sys_cmd (p->_system);
		}
		time_end (p->_time, time_begin);
		exit (rc);
	}
	if (p->_program) {
		if (!r_file_exists (p->_program)) {
			char *progpath = r_file_path (p->_program);
			if (!progpath) {
				R_LOG_ERROR ("file not found: %s", p->_program);
				return false;
			}
			free (p->_program);
			p->_program = progpath;
		}
#if R2__UNIX__
		// XXX HACK close all non-tty fds
		{ int i;
			for (i = 3; i < 1024; i++) {
				close (i);
			}
		}
		// TODO: use posix_spawn
		if (p->_setgid) {
#if __wasi__
			int ret = -1;
#else
			int ret = setgid (atoi (p->_setgid));
#endif
			if (ret < 0) {
				return false;
			}
		}
		if (p->_pid) {
			R_LOG_INFO ("pid = %d", r_sys_getpid ());
		}
		if (p->_pidfile) {
			char pidstr[32];
			snprintf (pidstr, sizeof (pidstr), "%d\n", r_sys_getpid ());
			r_file_dump (p->_pidfile,
				(const ut8*)pidstr,
				strlen (pidstr), 0);
		}
#endif

		if (p->_nice) {
#if R2__UNIX__ && !defined(__HAIKU__) && !defined(__serenity__) && !__wasi__
			if (nice (p->_nice) == -1) {
				return false;
			}
#else
			R_LOG_ERROR ("nice not supported for this platform");
#endif
		}
		if (p->_daemon) {
#if R2__WINDOWS__
			R_LOG_ERROR ("PID: Cannot determine pid with 'system' directive. Use 'program'");
#else
			pid_t child = r_sys_fork ();
			if (child == -1) {
				r_sys_perror ("fork");
				exit (1);
			}
			if (child) {
				if (p->_pidfile) {
					char pidstr[32];
					snprintf (pidstr, sizeof (pidstr), "%d\n", (int)child);
					r_file_dump (p->_pidfile,
							(const ut8*)pidstr,
							strlen (pidstr), 0);
					exit (0);
				}
			}
#if !__wasi__
			setsid ();
#if !LIBC_HAVE_FORK
			exit (execv (p->_program, (char* const*)p->_args));
#endif
#endif
#endif
		}
// TODO: must be HAVE_EXECVE
#if LIBC_HAVE_FORK
		time_end (p->_time, time_begin);
		exit (execv (p->_program, (char* const*)p->_args));
#endif
	}
	if (p->_runlib) {
		if (!p->_runlib_fcn) {
			R_LOG_ERROR ("No function specified. Please set runlib.fcn");
			return false;
		}
		void *addr = r_lib_dl_open (p->_runlib);
		if (!addr) {
			R_LOG_ERROR ("Could not load the library '%s'", p->_runlib);
			return false;
		}
		void (*fcn)(void) = r_lib_dl_sym (addr, p->_runlib_fcn);
		if (!fcn) {
			R_LOG_ERROR ("Could not find the function '%s'", p->_runlib_fcn);
			return false;
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
			R_LOG_ERROR ("Too many arguments");
			return false;
		}
		r_lib_dl_close (addr);
	}
	time_end (p->_time, time_begin);
	return true;
}

R_API char *r_run_get_environ_profile(char **env) {
	if (!env) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	while (*env) {
		char *k = strdup (*env);
		char *v = strchr (k, '=');
		if (v) {
			*v++ = 0;
			v = r_str_escape_latin1 (v, false, true, true);
			if (v) {
				r_strbuf_appendf (sb, "setenv=%s=\"%s\"\n", k, v);
				free (v);
			}
		}
		free (k);
		env++;
	}
	return r_strbuf_drain (sb);
}
