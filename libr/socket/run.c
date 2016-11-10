/* radare - LGPL - Copyright 2014-2016 - pancake */

/* this helper api is here because it depends on r_util and r_socket */
/* we should find a better place for it. r_io? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <r_util.h>
#include <r_socket.h>
#include <r_lib.h>
#include <sys/stat.h>
#include <sys/types.h>
#if __APPLE__
#if !__POWERPC__
#include <spawn.h>
#endif
#include <sys/ptrace.h>
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
#include <signal.h>
#include <grp.h>
#include <errno.h>
#if __linux__ && !__ANDROID__
#include <sys/personality.h>
#include <pty.h>
#endif
#if defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <util.h>
#endif
#endif

R_API RRunProfile *r_run_new(const char *str) {
	RRunProfile *p = R_NEW (RRunProfile);
	if (p) {
		r_run_reset (p);
		if (str) r_run_parsefile (p, str);
	}
	return p;
}

R_API void r_run_reset(RRunProfile *p) {
	memset (p, 0, sizeof (RRunProfile));
	p->_aslr = -1;
}

R_API int r_run_parse(RRunProfile *pf, const char *profile) {
	char *p, *o, *str = strdup (profile);
	if (!str) return 0;
	for (o = p = str; (o = strchr (p, '\n')); p = o) {
		*o++ = 0;
		r_run_parseline (pf, p);
	}
	free (str);
	return 1;
}

R_API void r_run_free (RRunProfile *r) {
	free (r->_system);
	free (r->_program);
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
			if (len>0) {
				len--;
				if (ret[len]=='\'') {
					ret[len] = 0;
					return ret;
				} else eprintf ("Missing \"\n");
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
	case '!':
		return r_str_trim_tail (r_sys_cmd_str (src + 1, NULL, NULL));
	case ':':
		if (src[1] == '!') {
			ret = r_str_trim_tail (r_sys_cmd_str (src + 1, NULL, NULL));
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
	}
	r_str_unescape ((ret = strdup (src)));
	return ret;
}

static int parseBool (const char *e) {
	return (strcmp (e, "yes")?
		(strcmp (e, "true")?
		(strcmp (e, "1")?
		0: 1): 1): 1);
}

#if __linux__
#define RVAS "/proc/sys/kernel/randomize_va_space"
static void setRVA(const char *v) {
	int fd = open (RVAS, O_WRONLY);
	if (fd != -1) {
		write (fd, v, 2);
		close (fd);
	}
}
#endif

// TODO: move into r_util? r_run_... ? with the rest of funcs?
static void setASLR(int enabled) {
#if __linux__
	if (enabled) {
		setRVA ("2\n");
	} else {
#if __ANDROID__
		setRVA ("0\n");
#else
#ifdef ADDR_NO_RANDOMIZE
		if (personality (ADDR_NO_RANDOMIZE) == -1)
#endif
			setRVA ("0\n");
#endif
	}
#elif __APPLE__
	// TOO OLD setenv ("DYLD_NO_PIE", "1", 1);
	// disable this because its
	//eprintf ("Patch mach0.hdr.flags with:\n"
	//	"f MH_PIE=0x00200000; wB-MH_PIE @ 24\n");
	// for osxver>=10.7
	// "unset the MH_PIE bit in an already linked executable" with --no-pie flag of the script
	// the right way is to disable the aslr bit in the spawn call
#else
	// not supported for this platform
#endif
}

static int handle_redirection_proc (const char *cmd, bool in, bool out, bool err) {
#if __UNIX__ && !__ANDROID__ && LIBC_HAVE_FORK
	// use PTY to redirect I/O because pipes can be problematic in
	// case of interactive programs.
	int fdm;

	int saved_stdin = dup (STDIN_FILENO);
	int saved_stdout = dup (STDOUT_FILENO);
	int saved_stderr = dup (STDERR_FILENO);

	if (forkpty (&fdm, NULL, NULL, NULL) == 0) {
		// child - program to run
		struct termios t;

		// necessary because otherwise you can read the same thing you
		// wrote on fdm.
		tcgetattr (0, &t);
		cfmakeraw (&t);
		tcsetattr (0, TCSANOW, &t);

		if (!in) dup2 (saved_stdin, STDIN_FILENO);
		if (!out) dup2 (saved_stdout, STDOUT_FILENO);
		if (!err) dup2 (saved_stderr, STDERR_FILENO);
		if (saved_stdin != -1) {
			close (saved_stdin);
		}
		if (saved_stdout != -1) {
			close (saved_stdout);
		}
		if (saved_stderr != -1) {
			close (saved_stderr);
		}
		saved_stdin = -1;
		saved_stdout = -1;
		saved_stderr = -1;
		return 0;
	}
	// father
	if (saved_stdin != -1) {
		close (saved_stdin);
	}
	if (saved_stdout != -1) {
		close (saved_stdout);
	}
	if (saved_stderr != -1) {
		close (saved_stderr);
	}
	if (in) dup2 (fdm, STDOUT_FILENO);
	if (out) dup2 (fdm, STDIN_FILENO);
	exit (r_sys_cmd (cmd));
#else
#warning handle_redirection_proc : unimplemented for this platform
	return -1;
#endif
}

static int handle_redirection(const char *cmd, bool in, bool out, bool err) {
	if (!cmd || cmd[0] == '\0') return 0;

	if (cmd[0] == '"') {
#if __UNIX__
		if (in) {
			int pipes[2];
			if (pipe (pipes) != -1) {
				write (pipes[1], cmd+1, strlen (cmd)-2);
				write (pipes[1], "\n", 1);
				close (0);
				dup2 (pipes[0], 0);
			} else {
				eprintf ("[ERROR] rarun2: Cannot create pipe\n");
			}
		}
#else
#warning quoted string redirection handle not yet done
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
		if (in) DUP(0);
		if (out) DUP(1);
		if (err) DUP(2);
		close (f);
		return 0;
	}
}

R_API int r_run_parsefile (RRunProfile *p, const char *b) {
	char *s = r_file_slurp (b, NULL);
	if (s) {
		int ret = r_run_parse (p, s);
		free (s);
		return ret;
	}
	return 0;
}

R_API int r_run_parseline (RRunProfile *p, char *b) {
	int must_free = false;
	char *e = strchr (b, '=');
	if (!e) return 0;
	if (*b=='#') return 0;
	*e++ = 0;
	if (*e=='$') {
		must_free = true;
		e = r_sys_getenv (e);
	}
	if (!e) return 0;
	if (!strcmp (b, "program")) p->_args[0] = p->_program = strdup (e);
	else if (!strcmp (b, "system")) p->_system = strdup (e);
	else if (!strcmp (b, "aslr")) p->_aslr = parseBool (e);
	else if (!strcmp (b, "pid")) p->_pid = atoi (e);
	else if (!strcmp (b, "pidfile")) p->_pidfile = strdup (e);
	else if (!strcmp (b, "connect")) p->_connect = strdup (e);
	else if (!strcmp (b, "listen")) p->_listen = strdup (e);
	else if (!strcmp (b, "stdio")) {
		if (e[0] == '!') {
			p->_stdio = strdup (e);
		} else {
			p->_stdout = strdup (e);
			p->_stderr = strdup (e);
			p->_stdin = strdup (e);
		}
	}
	else if (!strcmp (b, "stdout")) p->_stdout = strdup (e);
	else if (!strcmp (b, "stdin")) p->_stdin = strdup (e);
	else if (!strcmp (b, "stderr")) p->_stderr = strdup (e);
	else if (!strcmp (b, "input")) p->_input = strdup (e);
	else if (!strcmp (b, "chdir")) p->_chgdir = strdup (e);
	else if (!strcmp (b, "core")) p->_docore = parseBool (e);
	else if (!strcmp (b, "fork")) p->_dofork = parseBool (e);
	else if (!strcmp (b, "sleep")) p->_r2sleep = atoi (e);
	else if (!strcmp (b, "maxstack")) p->_maxstack = atoi (e);
	else if (!strcmp (b, "maxproc")) p->_maxproc = atoi (e);
	else if (!strcmp (b, "maxfd")) p->_maxfd = atoi (e);
	else if (!strcmp (b, "bits")) p->_bits = atoi (e);
	else if (!strcmp (b, "chroot")) p->_chroot = strdup (e);
	else if (!strcmp (b, "libpath")) p->_libpath = strdup (e);
	else if (!strcmp (b, "preload")) p->_preload = strdup (e);
	else if (!strcmp (b, "r2preload")) p->_r2preload = parseBool (e);
	else if (!strcmp (b, "r2preweb")) r_sys_setenv ("RARUN2_WEB", "yes");
	else if (!strcmp (b, "setuid")) p->_setuid = strdup (e);
	else if (!strcmp (b, "seteuid")) p->_seteuid = strdup (e);
	else if (!strcmp (b, "setgid")) p->_setgid = strdup (e);
	else if (!strcmp (b, "setegid")) p->_setegid = strdup (e);
	else if (!strcmp (b, "nice")) p->_nice = atoi (e);
	else if (!memcmp (b, "arg", 3)) {
		int n = atoi (b + 3);
		if (n >= 0 && n < R_RUN_PROFILE_NARGS) {
			p->_args[n] = getstr (e);
		} else eprintf ("Out of bounds args index: %d\n", n);
	} else if (!strcmp (b, "timeout")) {
		p->_timeout = atoi (e);
	} else if (!strcmp (b, "timeoutsig")) {
		// TODO: support non-numeric signal numbers here
		p->_timeout_sig = atoi (e);
	} else if (!strcmp (b, "envfile")) {
		char *p, buf[1024];
		FILE *fd = fopen (e, "r");
		if (!fd) {
			eprintf ("Cannot open '%s'\n", e);
			if (must_free == true) free (e);
			return 0;
		}
		for (;;) {
			fgets (buf, sizeof (buf)-1, fd);
			if (feof (fd)) break;
			p = strchr (buf, '=');
			if (p) {
				*p = 0;
				r_sys_setenv (buf, p + 1);
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
	if (must_free == true)
		free (e);
	return 1;
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
	"# connect=localhost:8080\n"
	"# listen=8080\n"
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
	"# stdin=input.txt # or !program to redirect input to another program\n"
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

R_API int r_run_config_env(RRunProfile *p) {
	int ret;

	if (!p->_program && !p->_system) {
		printf ("No program or system rule defined\n");
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
	if (p->_aslr != -1)
		setASLR (p->_aslr);
#if __UNIX__
	set_limit (p->_docore, RLIMIT_CORE, RLIM_INFINITY);
	if (p->_maxfd)
		set_limit (p->_maxfd, RLIMIT_NOFILE, p->_maxfd);
#ifdef RLIMIT_NPROC
	if (p->_maxproc)
		set_limit (p->_maxproc, RLIMIT_NPROC, p->_maxproc);
#endif
	if (p->_maxstack)
		set_limit (p->_maxstack, RLIMIT_STACK, p->_maxstack);
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
			eprintf ("connected\n");
			close (0);
			close (1);
			close (2);
			dup2 (fd->fd, 0);
			dup2 (fd->fd, 1);
			dup2 (fd->fd, 2);
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
					pid_t child_pid = r_sys_fork ();
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
					close (0);
					close (1);
					close (2);
					dup2 (child->fd, 0);
					dup2 (child->fd, 1);
					dup2 (child->fd, 2);
					break;
				} else {
					r_socket_close_fd (child);
				}
			}
		}
		if(!is_child) r_socket_free (child);
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
		pipe (f2);
		close (0);
		dup2 (f2[0], 0);
		inp = getstr (p->_input);
		if (inp) {
			write (f2[1], inp, strlen (inp));
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
		p->_preload = R2_LIBDIR"/libr2."R_LIB_EXT;
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
		r_sys_setenv ("DYLD_PRELOAD", p->_preload);
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
			if (p->_bits == 64)
				cpu |= CPU_ARCH_ABI64;
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
		{ int i; for (i=3; i<10; i++) close (i); }
		// TODO: use posix_spawn
		if (p->_setgid) {
			int ret = setgid (atoi (p->_setgid));
			if (ret < 0)
				return 1;
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
	return 0;
}
