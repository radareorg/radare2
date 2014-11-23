/* radare - LGPL - Copyright 2014 - pancake */

/* this helper api is here because it depends on r_util and r_socket */
/* we should find a better place for it. r_io? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <r_util.h>
#include <r_socket.h>
#if __APPLE__
#include <spawn.h>
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
#endif
#if __UNIX__
#include <sys/resource.h>
#include <signal.h>
#include <grp.h>
#if __linux__ && !__ANDROID__
#include <sys/personality.h>
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
	for (o = p = str; (o = strchr (p, '\n')); p = o) {
		*o++ = 0;
		r_run_parseline (pf, p);
	}
	free (str);
	return 1;
}

R_API void r_run_free (RRunProfile *r) {
	//int i;
	//for (i=0;i<R_RUN_PROFILE_NARGS;i++)
	//	free (r->_args[i]);
	free (r->_system);
	free (r->_program);
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
		ret = strdup (src+1);
		if (ret) {
			len = strlen (ret);
			if (len>0) {
				len--;
				if (ret[len]=='"') {
					ret[len] = 0;
					r_str_unescape (ret);
					return ret;
				} else eprintf ("Missing \"\n");
			}
			free (ret);
		}
		return NULL;
	case '@':
		{
			char *pat = strchr (src+1, '@');
			if (pat) {
				*pat++ = 0;
				int i, rep = atoi (src+1);
				int len = strlen (pat);
				if (rep>0) {
					char *buf = malloc (rep);
					for(i=0;i<rep;i++) {
						buf[i] = pat[i%len];
					}
					return buf;
				}
			}
			// slurp file
			return r_file_slurp (src+1, NULL);
		}
	case '!':
		return r_str_trim_tail (r_sys_cmd_str (src+1, NULL, NULL));
	case ':':
		if (src[1]=='!') {
			ret = r_str_trim_tail (r_sys_cmd_str (src+1, NULL, NULL));
		} else {
			ret = strdup (src);
		}
		len = r_hex_str2bin (src+1, (ut8*)ret);
		if (len>0) {
			ret[len] = 0;
			return ret;
		} else {
			eprintf ("Invalid hexpair string\n");
			free (ret);
			return NULL;
		}
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

// TODO: move into r_util? r_run_... ? with the rest of funcs?
static void setASLR(int enabled) {
#if __linux__
#define RVAS "/proc/sys/kernel/randomize_va_space"
	if (enabled) {
		system ("echo 2 > "RVAS);
	} else {
#if __ANDROID__
		system ("echo 0 > "RVAS);
#else
		if (personality (ADDR_NO_RANDOMIZE) == -1)
			system ("echo 0 > "RVAS);
#endif
	}
#elif __APPLE__
	setenv ("DYLD_NO_PIE", "1", 1);
	eprintf ("Patch mach0.hdr.flags with:\n"
		"f MH_PIE=0x00200000; wB-MH_PIE @ 24\n");
	// for osxver>=10.7
	// "unset the MH_PIE bit in an already linked executable" with --no-pie flag of the script
#else
	// not supported for this platform
#endif
}

R_API int r_run_parsefile (RRunProfile *p, const char *b) {
	int ret;
	char *s = r_file_slurp (b, NULL);
	if (s) {
		ret = r_run_parse (p, s);
		free (s);
		return ret;
	}
	return 0;
}

R_API int r_run_parseline (RRunProfile *p, char *b) {
	int must_free = R_FALSE;
	char *e = strchr (b, '=');
	if (!e) return 0;
	if (*b=='#') return 0;
	*e++ = 0;
	if (*e=='$') {
		must_free = R_TRUE;
		e = r_sys_getenv (e);
	}
	if (e == NULL) return 0;
	if (!strcmp (b, "program")) p->_args[0] = p->_program = strdup (e);
	else if (!strcmp (b, "system")) p->_system = strdup (e);
	else if (!strcmp (b, "aslr")) p->_aslr = parseBool (e);
	else if (!strcmp (b, "pid")) p->_pid = atoi (e);
	else if (!strcmp (b, "connect")) p->_connect = strdup (e);
	else if (!strcmp (b, "listen")) p->_listen = strdup (e);
	else if (!strcmp (b, "stdout")) p->_stdout = strdup (e);
	else if (!strcmp (b, "stdio")) {
		p->_stdout = p->_stderr = p->_stdin = strdup (e);
	} else if (!strcmp (b, "stdin")) p->_stdin = strdup (e);
	else if (!strcmp (b, "stderr")) p->_stderr = strdup (e);
	else if (!strcmp (b, "input")) p->_input = strdup (e);
	else if (!strcmp (b, "chdir")) p->_chgdir = strdup (e);
	else if (!strcmp (b, "core")) p->_docore = parseBool (e);
	else if (!strcmp (b, "sleep")) p->_r2sleep = atoi (e);
	else if (!strcmp (b, "maxstack")) p->_maxstack = atoi (e);
	else if (!strcmp (b, "maxproc")) p->_maxproc = atoi (e);
	else if (!strcmp (b, "maxfd")) p->_maxfd = atoi (e);
	else if (!strcmp (b, "bits")) p->_bits = atoi (e);
	else if (!strcmp (b, "chroot")) p->_chroot = strdup (e);
	else if (!strcmp (b, "libpath")) p->_libpath = strdup (e);
	else if (!strcmp (b, "preload")) p->_preload = strdup (e);
	else if (!strcmp (b, "r2preload")) p->_r2preload = parseBool (e);
	else if (!strcmp (b, "setuid")) p->_setuid = strdup (e);
	else if (!strcmp (b, "seteuid")) p->_seteuid = strdup (e);
	else if (!strcmp (b, "setgid")) p->_setgid = strdup (e);
	else if (!strcmp (b, "setegid")) p->_setegid = strdup (e);
	else if (!memcmp (b, "arg", 3)) {
		int n = atoi (b+3);
		if (n>=0 && n<R_RUN_PROFILE_NARGS) {
			p->_args[n] = getstr (e);
		} else eprintf ("Out of bounds args index: %d\n", n);
	} else if (!strcmp (b, "timeout")) {
		p->_timeout = atoi (e);
	} else if (!strcmp (b, "envfile")) {
		char *p, buf[1024];
		FILE *fd = fopen (e, "r");
		if (!fd) {
			eprintf ("Cannot open '%s'\n", e);
			if (must_free == R_TRUE)
				free (e);
			return 0;
		}
		for (;;) {
			fgets (buf, sizeof (buf)-1, fd);
			if (feof (fd)) break;
			p = strchr (buf, '=');
			if (p) {
				*p = 0;
				r_sys_setenv (buf, p+1);
			}
		}
		fclose (fd);
	} else if (!strcmp (b, "unsetenv")) {
		r_sys_setenv (e, NULL);
	} else if (!strcmp (b, "setenv")) {
		char *v = strchr (e, '=');
		if (v) {
			*v++ = 0;
			r_sys_setenv (e, v);
		}
	}
	if (must_free == R_TRUE)
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
	"# envfile=environ.txt\n"
	"timeout=3\n"
	"# connect=localhost:8080\n"
	"# listen=8080\n"
	"# bits=32\n"
	"# pid=0\n"
	"# #sleep=0\n"
	"# #maxfd=0\n"
	"# #maxproc=0\n"
	"# #maxstack=0\n"
	"# #core=false\n"
	"# #stdio=blah.txt\n"
	"# #stderr=foo.txt\n"
	"# stdout=foo.txt\n"
	"# stdin=input.txt\n"
	"# input=input.txt\n"
	"# chdir=/\n"
	"# chroot=/mnt/chroot\n"
	"# libpath=$PWD:/tmp/lib\n"
	"# r2preload=yes\n"
	"# preload=/lib/libfoo.so\n"
	"# setuid=2000\n"
	"# seteuid=2000\n"
	"# setgid=2001\n"
	"# setegid=2001\n";
}

#if __UNIX__
static void parseinput (char *s) {
	if (!*s) return;
	while (*s++) {
		if (s[0]=='\\' && s[1]=='n') {
			*s = '\n';
			strcpy (s+1, s+2);
		}
	}
}
#endif

R_API int r_run_start(RRunProfile *p) {
#if __APPLE__
	posix_spawnattr_t attr = {0};
	pid_t pid = -1;
#endif
	int ret;
	if (!p->_program && !p->_system) {
		printf ("No program or system rule defined\n");
		return 1;
	}
	if (p->_stdin) {
		int f = open (p->_stdin, O_RDONLY);
		if (f < 0)
			return 1;
		close (0);
		dup2 (f, 0);
	}
	if (p->_stdout) {
		int f = open (p->_stdout, O_WRONLY);
		if (f < 0)
			return 1;
		close (1);
		dup2 (f, 1);
	}
	if (p->_stderr) {
		int f = open (p->_stderr, O_WRONLY);
		if (f < 0)
			return 1;
		close (2);
		dup2 (f, 2);
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
		if (!r_socket_listen (fd, p->_listen, NULL)) {
			eprintf ("rarun2: cannot listen\n");
			r_socket_free (fd);
			return 1;
		}
		child = r_socket_accept (fd);
		if (child) {
			eprintf ("connected\n");
			close (0);
			close (1);
			close (2);
			dup2 (child->fd, 0);
			dup2 (child->fd, 1);
			dup2 (child->fd, 2);
		}
	}
	if (p->_r2sleep != 0) {
		r_sys_sleep (p->_r2sleep);
	}
	if (p->_chgdir) {
		ret = chdir (p->_chgdir);
		if (ret < 0)
			return 1;
	}
	if (p->_chroot) {
		ret = chdir (p->_chroot);
		if (ret < 0)
			return 1;
	}
#if __UNIX__
	if (p->_chroot) {
		if (chroot (p->_chroot)) {
			eprintf ("rarun2: cannot chroot\n");
			return 1;
		}
		chdir("/");
	}
	if (p->_setuid) {
		ret = setgroups(0, NULL);
		if (ret < 0)
			return 1;
		ret = setuid (atoi (p->_setuid));
		if (ret < 0)
			return 1;
	}
	if (p->_seteuid) {
		ret = seteuid (atoi (p->_seteuid));
		if (ret < 0)
			return 1;
	}
	if (p->_setgid) {
		ret = setgid (atoi (p->_setgid));
		if (ret < 0)
			return 1;
	}
	if (p->_input) {
		int f2[2];
		pipe (f2);
		close (0);
		dup2 (f2[0], 0);
		parseinput (p->_input);
		write (f2[1], p->_input, strlen (p->_input));
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
		if (!fork ()) {
			sleep (p->_timeout);
			if (!kill (mypid, 0))
				eprintf ("\nrarun2: Interrupted by timeout\n");
			kill (mypid, SIGKILL);
			exit (0);
		}
#else
		eprintf ("timeout not supported for this platform\n");
#endif
	}
#if __APPLE__
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
			ret = setgid (atoi (p->_setgid));
			if (ret < 0)
				return 1;
		}
		if (p->_pid) {
			eprintf ("PID: %d\n", getpid ());
		}
#endif
		exit (execv (p->_program, (char* const*)p->_args));
	}
	return 0;
}
