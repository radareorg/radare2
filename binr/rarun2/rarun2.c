/* radare2 - Copyleft 2011-2014 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <r_util.h>
#include <r_socket.h>
#if __UNIX__
#include <sys/resource.h>
#include <signal.h>
#endif

#define NARGS (sizeof (_args)/sizeof(*_args))
static char *_args[512] = {NULL};
static char *_system = NULL;
static char *_program = NULL;
static char *_stdin = NULL;
static char *_stdout = NULL;
static char *_stderr = NULL;
static char *_chgdir = NULL;
static char *_chroot = NULL;
static char *_libpath = NULL;
static char *_preload = NULL;
static int _r2preload = 0;
static int _docore = 0;
static int _aslr = -1;
static int _maxstack = 0;
static int _maxproc = 0;
static int _maxfd = 0;
static int _r2sleep = 0;
static char *_setuid = NULL;
static char *_seteuid = NULL;
static char *_setgid = NULL;
static char *_setegid = NULL;
static char *_input = NULL;
static char *_connect = NULL;
static char *_listen = NULL;
static int _timeout = 0;

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
		// slurp file
		return r_file_slurp (src+1, NULL);
	case ':':
		// hexpairs
		ret = strdup (src);
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
		if (personality (ADDR_NO_RANDOMIZE) == -1)
			system ("echo 0 > "RVAS);
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

static void parseline (char *b) {
	int must_free = R_FALSE;
	char *e = strchr (b, '=');
	if (!e) return;
	if (*b=='#') return;
	*e++ = 0;
	if (*e=='$') {
		must_free = R_TRUE;
		e = r_sys_getenv (e);
	}
	if (e == NULL) return;
	if (!strcmp (b, "program")) _args[0] = _program = strdup (e);
	else if (!strcmp (b, "system")) _system = strdup (e);
	else if (!strcmp (b, "aslr")) _aslr = parseBool (e);
	else if (!strcmp (b, "connect")) _connect = strdup (e);
	else if (!strcmp (b, "listen")) _listen = strdup (e);
	else if (!strcmp (b, "stdout")) _stdout = strdup (e);
	else if (!strcmp (b, "stdio")) {
		_stdout = _stderr = _stdin = strdup (e);
	} else if (!strcmp (b, "stdin")) _stdin = strdup (e);
	else if (!strcmp (b, "stderr")) _stderr = strdup (e);
	else if (!strcmp (b, "input")) _input = strdup (e);
	else if (!strcmp (b, "chdir")) _chgdir = strdup (e);
	else if (!strcmp (b, "core")) _docore = parseBool (e);
	else if (!strcmp (b, "sleep")) _r2sleep = atoi (e);
	else if (!strcmp (b, "maxstack")) _maxstack = atoi (e);
	else if (!strcmp (b, "maxproc")) _maxproc = atoi (e);
	else if (!strcmp (b, "maxfd")) _maxfd = atoi (e);
	else if (!strcmp (b, "chroot")) _chroot = strdup (e);
	else if (!strcmp (b, "libpath")) _libpath = strdup (e);
	else if (!strcmp (b, "preload")) _preload = strdup (e);
	else if (!strcmp (b, "r2preload")) _r2preload = parseBool (e);
	else if (!strcmp (b, "setuid")) _setuid = strdup (e);
	else if (!strcmp (b, "seteuid")) _seteuid = strdup (e);
	else if (!strcmp (b, "setgid")) _setgid = strdup (e);
	else if (!strcmp (b, "setegid")) _setegid = strdup (e);
	else if (!memcmp (b, "arg", 3)) {
		int n = atoi (b+3);
		if (n>=0 && n<NARGS) {
			_args[n] = getstr (e);
		} else eprintf ("Out of bounds args index: %d\n", n);
	} else if (!strcmp (b, "timeout")) {
		_timeout = atoi (e);
	} else if (!strcmp (b, "envfile")) {
		char *p, buf[1024];
		FILE *fd = fopen (e, "r");
		if (!fd) {
			eprintf ("Cannot open '%s'\n", e);
			if (must_free == R_TRUE)
				free (e);
			return;
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

static int runfile () {
	int ret;
	if (!_program && !_system) {
		printf ("No program or system rule defined\n");
		return 1;
	}
	if (_stdin) {
		int f = open (_stdin, O_RDONLY);
		if (f < 0)
			return 1;
		close (0);
		dup2 (f, 0);
	}
	if (_stdout) {
		int f = open (_stdout, O_WRONLY);
		if (f < 0)
			return 1;
		close (1);
		dup2 (f, 1);
	}
	if (_stderr) {
		int f = open (_stderr, O_WRONLY);
		if (f < 0)
			return 1;
		close (2);
		dup2 (f, 2);
	}
	if (_aslr != -1)
		setASLR (_aslr);
#if __UNIX__
	set_limit (_docore, RLIMIT_CORE, RLIM_INFINITY);
	set_limit (_maxfd, RLIMIT_NOFILE, _maxfd);
#ifdef RLIMIT_NPROC
	set_limit (_maxproc, RLIMIT_NPROC, _maxproc);
#endif
	set_limit (_maxstack, RLIMIT_STACK, _maxstack);
#else
	if (_docore || _maxfd || _maxproc || _maxstack)
		eprintf ("Warning: setrlimits not supported for this platform\n");
#endif

	if (_connect) {
		char *p = strchr (_connect, ':');
		if (p) {
			RSocket *fd = r_socket_new (0);
			*p=0;
			if (!r_socket_connect_tcp (fd, _connect, p+1, 30)) {
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
	if (_listen) {
		RSocket *child, *fd = r_socket_new (0);
		if (!r_socket_listen (fd, _listen, NULL)) {
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
	if (_r2sleep != 0) {
		r_sys_sleep (_r2sleep);
	}
	if (_chgdir) {
		ret = chdir (_chgdir);
		if (ret < 0)
			return 1;
	}
	if (_chroot) {
		ret = chdir (_chroot);
		if (ret < 0)
			return 1;
	}
#if __UNIX__
	if (_chroot) {
		if (chroot (_chroot)) {
			eprintf ("rarun2: cannot chroot\n");
			return 1;
		}
	}
	if (_setuid) {
		ret = setuid (atoi (_setuid));
		if (ret < 0)
			return 1;
	}
	if (_seteuid) {
		ret = seteuid (atoi (_seteuid));
		if (ret < 0)
			return 1;
	}
	if (_setgid) {
		ret = setgid (atoi (_setgid));
		if (ret < 0)
			return 1;
	}
	if (_input) {
		int f2[2];
		pipe (f2);
		close (0);
		dup2 (f2[0], 0);
		parseinput (_input);
		write (f2[1], _input, strlen (_input));
	}
#endif
	if (_r2preload) {
		if (_preload) {
			eprintf ("WARNING: Only one library can be opened at a time\n");
		}
		_preload = R2_LIBDIR"/libr2."R_LIB_EXT;
	}
	if (_libpath) {
#if __WINDOWS__
		eprintf ("rarun2: libpath unsupported for this platform\n");
#elif __HAIKU__
		r_sys_setenv ("LIBRARY_PATH", _libpath);
#elif __APPLE__
		r_sys_setenv ("DYLD_LIBRARY_PATH", _libpath);
#else
		r_sys_setenv ("LD_LIBRARY_PATH", _libpath);
#endif
	}
	if (_preload) {
#if __APPLE__
		// 10.6
		r_sys_setenv ("DYLD_PRELOAD", _preload);
		r_sys_setenv ("DYLD_INSERT_LIBRARIES", _preload);
		// 10.8
		r_sys_setenv ("DYLD_FORCE_FLAT_NAMESPACE", "1");
#else
		r_sys_setenv ("LD_PRELOAD", _preload);
#endif
	}
	if (_timeout) {
#if __UNIX__
		int mypid = getpid ();
		if (!fork ()) {
			sleep (_timeout);
			if (!kill (mypid, 0))
				eprintf ("\nrarun2: Interrupted by timeout\n");
			kill (mypid, SIGKILL);
			exit (0);
		}
#else
		eprintf ("timeout not supported for this platform\n");
#endif
	}
	if (_system) {
		exit (r_sys_cmd (_system));
	}
	if (!r_file_exists (_program)) {
		eprintf ("rarun2: %s: file not found\n", _program);
		return 1;
	}
	exit (execv (_program, _args));
}

int main(int argc, char **argv) {
	int i;
	FILE *fd;
	char *file, buf[4096];
	if (argc==1 || !strcmp (argv[1], "-h")) {
		eprintf ("Usage: rarun2 [-v] [script.rr2] [directive ..]\n");
		printf (
			"program=/bin/ls\n"
			"arg1=/bin\n"
			"# arg2=hello\n"
			"# arg3=\"hello\\nworld\"\n"
			"# arg4=:048490184058104849\n"
			"# arg4=@arg.txt\n"
			"# system=r2 -\n"
			"# aslr=no\n"
			"setenv=FOO=BAR\n"
			"# unsetenv=FOO\n"
			"# envfile=environ.txt\n"
			"timeout=3\n"
			"# connect=localhost:8080\n"
			"# listen=8080\n"
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
			"# setegid=2001\n");
		return 1;
	}
	if (!strcmp (argv[1], "-v")) {
		printf ("rarun2 "R2_VERSION"\n");
		return 0;
	}
	file = argv[1];
	if (*file && !strchr (file, '=')) {
		fd = fopen (file, "r");
		if (!fd) {
			eprintf ("Cannot open %s\n", file);
			return 1;
		}
		for (;;) {
			fgets (buf, sizeof (buf)-1, fd);
			if (feof (fd)) break;
			buf[strlen (buf)-1] = 0;
			parseline (buf);
		}
		fclose (fd);
	} else {
		for (i=*file?1:2; i<argc; i++)
			parseline (argv[i]);
	}
	return runfile ();
}
