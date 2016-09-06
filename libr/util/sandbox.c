/* radare - LGPL - Copyright 2012-2016 - pancake */

#include <r_util.h>
#include <signal.h>

static bool enabled = false;
static bool disabled = false;

/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * path are ok.
 */
R_API int r_sandbox_check_path (const char *path) {
	size_t root_len;
	char ch;
	char *p;
	/* XXX: the sandbox can be bypassed if a directory is symlink */

	if (!path) return 0;

	root_len = strlen (R2_LIBDIR"/radare2");
	if (!strncmp (path, R2_LIBDIR"/radare2", root_len))
		return 1;
	root_len = strlen (R2_DATDIR"/radare2");
	if (!strncmp (path, R2_DATDIR"/radare2", root_len))
		return 1;
	// Accessing stuff inside the webroot is ok even if we need .. or leading / for that
	root_len = strlen (R2_WWWROOT);
	if (R2_WWWROOT[0] && !strncmp (path, R2_WWWROOT, root_len) && (
			R2_WWWROOT[root_len-1] == '/' || path[root_len] == '/' || path[root_len] == '\0')) {
		path += strlen (R2_WWWROOT);
		while (*path == '/') path++;
	}

	// ./ path is not allowed
        if (path[0]=='.' && path[1]=='/') return 0;
	// Properly check for directrory traversal using "..". First, does it start with a .. part?
        if (path[0]=='.' && path[1]=='.' && (path[2]=='\0' || path[2]=='/')) return 0;

	// Or does it have .. in some other position?
	for (p = strstr (path, "/.."); p; p = strstr(p, "/.."))
		if (p[3] == '\0' || p[3] == '/') return 0;

	// Absolute paths are forbidden.
	if (*path == '/') return 0;
#if __UNIX__
	if (readlink (path, &ch, 1) != -1) return 0;
#endif
	return true;
}

R_API bool r_sandbox_disable (bool e) {
	if (e) {
#if LIBC_HAVE_PLEDGE
		if (enabled) {
			eprintf ("sandbox mode couldn't be disabled when pledged\n");
			return enabled;
		}
#endif
		disabled = enabled;
		enabled = 0;
	} else {
		enabled = disabled;
	}
	return enabled;
}

R_API bool r_sandbox_enable (bool e) {
	if (enabled) {
		return true;
	}
	enabled = !!e;
#if LIBC_HAVE_PLEDGE
	if (enabled && pledge ("stdio rpath tty prot_exec", NULL) == -1) {
		eprintf ("sandbox: pledge call failed\n");
		exit (1);
	}
#endif
	return enabled;
}

R_API int r_sandbox_system (const char *x, int n) {
	if (enabled) {
		eprintf ("sandbox: system call disabled\n");
		return -1;
	}
#if LIBC_HAVE_FORK
#if LIBC_HAVE_SYSTEM
	if (n) return system (x);
	return execl ("/bin/sh", "sh", "-c", x, (const char*)NULL);
#else
	#include <spawn.h>
	if (n && !strchr (x, '|')) {
		char **argv, *cmd = strdup (x);
		int rc, pid, argc;
		char *isbg = strchr (cmd, '&');
		// XXX this is hacky
		if (isbg) {
			*isbg = 0;
		}
		argv = r_str_argv (cmd, &argc);
		if (argv) {
			char *argv0 = r_file_path (argv[0]);
			if (!argv0) {
				eprintf ("Cannot find '%s'\n", argv[0]);
				return -1;
			}
			pid = 0;
			posix_spawn (&pid, argv0, NULL, NULL, argv, NULL);
			if (isbg) {
				// XXX. wait for children
				rc = 0;
			} else {
				rc = waitpid (pid, NULL, 0);
			}
			r_str_argv_free (argv);
			free (argv0);
			return rc;
		}
		eprintf ("Error parsing command arguments\n");
		return -1;
	}
	int child = fork();
	if (child == -1) return -1;
	if (child) {
		return waitpid (child, NULL, 0);
	}
	execl ("/bin/sh", "sh", "-c", x, (const char*)NULL);
	exit (1);
#endif
#endif
	return -1;
}

R_API bool r_sandbox_creat (const char *path, int mode) {
	if (enabled) {
		return false;
#if 0
		if (mode & O_CREAT) return -1;
		if (mode & O_RDWR) return -1;
		if (!r_sandbox_check_path (path))
			return -1;
#endif
	}
	int fd = open (path, O_CREAT | O_TRUNC | O_WRONLY, mode);
	if (fd != -1) {
		close (fd);
		return true;
	}
	return false;
}

static char *expand_home(const char *p) {
	if (*p == '~') {
		return r_str_home (p);
	}
	return strdup (p);
}

R_API int r_sandbox_lseek (int fd, ut64 addr, int whence) {
	if (enabled) {
		return -1;
	}
	return lseek (fd, (off_t)addr, whence);
}

R_API int r_sandbox_read (int fd, ut8* buf, int len) {
	return enabled? -1 : read (fd, buf, len);
}

R_API int r_sandbox_write (int fd, const ut8* buf, int len) {
	return enabled? -1 : write (fd, buf, len);
}

R_API int r_sandbox_close (int fd) {
	return enabled? -1 : close (fd);
}

/* perm <-> mode */
R_API int r_sandbox_open (const char *path, int mode, int perm) {
	if (!path) {
		return -1;
	}
	char *epath = expand_home (path);
#if __WINDOWS__
	mode |= O_BINARY;
#endif
	if (enabled) {
		if ((mode & O_CREAT)
		|| (mode & O_RDWR)
		|| (!r_sandbox_check_path (epath))) {
			free (epath);
			return -1;
		}
	}
	int ret = open (epath, mode, perm);
	free (epath);
	return ret;
}

R_API FILE *r_sandbox_fopen (const char *path, const char *mode) {
	FILE *ret = NULL;
	char *epath = NULL;
	if (!path)
		return NULL;
	if (enabled) {
		if (strchr (mode, 'w') || strchr (mode, 'a') || strchr (mode, '+'))
			return NULL;
		epath = expand_home (path);
		if (!r_sandbox_check_path (epath)) {
			free (epath);
			return NULL;
		}
	}
	if (!epath)
		epath = expand_home (path);
	if ((strchr (mode, 'w') || r_file_is_regular (epath)))
		ret = fopen (epath, mode);
	free (epath);
	return ret;
}

R_API int r_sandbox_chdir (const char *path) {
	if (enabled) {
		// TODO: check path
		if (strstr (path, "../")) return -1;
		if (*path == '/') return -1;
		return -1;
	}
	return chdir (path);
}

R_API int r_sandbox_kill(int pid, int sig) {
	// XXX: fine-tune. maybe we want to enable kill for child?
	if (enabled) return -1;
#if __UNIX__
	if (pid > 0) {
		return kill (pid, sig);
	}
	// eprintf ("r_sandbox_kill: Better not to kill pids <= 0.\n");
#endif
	return -1;
}

R_API DIR* r_sandbox_opendir (const char *path) {
	if (!path)
		return NULL;
	if (r_sandbox_enable (0)) {
		if (path && !r_sandbox_check_path (path)) {
			return NULL;
		}
	}
	return opendir (path);
}

R_API int r_sys_stop () {
	int pid;
	if (enabled) {
		return false;
	}
	pid = r_sys_getpid ();
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
	return (!r_sandbox_kill (pid, SIGSTOP));
}
