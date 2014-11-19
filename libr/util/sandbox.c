/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_util.h>
#include <signal.h>

static int enabled = 0;
static int disabled = 0;

/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * paths are ok.
 */
R_API int r_sandbox_check_path (const char *path) {
	char ch;
	char *p;
	/* XXX: the sandbox can be bypassed if a directory is symlink */

	if (!path) return 0;

	// Accessing stuff inside the webroot is ok even if we need .. or leading / for that
	size_t root_len = strlen (R2_WWWROOT);
	if (R2_WWWROOT[0] && !strncmp (path, R2_WWWROOT, root_len) && (
			R2_WWWROOT[root_len-1] == '/' || path[root_len] == '/' || path[root_len] == '\0')) {
		path += strlen (R2_WWWROOT);
		while (*path == '/') path++;
	}

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
	return R_TRUE;
}

R_API int r_sandbox_disable (int e) {
	if (e) {
		disabled = enabled;
		enabled = 0;
	} else {
		enabled = disabled;
	}
	return enabled;
}

R_API int r_sandbox_enable (int e) {
	if (enabled) return R_TRUE;
	return (enabled = !!e);
}

R_API int r_sandbox_system (const char *x, int n) {
	if (!enabled) {
		if (n) return system (x);
		return execl ("/bin/sh", "sh", "-c", x, (const char*)NULL);
	}
	eprintf ("sandbox: system call disabled\n");
	return -1;
}

R_API int r_sandbox_creat (const char *path, int mode) {
	if (enabled) {
		if (mode & O_CREAT) return -1;
		if (mode & O_RDWR) return -1;
		if (!r_sandbox_check_path (path))
			return -1;
	}
	return creat (path, mode);
}

static char *expand_home(const char *p) {
	if (*p=='~')
		return r_str_home (p);
	return strdup (p);
}

R_API int r_sandbox_open (const char *path, int mode, int perm) {
	int ret;
	char *epath;
	if (!path) return -1;
	epath = expand_home (path);
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
	ret = open (epath, mode, perm);
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
	if (pid>0) return kill (pid, sig);
	eprintf ("r_sandbox_kill: Better not to kill pids <= 0.\n");
#endif
	return -1;
}

R_API DIR* r_sandbox_opendir (const char *path) {
	if (!path || (r_sandbox_enable (0) && !r_sandbox_check_path (path)))
		return NULL;
	return opendir (path);
}

R_API int r_sys_stop () {
	if (enabled) return R_FALSE;
	int pid = r_sys_getpid ();
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
	if (!r_sandbox_kill (pid, SIGSTOP))
		return R_TRUE;
	return R_FALSE;
}
