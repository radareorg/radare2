/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_util.h>
#include <signal.h>

static int enabled = 0;

R_API int r_sandbox_check_path (const char *path) {
	char ch;
	/* XXX: the sandbox can be bypassed if a directory is symlink */
	if (!memcmp (path, WWWROOT, strlen (WWWROOT)))
		return R_TRUE;
	if (strstr (path, "../")) return 0;
	if (*path == '/') return 0;
#if __UNIX__
	if (readlink (path, &ch, 1) != -1) return 0;
#endif
	return R_TRUE;
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

R_API int r_sandbox_open (const char *path, int mode, int perm) {
#if __WINDOWS__
	mode |= O_BINARY;
#endif
	if (enabled) {
		if (mode & O_CREAT) return -1;
		if (mode & O_RDWR) return -1;
		if (!r_sandbox_check_path (path))
			return -1;
	}
#if __WINDOWS__
	perm = 0;
#endif
	return open (path, mode, perm);
}

R_API FILE *r_sandbox_fopen (const char *path, const char *mode) {
	if (enabled) {
		if (strchr (mode, 'w') || strchr (mode, 'a') || strchr (mode, '+'))
			return NULL;
		if (!r_sandbox_check_path (path))
			return NULL;
	}
	return fopen (path, mode);
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
	if (pid>=0) return kill (pid, sig);
	eprintf ("r_sandbox_kill: Better not to kill negative pids.\n");
#endif
	return -1;
}
