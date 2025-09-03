/* radare - LGPL - Copyright 2012-2024 - pancake */

#include <r_util.h>
#include <signal.h>
#if _MSC_VER
#include <process.h> // to compile execl under msvc windows
#include <direct.h>  // to compile chdir under msvc windows
#endif

#if HAVE_CAPSICUM
#include <sys/capsicum.h>
#endif

#if LIBC_HAVE_PRIV_SET
#include <priv.h>
#endif

static R_TH_LOCAL bool G_enabled = false;
static R_TH_LOCAL bool G_disabled = false;
static R_TH_LOCAL int G_graintype = R_SANDBOX_GRAIN_NONE;

#define R_SANDBOX_GUARD(x,y) if (G_enabled && !(G_graintype & (x))) { return (y); }

static bool inHomeWww(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, false);
	bool ret = false;
	char *homeWww = r_xdg_datadir ("www");
	if (homeWww) {
		if (r_str_startswith (path, homeWww)) {
			ret = true;
		}
		free (homeWww);
	}
	return ret;
}

/**
 * This function verifies that the given path is allowed. Paths are allowed only if they don't
 * contain .. components (which would indicate directory traversal) and they are relative.
 * Paths pointing into the webroot are an exception: For reaching the webroot, .. and absolute
 * path are ok.
 */
R_API bool r_sandbox_check_path(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, false);
	size_t root_len;
	char *p;
	/* XXX: the sandbox can be bypassed if a directory is symlink */
	root_len = strlen (R2_LIBDIR"/radare2");
	if (!strncmp (path, R2_LIBDIR"/radare2", root_len)) {
		return true;
	}
	root_len = strlen (R2_DATDIR"/radare2");
	if (!strncmp (path, R2_DATDIR"/radare2", root_len)) {
		return true;
	}
	if (inHomeWww (path)) {
		return true;
	}
	// Accessing stuff inside the webroot is ok even if we need .. or leading / for that
	root_len = strlen (R2_WWWROOT);
	if (R2_WWWROOT[0] && !strncmp (path, R2_WWWROOT, root_len) && (
			R2_WWWROOT[root_len-1] == '/' || path[root_len] == '/' || path[root_len] == '\0')) {
		path += strlen (R2_WWWROOT);
		while (*path == '/') {
			path++;
		}
	}

	// ./ path is not allowed
	if (path[0] == '.' && path[1] == '/') {
		return false;
	}
	// Properly check for directory traversal using "..". First, does it start with a .. part?
	if (path[0] == '.' && path[1] == '.' && (path[2] == '\0' || path[2] == '/')) {
		return 0;
	}

	// Or does it have .. in some other position?
	for (p = strstr (path, "/.."); p; p = strstr (p, "/..")) {
		if (p[3] == '\0' || p[3] == '/') {
			return false;
		}
	}
	// Absolute paths are forbidden.
	if (*path == '/') {
		return false;
	}
#if R2__UNIX__
	char ch;
	if (readlink (path, &ch, 1) != -1) {
		return false;
	}
#endif
	return true;
}

R_API bool r_sandbox_disable(bool e) {
	if (e) {
#if LIBC_HAVE_PLEDGE
		if (G_enabled) {
			R_LOG_ERROR ("sandbox mode couldn't be G_disabled when pledged");
			return G_enabled;
		}
#endif
#if HAVE_CAPSICUM
		if (G_enabled) {
			R_LOG_ERROR ("sandbox mode couldn't be G_disabled in capability mode");
			return G_enabled;
		}
#endif
#if LIBC_HAVE_PRIV_SET
		if (G_enabled) {
			R_LOG_ERROR ("sandbox mode couldn't be G_disabled in priv mode");
			return G_enabled;
		}
#endif
		G_disabled = G_enabled;
		G_enabled = false;
	} else {
		G_enabled = G_disabled;
		G_disabled = false;
	}
	return G_enabled;
}

R_API int r_sandbox_grain(int mask) {
	int old_grain = G_graintype;
	G_graintype = (mask & R_SANDBOX_GRAIN_ALL);
	return old_grain;
}

R_API bool r_sandbox_check(int mask) {
	if (r_sandbox_enable (0)) {
		R_SANDBOX_GUARD (mask, false);
	}
	return true;
}

R_API bool r_sandbox_enable(bool e) {
	if (G_enabled) {
		if (!e) {
			// R_LOG_ERROR ("Can't disable sandbox");
		}
		return true;
	}
	G_graintype = R_SANDBOX_GRAIN_ALL;
	G_enabled = e;
#if LIBC_HAVE_PLEDGE
	if (G_enabled && pledge ("stdio rpath tty prot_exec inet", NULL) == -1) {
		R_LOG_ERROR ("sandbox: pledge call failed");
		return false;
	}
#endif
#if HAVE_CAPSICUM
	if (G_enabled) {
#if __FreeBSD_version >= 1000000
		cap_rights_t wrt, rdr;

		if (!cap_rights_init (&wrt, CAP_READ, CAP_WRITE)) {
			R_LOG_ERROR ("sandbox: write descriptor failed");
			return false;
		}

		if (!cap_rights_init (&rdr, CAP_READ, CAP_EVENT, CAP_FCNTL)) {
			R_LOG_ERROR ("sandbox: read descriptor failed");
			return false;
		}

		if (cap_rights_limit (STDIN_FILENO, &rdr) == -1) {
			R_LOG_ERROR ("sandbox: stdin protection failed");
			return false;
		}

		if (cap_rights_limit (STDOUT_FILENO, &wrt) == -1) {
			R_LOG_ERROR ("sandbox: stdout protection failed");
			return false;
		}

		if (cap_rights_limit (STDERR_FILENO, &wrt) == -1) {
			R_LOG_ERROR ("sandbox: stderr protection failed");
			return false;
		}
#endif

		if (cap_enter () != 0) {
			R_LOG_ERROR ("sandbox: call_enter failed");
			return false;
		}
	}
#endif
#if LIBC_HAVE_PRIV_SET
	if (G_enabled) {
		priv_set_t *priv = priv_allocset();
		const char *const privrules[] = {
			PRIV_PROC_INFO,
			PRIV_PROC_SESSION,
			PRIV_PROC_ZONE,
			PRIV_NET_OBSERVABILITY
		};

		size_t i, privrulescnt = sizeof (privrules) / sizeof (privrules[0]);
		if (!priv) {
			R_LOG_ERROR ("sandbox: priv_allocset failed");
			return false;
		}
		priv_basicset (priv);
		for (i = 0; i < privrulescnt; i ++) {
			if (priv_delset (priv, privrules[i]) != 0) {
				priv_emptyset (priv);
				priv_freeset (priv);
				R_LOG_ERROR ("sandbox: priv_delset failed");
				return false;
			}
		}

		priv_freeset (priv);
	}
#endif
	return G_enabled;
}

static inline int bytify(int v) {
#if R2__WINDOWS__ || __wasi__
	// on windows, there are no WEXITSTATUS, the return value is right there
	unsigned int uv = (unsigned int)v;
	return (int) ((uv > 255)? 1: 0);
#else
	// on unix, return code is (system() >> 8) & 0xff
	if (v == -1 || WIFEXITED (v)) {
		return WEXITSTATUS (v);
	}
#endif
	return 1;
}

R_API int r_sandbox_system(const char *x, int n) {
	R_RETURN_VAL_IF_FAIL (x, -1);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_EXEC, -1);
	if (G_enabled) {
		R_LOG_ERROR ("sandbox: system call disabled");
		return bytify (-1);
	}
#if R2__WINDOWS__
	return system (x);
#elif LIBC_HAVE_FORK
#if LIBC_HAVE_SYSTEM
	if (n) {
#if APPLE_SDK_IPHONEOS
#include <spawn.h>
		int argc;
		char *cmd = strdup (x);
		char **argv = r_str_argv (cmd, &argc);
		if (argv) {
			char *argv0 = r_file_path (argv[0]);
			pid_t pid = 0;
			int r = posix_spawn (&pid, argv0, NULL, NULL, argv, NULL);
			if (r != 0) {
				return bytify (-1);
			}
			int status;
			int s = waitpid (pid, &status, 0);
			return bytify (WEXITSTATUS (s));
		}
		int child = fork ();
		if (child == -1) {
			return bytify (-1);
		}
		if (child) {
			return bytify (waitpid (child, NULL, 0));
		}
#else
		// the most common execution path
		return bytify (system (x));
#endif
	}
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
				R_LOG_ERROR ("Cannot find '%s'", argv[0]);
				return bytify (-1);
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
			return bytify (rc);
		}
		R_LOG_ERROR ("parsing command arguments");
		return bytify (-1);
	}
#endif
	char *bin_sh = r_file_binsh ();
	int rc = execl (bin_sh, bin_sh, "-c", x, (const char*)NULL);
	if (rc == -1) {
		r_sys_perror ("execl");
	}
	free (bin_sh);
	exit (bytify (rc));
#endif
	return bytify (-1);
}

R_API bool r_sandbox_creat(const char *path, int mode) {
	if (G_enabled) {
		return false;
#if 0
		if (mode & O_CREAT) {
			return -1;
		}
		if (mode & O_RDWR) {
			return -1;
		}
		if (!r_sandbox_check_path (path)) {
			return -1;
		}
#endif
	}
	int fd = open (path, O_CREAT | O_TRUNC | O_WRONLY, mode);
	if (fd != -1) {
		close (fd);
		return true;
	}
	return false;
}

static inline char *expand_home(const char *p) {
	return (*p == '~')? r_file_home (p): strdup (p);
}

R_API int r_sandbox_lseek(int fd, ut64 addr, int whence) {
	if (G_enabled) {
		return -1;
	}
	return lseek (fd, (off_t)addr, whence);
}

R_API int r_sandbox_truncate(int fd, ut64 length) {
	if (G_enabled) {
		return -1;
	}
#ifdef _MSC_VER
	return _chsize_s (fd, length);
#else
	return ftruncate (fd, (off_t)length);
#endif
}

R_API int r_sandbox_read(int fd, ut8 *buf, int len) {
	return G_enabled? -1: read (fd, buf, len);
}

R_API int r_sandbox_write(int fd, const ut8* buf, int len) {
	return G_enabled? -1: write (fd, buf, len);
}

R_API int r_sandbox_close(int fd) {
	return G_enabled? -1: close (fd);
}

/* perm <-> mode */
R_API int r_sandbox_open(const char *path, int perm, int mode) {
	R_RETURN_VAL_IF_FAIL (path, -1);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_DISK, -1);
	char *epath = expand_home (path);
	int ret = -1;
#if R2__WINDOWS__
	if (!strcmp (path, "/dev/null")) {
		path = "NUL";
	}
#endif
	if (G_enabled) {
		if ((perm & O_CREAT) || (perm & O_RDWR)
			|| (!r_sandbox_check_path (epath))) {
			free (epath);
			return -1;
		}
	}
#if R2__WINDOWS__
	{
		DWORD flags = 0;
		if (perm & O_RANDOM) {
			flags = FILE_FLAG_RANDOM_ACCESS;
		} else if (perm & O_SEQUENTIAL) {
			flags = FILE_FLAG_SEQUENTIAL_SCAN;
		}
		if (perm & O_TEMPORARY) {
			flags |= FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_TEMPORARY;
		} else if (perm & _O_SHORT_LIVED) {
			flags |= FILE_ATTRIBUTE_TEMPORARY;
		} else {
			flags |= FILE_ATTRIBUTE_NORMAL;
		}
		DWORD creation = 0;
		bool read_only = false;
		if (perm & O_CREAT) {
			if (perm & O_EXCL) {
				creation = CREATE_NEW;
			} else {
				creation = OPEN_ALWAYS;
			}
			if (mode & S_IREAD && !(mode & S_IWRITE)) {
				flags = FILE_ATTRIBUTE_READONLY;
				read_only = true;
			}
		} else if (perm & O_TRUNC) {
			creation = TRUNCATE_EXISTING;
		}
		if (!creation || !strcasecmp ("NUL", path)) {
			creation = OPEN_EXISTING;
		}
		DWORD permission = 0;
		if (perm & O_WRONLY) {
			permission = GENERIC_WRITE;
		} else if (perm & O_RDWR) {
			permission = GENERIC_WRITE | GENERIC_READ;
		} else {
			permission = GENERIC_READ;
		}
		if (perm & O_APPEND) {
			permission |= FILE_APPEND_DATA;
		}

		wchar_t *wepath = r_utf8_to_utf16 (epath);
		if (!wepath) {
			free (epath);
			return -1;
		}
		HANDLE h = CreateFileW (wepath, permission, FILE_SHARE_READ | (read_only ? 0 : FILE_SHARE_WRITE), NULL, creation, flags, NULL);
		if (h != INVALID_HANDLE_VALUE) {
			ret = _open_osfhandle ((intptr_t)h, perm);
		}
		free (wepath);
	}
#else // R2__WINDOWS__
	ret = open (epath, perm, mode);
#endif // R2__WINDOWS__
	free (epath);
	return ret;
}

R_API FILE *r_sandbox_fopen(const char *path, const char *mode) {
	R_RETURN_VAL_IF_FAIL (path && mode, NULL);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK, NULL);
	FILE *ret = NULL;
	char *epath = NULL;
	if (G_enabled) {
		if (strchr (mode, 'w') || strchr (mode, 'a') || strchr (mode, '+')) {
			return NULL;
		}
		epath = expand_home (path);
		if (!r_sandbox_check_path (epath)) {
			free (epath);
			return NULL;
		}
	}
	if (!epath) {
		epath = expand_home (path);
	}
	if ((strchr (mode, 'w') || strchr (mode, 'a') || r_file_is_regular (epath))) {
#if R2__WINDOWS__
		wchar_t *wepath = r_utf8_to_utf16 (epath);
		if (wepath) {
			wchar_t *wmode = r_utf8_to_utf16 (mode);
			if (wmode) {
				ret = _wfopen (wepath, wmode);
				free (wmode);
			}
			free (wepath);
		}
#else // R2__WINDOWS__
		ret = fopen (epath, mode);
#endif // R2__WINDOWS__
	}
	free (epath);
	return ret;
}

R_API int r_sandbox_chdir(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, -1);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK, -1);
	if (G_enabled) {
		// TODO: check path
		if (strstr (path, "../")) {
			return -1;
		}
		if (*path == '/') {
			return -1;
		}
		return -1;
	}
	return chdir (path);
}

R_API int r_sandbox_kill(int pid, int sig) {
	R_RETURN_VAL_IF_FAIL (pid != -1, -1);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_EXEC, -1);
	// XXX: fine-tune. maybe we want to enable kill for child?
	if (G_enabled) {
		return -1;
	}
#if HAVE_SYSTEM && R2__UNIX__
	int ret = kill (pid, sig);
	const bool sync_kill = false;
	if (sync_kill) {
		waitpid (pid, NULL, 0);
	}
	return ret;
#endif
	return -1;
}
#if R2__WINDOWS__
R_API HANDLE r_sandbox_opendir(const char *path, WIN32_FIND_DATAW *entry) {
	R_RETURN_VAL_IF_FAIL (path, NULL);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK, NULL);
	wchar_t dir[MAX_PATH];
	wchar_t *wcpath = 0;
	if (r_sandbox_enable (0)) {
		if (path && !r_sandbox_check_path (path)) {
			return NULL;
		}
	}
	if (!(wcpath = r_utf8_to_utf16 (path))) {
		return NULL;
	}
	swprintf (dir, MAX_PATH, L"%ls\\*.*", wcpath);
	free (wcpath);
	return FindFirstFileW (dir, entry);
}
#else
R_API DIR* r_sandbox_opendir(const char *path) {
	R_RETURN_VAL_IF_FAIL (path, NULL);
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_FILES | R_SANDBOX_GRAIN_DISK, NULL);
	if (r_sandbox_enable (0)) {
		if (path && !r_sandbox_check_path (path)) {
			return NULL;
		}
	}
	return opendir (path);
}
#endif
R_API bool r_sys_stop(void) {
	R_SANDBOX_GUARD (R_SANDBOX_GRAIN_EXEC, false);
	if (G_enabled) {
		return false;
	}
#if R2__UNIX__
	return !r_sandbox_kill (0, SIGTSTP);
#else
	return false;
#endif
}
