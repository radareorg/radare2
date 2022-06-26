/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_cons.h>
#include <r_th.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif

// cons_pipe should be using a stack pipe_push, pipe_pop
static R_TH_LOCAL int backup_fd = -1;
static R_TH_LOCAL int backup_fdn = 1;

static bool __dupDescriptor(int fd, int fdn) {
	if (fd == fdn) {
		return false;
	}
#if __wasi__
	return false;
#elif __WINDOWS__
	backup_fd = 2002 - (fd - 2); // windows xp has 2048 as limit fd
	return _dup2 (fdn, backup_fd) != -1;
#else
	backup_fd = sysconf (_SC_OPEN_MAX) - (fd - 2); // portable getdtablesize()
	if (backup_fd < 2) {
		backup_fd = 2002 - (fd - 2); // fallback
	}
	return dup2 (fdn, backup_fd) != -1;
#endif
}

R_API int r_cons_pipe_open(const char *file, int fdn, int append) {
#if __wasi__
	return -1;
#else
	if (fdn < 1) {
		return -1;
	}
	char *targetFile = (!strncmp (file, "~/", 2) || !strncmp (file, "~\\", 2))
		? r_str_home (file + 2): strdup (file);
	const int fd_flags = O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC);
	int fd = r_sandbox_open (targetFile, fd_flags, 0644);
	if (fd == -1) {
		R_LOG_ERROR ("Cannot open file '%s'", file);
		free (targetFile);
		return -1;
	}
	if (backup_fd != -1) {
		close (backup_fd);
		// already set in __dupDescriptor // backup_fd = -1;
	}
	backup_fdn = fdn;
	if (!__dupDescriptor (fd, fdn)) {
		R_LOG_ERROR ("Cannot dup stdout to %d", fdn);
		free (targetFile);
		return -1;
	}
	close (fdn);
	dup2 (fd, fdn);
	free (targetFile);
	return fd;
#endif
}

R_API void r_cons_pipe_close(int fd) {
#if !__wasi__
	if (fd != -1) {
		close (fd);
		if (backup_fd != -1) {
			dup2 (backup_fd, backup_fdn);
			close (backup_fd);
			backup_fd = -1;
		}
	}
#endif
}
