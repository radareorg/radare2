/* radare - LGPL - Copyright 2009-2019 - pancake */

#include <r_cons.h>
#include <limits.h>

// TODO: kill globals, and make this stackable
// cons_pipe should be using a stack pipe_push, pipe_pop
static int backup_fd = -1;
static int backup_fdn = 1;

#ifndef O_BINARY
#define O_BINARY 0
#endif

static bool __dupDescriptor(int fd, int fdn) {
#if __WINDOWS__
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
	if (fdn < 1) {
		return -1;
	}
	char *targetFile = (!strncmp (file, "~/", 2) || !strncmp (file, "~\\", 2))
		? r_str_home (file + 2): strdup (file);
	const int fd_flags = O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC);
	int fd = r_sandbox_open (targetFile, fd_flags, 0644);
	if (fd == -1) {
		eprintf ("r_cons_pipe_open: Cannot open file '%s'\n", file);
		free (targetFile);
		return -1;
	}
	if (backup_fd != -1) {
		close (backup_fd);
		// already set in __dupDescriptor // backup_fd = -1;
	}
	backup_fdn = fdn;
	if (!__dupDescriptor (fd, fdn)) {
		eprintf ("Cannot dup stdout to %d\n", fdn);
		free (targetFile);
		return -1;
	}
	close (fdn);
	dup2 (fd, fdn);
	free (targetFile);
	return fd;
}

R_API void r_cons_pipe_close(int fd) {
	if (fd != -1) {
		close (fd);
		if (backup_fd != -1) {
			dup2 (backup_fd, backup_fdn);
			close (backup_fd);
			backup_fd = -1;
		}
	}
}
