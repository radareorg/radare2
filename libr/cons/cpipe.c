/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_cons.h>
#include <r_th.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define I (r_cons_singleton ())

static bool __dupDescriptor(int fd, int fdn) {
	if (fd == fdn) {
		return false;
	}
#if __wasi__
	return false;
#elif R2__WINDOWS__
	I->backup_fd = 2002 - (fd - 2); // windows xp has 2048 as limit fd
	return _dup2 (fdn, I->backup_fd) != -1;
#else
	I->backup_fd = sysconf (_SC_OPEN_MAX) - (fd - 2); // portable getdtablesize()
	if (I->backup_fd < 2) {
		I->backup_fd = 2002 - (fd - 2); // fallback
	}
	return dup2 (fdn, I->backup_fd) != -1;
#endif
}

R_API int r_cons_pipe_open(const char *file, int fdn, int append) {
#if __wasi__
	return -1;
#else
	if (fdn < 1) {
		return -1;
	}
	char *targetFile = (r_str_startswith (file, "~/") || r_str_startswith (file, "~\\"))
		? r_file_home (file + 2): strdup (file);
	const int fd_flags = O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC);
	int fd = r_sandbox_open (targetFile, fd_flags, 0644);
	if (fd == -1) {
		R_LOG_ERROR ("ConsPipe cannot open file '%s'", file);
		free (targetFile);
		return -1;
	}
	if (I->backup_fd != -1) {
		close (I->backup_fd);
		// already set in __dupDescriptor // backup_fd = -1;
	}
	I->backup_fdn = fdn;
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
		if (I->backup_fd != -1) {
			dup2 (I->backup_fd, I->backup_fdn);
			close (I->backup_fd);
			I->backup_fd = -1;
		}
	}
#endif
}
