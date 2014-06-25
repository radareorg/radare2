/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <r_cons.h>
#include <unistd.h>
#include <limits.h>

//TODO: cons_pipe should be using a stack pipe_push, pipe_pop
/* this is the base fd.. more than one is supported :) */
static int backup_fd = -1;
static int backup_fdn = 1;

#ifndef O_BINARY
#define O_BINARY 0
#endif

R_API int r_cons_pipe_open(const char *file, int fdn, int append) {
	int fd = r_sandbox_open (file,
		O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC), 0644);
	if (fd==-1) {
		eprintf ("r_cons_pipe_open: Cannot open file '%s'\n", file);
		return -1;
	}// else eprintf ("%s created\n", file);
	if (backup_fd != -1)
		close (backup_fd);
	backup_fdn = (fdn>0)? fdn: 1;
#if __WINDOWS__ && !__CYGWIN__
	backup_fd = 2002-(fd-2); // windows xp has 2048 as limit fd
	if (_dup2 (fdn, backup_fd) == -1) {
#else
	backup_fd = sysconf (_SC_OPEN_MAX)-(fd-2); // portable getdtablesize()
	if (backup_fd <2) backup_fd = 2002-(fd-2); // fallback
	if (dup2 (fdn, backup_fd) == -1) {
#endif
		eprintf ("Cannot dup stdout to %d\n", backup_fd);
		return -1;
	}
	close (fdn);
	dup2 (fd, fdn);
	return fd;
}

R_API void r_cons_pipe_close(int fd) {
	if (fd == -1)
		return;
	close (fd);
	if (backup_fd != -1) {
		dup2 (backup_fd, backup_fdn);
		close (backup_fd);
		backup_fd = -1;
	}
}
