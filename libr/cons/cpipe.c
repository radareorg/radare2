/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_cons.h>
#include <r_th.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define HONOR_LAST_REDIRECT 0
#define USE_HACK 0

#if 0
static bool mydup(const int fd, const int fdn) {
	if (fd == fdn) {
		return false;
	}
#if __wasi__
	return false;
#else
#  if R2__WINDOWS__
	int newfd = -1;
#  else
	int newfd = sysconf (_SC_OPEN_MAX) - (fd - 2); // portable getdtablesize()
#  endif
	if (newfd < 2) {
		newfd = 2002 - (fd - 2); // fallback
	}
	return dup2 (fd, newfd) != -1;
#endif
}
#endif

R_API int r_cons_pipe_open(RCons *cons, const char *file, int fd_src, int append) {
#if __wasi__
	return -1;
#else
	if (fd_src < 1) {
		return -1;
	}
	RConsFdPair *pair;
#if !HONOR_LAST_REDIRECT
	// prevent redirecting the same fd twice in the same line
	R_VEC_FOREACH (&cons->fds, pair) {
		if (fd_src == pair->fd_src) {
			R_LOG_WARN ("cannot redirect the same fd twice");
			// do not permit redirecting output to more than one file
			return -1;
		}
	}
#endif
	char *targetFile = (r_str_startswith (file, "~/") || r_str_startswith (file, "~\\"))
		? r_file_home (file + 2): strdup (file);
	const int fd_flags = O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC);
	int fd_new = r_sandbox_open (targetFile, fd_flags, 0644);
	if (fd_new < 0) {
		R_LOG_ERROR ("ConsPipe cannot open file '%s'", file);
		free (targetFile);
		return -1;
	}
	R_LOG_DEBUG ("open (%s) = %d", targetFile, fd_new);
	int fd_bak = fd_src + 32; // XXX wrong assumptions
	bool is_dual = false;
#if HONOR_LAST_REDIRECT
	R_VEC_FOREACH (&cons->fds, pair) {
		if (fd_src == pair->fd_src) {
			// do not permit redirecting output to more than one file
#if USE_HACK
			int fd_new2 = pair->fd_new + 64;
			dup2 (pair->fd_bak, fd_new2);
#else
			int fd_new2 = dup (pair->fd_bak);
#endif
			fd_bak = fd_new2;
			break;
		}
	}
#endif
	// int res = dup2 (fdn, rfd);
	int res;
	if (!is_dual) {
#if USE_HACK
		res = dup2 (fd_src, fd_bak);
#else
		res = fd_bak = dup (fd_src);
#endif
		R_LOG_DEBUG ("dup2 %d %d = %d", fd_src, fd_bak, res);
		close (fd_src);
		res = dup2 (fd_new, fd_src);
	}
	R_LOG_DEBUG ("dup2 %d %d = %d", fd_new, fd_src, res);
	RConsFdPair newPair = {
		.fd_src = fd_src, // original source file descriptor
		.fd_new = fd_new, // new file descriptor created to write into the file
		.fd_bak = fd_bak, // restored file descriptor to be used to recover the original fd into fdn
	};
	// eprintf (" %d -> %d\n", fd_src, fd_new);
	RVecFdPairs_push_back (&cons->fds, &newPair);
#if 0
	if (!mydup (fd, fdn)) {
		R_LOG_ERROR ("Cannot dup stdout to %d", fdn);
		free (targetFile);
		return -1;
	}
#endif
	// close (fdn);
	// res = dup2 (fd, fdn);
	// eprintf ("dup2 %d %d = %d\n", fd, fdn, res);
	free (targetFile);
	return fd_new;
#endif
}

R_API void r_cons_pipe_close(RCons *cons, int fd) {
#if !__wasi__
	r_cons_pipe_close_all (cons);
#if 0
	if (fd != -1) {
		close (fd);
		RCons *ci = r_cons_singleton ();
		if (cons->backup_fdn[fd] != -1) {
			dup2 (cons->backup_fd, cons->backup_fdn[fd]);
			close (cons->backup_fd);
			cons->backup_fd = -1;
			cons->backup_fdn[fd] = -1;
		}
	}
#endif
#endif
}

R_API void r_cons_pipe_close_all(RCons *cons) {
#if !__wasi__
	RConsFdPair *pair;
	int res;
	R_VEC_FOREACH_PREV (&cons->fds, pair) {
		res = dup2 (pair->fd_bak, pair->fd_src);
		R_LOG_DEBUG ("dup2 %d -> %d = %d", pair->fd_bak, pair->fd_src, res);
		res = close (pair->fd_bak);
		R_LOG_DEBUG ("close (%d)=%d", pair->fd_bak, res);
#if 0
		res = dup2 (pair->fd_new, pair->fd_src);
		eprintf ("dup %d -> %d\n", pair->fd_new, pair->fd_src);
#endif
		res = close (pair->fd_new);
		R_LOG_DEBUG ("close (%d)=%d", pair->fd_new, res);
	}
	RVecFdPairs_fini (&cons->fds);
	RVecFdPairs_init (&cons->fds);
#endif
}
