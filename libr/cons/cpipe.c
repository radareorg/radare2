/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_cons.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

R_API int r_cons_pipe_open(RCons *cons, const char *file, int fd_src, int append) {
	R_RETURN_VAL_IF_FAIL (cons && file, -1);
#if __wasi__
	cons->wasm_redirect_append = append;
	free (cons->wasm_redirect_file);
	cons->wasm_redirect_file = strdup (file);
	return 0;
#else
	if (fd_src < 1 || fd_src > ST16_MAX) {
		return -1;
	}
	RConsFdPair *pair;
	R_VEC_FOREACH (&cons->fds, pair) {
		if (fd_src == pair->fd_src) {
			R_LOG_WARN ("cannot redirect the same fd twice");
			return -1;
		}
	}
	// Opening the output first could reuse a closed source descriptor.
	int fd_bak = dup (fd_src);
	if (fd_bak < 0) {
		R_LOG_ERROR ("Cannot back up file descriptor %d", fd_src);
		return -1;
	}
	if (fd_bak > ST16_MAX) {
		close (fd_bak);
		return -1;
	}
	char *target_file = (r_str_startswith (file, "~/") || r_str_startswith (file, "~\\"))
		? r_file_home (file + 2): strdup (file);
	if (!target_file) {
		close (fd_bak);
		return -1;
	}
	const int fd_flags = O_BINARY | O_RDWR | O_CREAT | (append? O_APPEND: O_TRUNC);
	int fd_new = r_sandbox_open (target_file, fd_flags, 0644);
	R_LOG_DEBUG ("open (%s) = %d", target_file, fd_new);
	free (target_file);
	if (fd_new < 0) {
		close (fd_bak);
		R_LOG_ERROR ("ConsPipe cannot open file '%s'", file);
		return -1;
	}
	pair = fd_new <= ST16_MAX? RVecFdPairs_emplace_back (&cons->fds): NULL;
	if (!pair) {
		close (fd_new);
		close (fd_bak);
		return -1;
	}
	int res = dup2 (fd_new, fd_src);
	if (res < 0) {
		RVecFdPairs_pop_back (&cons->fds);
		close (fd_new);
		close (fd_bak);
		R_LOG_ERROR ("Cannot redirect file descriptor %d", fd_src);
		return -1;
	}
	*pair = (RConsFdPair){ .fd_src = fd_src, .fd_new = fd_new, .fd_bak = fd_bak };
	R_LOG_DEBUG ("dup2 %d %d = %d", fd_new, fd_src, res);
	return fd_new;
#endif
}

R_API void r_cons_pipe_close(RCons *cons, int fd) {
#if !__wasi__
	r_cons_pipe_close_all (cons);
#if 0
	if (fd != -1) {
		close (fd);
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
	int res R_UNUSED;
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
#else
	R_FREE (cons->wasm_redirect_file);
#endif
}
