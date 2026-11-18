/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_io.h>
#include <errno.h>

#if R2__UNIX__ && !__wasi__
#if LIBC_HAVE_FORK
#include <sys/wait.h>
#endif

typedef struct {
	int fd;
} ContentData;

static int content_temp(void) {
	char *path = NULL;
	int fd = r_file_mkstemp ("r2-content", &path);
	if (fd >= 0 && unlink (path) < 0) {
		close (fd);
		fd = -1;
	}
	free (path);
	return fd;
}

static int content_termux(const char *uri, int perm) {
#if LIBC_HAVE_FORK
	if (perm & R_PERM_W) {
		R_LOG_ERROR ("Termux content snapshots are read-only");
		return -1;
	}
	char *helper = r_file_path ("termux-saf-read");
	if (!helper) {
		R_LOG_ERROR ("content:// needs an app resolver or termux-saf-read (Termux:API)");
		return -1;
	}
	int fd = content_temp ();
	if (fd < 0) {
		free (helper);
		return -1;
	}
	pid_t pid = r_sys_fork ();
	if (!pid) {
		if (dup2 (fd, STDOUT_FILENO) < 0) {
			_exit (127);
		}
		if (fd != STDOUT_FILENO) {
			close (fd);
		}
		char *const args[] = { helper, (char *)uri, NULL };
		execv (helper, args);
		_exit (127);
	}
	free (helper);
	int status = 0;
	pid_t waited = -1;
	if (pid > 0) {
		do {
			waited = waitpid (pid, &status, 0);
		} while (waited < 0 && errno == EINTR);
	}
	if (waited < 0 || !WIFEXITED (status) || WEXITSTATUS (status)) {
		R_LOG_ERROR ("Cannot read content URI with termux-saf-read");
		close (fd);
		return -1;
	}
	return fd;
#else
	R_LOG_ERROR ("content:// needs an app resolver on this platform");
	return -1;
#endif
}

static int content_snapshot(int input) {
	int fd = content_temp ();
	if (fd < 0) {
		return -1;
	}
	ut8 buf[65536];
	ssize_t size;
	for (;;) {
		do {
			size = read (input, buf, sizeof (buf));
		} while (size < 0 && errno == EINTR);
		if (size <= 0) {
			break;
		}
		ssize_t offset = 0;
		while (offset < size) {
			ssize_t written = write (fd, buf + offset, size - offset);
			if (written < 0 && errno == EINTR) {
				continue;
			}
			if (written <= 0) {
				close (fd);
				return -1;
			}
			offset += written;
		}
	}
	if (size < 0 || lseek (fd, 0, SEEK_SET) < 0) {
		close (fd);
		return -1;
	}
	return fd;
}

static bool content_check(RIO *io, const char *uri, bool many) {
	return !many && r_str_startswith (uri, "content://");
}

static RIODesc *content_open(RIO *io, const char *uri, int perm, int mode) {
	if (!content_check (io, uri, false) || r_sandbox_enable (false)) {
		return NULL;
	}
	RIOPlugin *plugin = r_io_plugin_resolve (io, uri, false);
	RIOContent *resolver = plugin->data;
	int fd = -1;
	if (resolver && resolver->open) {
		fd = resolver->open (resolver->user, uri, perm);
	} else {
		fd = content_termux (uri, perm);
	}
	if (fd < 0) {
		return NULL;
	}
	if (lseek (fd, 0, SEEK_SET) < 0) {
		int snapshot = -1;
		if (!(perm & R_PERM_W) && errno == ESPIPE) {
			snapshot = content_snapshot (fd);
		} else {
			R_LOG_ERROR ("Content descriptor does not support seeking");
		}
		close (fd);
		fd = snapshot;
		if (fd < 0) {
			return NULL;
		}
	}
	fcntl (fd, F_SETFD, FD_CLOEXEC);
	ContentData *data = R_NEW (ContentData);
	data->fd = fd;
	RIODesc *desc = r_io_desc_new (io, plugin, uri, perm, mode, data);
	if (!desc) {
		close (fd);
		free (data);
	}
	return desc;
}

static int content_read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	ContentData *data = desc->data;
	int ret;
	do {
		ret = read (data->fd, buf, count);
	} while (ret < 0 && errno == EINTR);
	return ret;
}

static int content_write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	ContentData *data = desc->data;
	int ret;
	do {
		ret = write (data->fd, buf, count);
	} while (ret < 0 && errno == EINTR);
	return ret;
}

static ut64 content_seek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	ContentData *data = desc->data;
	return lseek (data->fd, (st64)offset, whence);
}

static bool content_close(RIODesc *desc) {
	ContentData *data = desc->data;
	close (data->fd);
	R_FREE (desc->data);
	return true;
}
#endif

RIOPlugin r_io_plugin_content = {
	.meta = {
		.name = "content",
		.desc = "Android content provider IO (app resolver or Termux:API)",
		.license = "LGPL-3.0-only",
	},
	.uris = "content://",
#if R2__UNIX__ && !__wasi__
	.open = content_open,
	.close = content_close,
	.read = content_read,
	.write = content_write,
	.seek = content_seek,
	.check = content_check,
#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_content,
	.version = R2_VERSION
};
#endif
