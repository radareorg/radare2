/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_main.h>

#if EMSCRIPTEN__TODO
#include <emscripten.h>
static R_TH_LOCAL RCore *core = NULL;

void *r2_asmjs_new(const char *cmd) {
	return r_core_new ();
}

void r2_asmjs_free(void *core) {
	r_core_free (core);
}

char *r2_asmjs_cmd(void *kore, const char *cmd) {
	if (kore) {
		if (!cmd) {
			r_core_free (kore);
		}
	} else {
		if (core) {
			kore = core;
		} else {
			kore = core = r_core_new ();
		}
	}
	return r_core_cmd_str (kore, cmd);
}

static void wget_cb(const char *f) {
	r_core_cmdf (core, "\"o %s\"", f);
}

void r2_asmjs_openurl(void *kore, const char *url) {
	const char *file = r_str_lchr (url, '/');
	if (kore) {
		core = kore;
	}
	if (file) {
		emscripten_async_wget (url, file + 1, wget_cb, NULL);
	}
}
#else

static ssize_t write_all(int fd, const void *buf, size_t count) {
	size_t total_written = 0;
	const char *ptr = buf;

	while (total_written < count) {
		ssize_t written = write (fd, ptr + total_written, count - total_written);
		if (written <= 0) {
			if (errno == EINTR) {
				continue;
			}
			return -1;
		}
		total_written += written;
	}
	return total_written;
}

static void r2cmd(int in_fd, int out_fd, const char *cmd) {
	// Send the command followed by a newline to the output file descriptor
	size_t cmd_len = strlen (cmd);
	if (write_all (out_fd, cmd, cmd_len) != (ssize_t)cmd_len) {
		return;
	}
	if (write_all (out_fd, "\n", 1) != 1) {
		return;
	}

	ut8 *buf = NULL;
	size_t bufsz = 0;
	ssize_t bytes_read;

	while (1) {
		// Read data in small chunks to handle any size
		ut8 small_buf[4096];
		bytes_read = read (in_fd, small_buf, sizeof(small_buf));
		if (bytes_read < 0) {
			if (errno == EINTR) {
				continue;
			}
			break;
		} else if (bytes_read == 0) {
			break;
		}

		// Allocate or expand the buffer to hold the new data
		unsigned char *new_buf = realloc (buf, bufsz + bytes_read);
		if (!new_buf) {
			free (buf);
			return; // Allocation failed
		}
		buf = new_buf;
		memcpy (buf + bufsz, small_buf, bytes_read);
		bufsz += bytes_read;
	}

	if (bufsz > 0) {
		if (write_all (STDOUT_FILENO, buf, bufsz) != (ssize_t)bufsz) {
			free (buf);
			return;
		}
	}

	free (buf);
	write_all (STDOUT_FILENO, "\n", 1);
}

static int r_main_r2pipe(int argc, const char **argv) {
	int i, rc = 0;
	char *_in = r_sys_getenv ("R2PIPE_IN");
	char *_out = r_sys_getenv ("R2PIPE_OUT");
	if (R_STR_ISNOTEMPTY (_in) && R_STR_ISNOTEMPTY (_out)) {
		int in = atoi (_in);
		int out = atoi (_out);
		for (i = 1; i < argc; i++) {
			r2cmd (in, out, argv[i]);
		}
	} else {
		R_LOG_ERROR ("R2PIPE_(IN|OUT) environment not set");
		R_LOG_INFO ("Usage: r2 -c '!*r2p x' # run commands via r2pipe");
		rc = 1;
	}
	free (_in);
	free (_out);
	return rc;
}

int main(int argc, const char **argv) {
	if (argc > 0 && strstr (argv[0], "r2p")) {
		return r_main_r2pipe (argc, argv);
	}
	char *ea = r_sys_getenv ("R2_ARGS");
	if (R_STR_ISNOTEMPTY (ea)) {
		R_LOG_INFO ("Using R2_ARGS: \"%s\"", ea);
		if (!r_str_startswith (ea, argv[0])) {
			R_LOG_WARN ("R2_ARGS should start with argv[0]=%s", argv[0]);
		}
		char **argv = r_str_argv (ea, &argc);
		r_sys_setenv ("R2_ARGS", NULL);
		int res = r_main_radare2 (argc, (const char **)argv);
		free (ea);
		free (argv);
		return res;
	}
	free (ea);
	return r_main_radare2 (argc, argv);
}

#endif
