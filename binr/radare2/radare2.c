/* radare - LGPL - Copyright 2009-2024 - pancake */

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


// Helper function to write all data to a file descriptor
static ssize_t write_all(int fd, const void *buf, size_t count) {
    size_t total_written = 0;
    const char *ptr = buf;

    while (total_written < count) {
        ssize_t written = write(fd, ptr + total_written, count - total_written);
        if (written <= 0) {
            if (errno == EINTR)
                continue; // Retry if interrupted
            return -1; // Error occurred
        }
        total_written += written;
    }
    return total_written;
}

static void r2cmd(int in_fd, int out_fd, const char *cmd) {
    // Send the command including the null terminator and newline
    size_t cmd_len = strlen(cmd) + 1; // Include null terminator
    if (write_all(out_fd, cmd, cmd_len) != (ssize_t)cmd_len)
        return;
    if (write_all(out_fd, "\n", 1) != 1)
        return;

    // Set the input file descriptor to non-blocking mode
    int flags = fcntl(in_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        return;
    }
    if (fcntl(in_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL");
        return;
    }

    unsigned char tmp_buf[4096];
    ssize_t bytes_read;
    RBuffer *buf = r_buf_new(); // Initialize RBuf
    if (!buf)
        return;

    // The response terminator (adjust based on your protocol)
    const char *response_terminator = "\0"; // Null terminator as an example
    size_t terminator_len = strlen(response_terminator);

    while (1) {
        bytes_read = read(in_fd, tmp_buf, sizeof(tmp_buf));
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue; // Retry if interrupted
            else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available right now
                // Implement a timeout or sleep if necessary
                usleep(10000); // Sleep for 10ms
                continue;
            } else {
                perror("read");
                break; // Error occurred
            }
        } else if (bytes_read == 0) {
            // EOF reached
            break;
        }

        // Append data to RBuf
        if (!r_buf_append_bytes(buf, tmp_buf, bytes_read)) {
            // Failed to append data
            r_buf_free(buf);
            return;
        }

        // Write data to STDOUT
        if (write_all(STDOUT_FILENO, tmp_buf, bytes_read) != bytes_read) {
            // Error occurred during write
            perror("write");
            r_buf_free(buf);
            return;
        }

        // Check if the response terminator is in the buffer
        st64 buf_size = r_buf_size(buf);
        if (buf_size >= (st64)terminator_len) {
            // Read the last few bytes to check for the terminator
            ut8 *end_check = malloc(terminator_len);
            if (!end_check) {
                perror("malloc");
                r_buf_free(buf);
                return;
            }
            if (r_buf_read_at(buf, buf_size - terminator_len, end_check, terminator_len) != (st64)terminator_len) {
                free(end_check);
                r_buf_free(buf);
                return;
            }
            if (memcmp(end_check, response_terminator, terminator_len) == 0) {
                // Terminator found, end of response
                free(end_check);
                break;
            }
            free(end_check);
        }
    }

    r_buf_free(buf);
    write_all(STDOUT_FILENO, "\n", 1);
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
