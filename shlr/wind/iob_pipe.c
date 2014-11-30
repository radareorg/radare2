#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include "transport.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

struct qemu_pipe_t {
	int in, out;
};

void *iob_pipe_open (const char *path) {
	char pipe_in[256], pipe_out[256]; 
	int in_fd, out_fd;
	struct qemu_pipe_t *ret;

	snprintf(pipe_in, sizeof(pipe_in), "%s.in", path);
	snprintf(pipe_out, sizeof(pipe_out), "%s.out", path);

	in_fd = open(pipe_in, O_WRONLY | O_BINARY);
	out_fd = open(pipe_out, O_RDONLY | O_BINARY);

	if (in_fd < 0 || out_fd < 0) {
		close(in_fd);
		close(out_fd);
		return 0;
	}

	ret = malloc(sizeof(struct qemu_pipe_t));
	if (!ret) {
		close(in_fd);
		close(out_fd);
		return 0;
	}

	ret->in = in_fd;
	ret->out = out_fd;

	return (void *)ret;
}

int iob_pipe_close (void *p) {
	struct qemu_pipe_t *ptr = (struct qemu_pipe_t *)p;

	if (!ptr)
		return E_ERROR;

	close(ptr->in);
	close(ptr->out);

	free(ptr);

	return E_OK;
}

int iob_pipe_read (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	struct qemu_pipe_t *ptr = (struct qemu_pipe_t *)p;

	if (!ptr)
		return E_ERROR;

	return read(ptr->out, buf, count);
}

int iob_pipe_write (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	struct qemu_pipe_t *ptr = (struct qemu_pipe_t *)p;

	if (!ptr)
		return E_ERROR;

	return write(ptr->in, buf, count);
}

io_backend_t iob_pipe = {
	.name = "pipe",
	.init = NULL,
	.deinit = NULL,
	.config = NULL,
	.open = &iob_pipe_open,
	.close = &iob_pipe_close,
	.read = &iob_pipe_read,
	.write = &iob_pipe_write,
};
