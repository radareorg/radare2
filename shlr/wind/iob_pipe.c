// Copyright (c) 2014, The Lemon Man, All rights reserved. LGPLv3


#if __WIN32__ || __CYGWIN__ || MINGW32
#warning No support for windows yet
#else

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "transport.h"

void *iob_pipe_open (const char *path) {
	int sock;
	struct sockaddr_un sa;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 0;
	}

	memset (&sa, 0, sizeof (struct sockaddr_un));

	sa.sun_family = AF_UNIX;
	strncpy (sa.sun_path, path, sizeof(sa.sun_path));

	if (connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) < 0) {
		perror("bind");
		return 0;
	}

	return (void *)sock;
}

int iob_pipe_close (void *p) {
	close((int)p);
}

int iob_pipe_read (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	return recv((int)p, buf, count, 0);
}

int iob_pipe_write (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	return send((int)p, buf, count, 0);
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
#endif
