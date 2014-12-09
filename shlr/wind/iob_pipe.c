// Copyright (c) 2014, The Lemon Man, All rights reserved. LGPLv3

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if __WIN32__ || __CYGWIN__ || MINGW32
#warning No support for windows yet
#else

#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "transport.h"

static void *iob_pipe_open (const char *path) {
	int sock;
	struct sockaddr_un sa;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror ("socket");
		return 0;
	}

	memset (&sa, 0, sizeof (struct sockaddr_un));

	sa.sun_family = AF_UNIX;
	strncpy (sa.sun_path, path, sizeof(sa.sun_path));
	sa.sun_path[sizeof (sa.sun_path)-1] = 0;
	if (connect (sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_un)) == -1) {
		perror ("connect");
		close (sock);
		return 0;
	}
	return (void *)(size_t)sock;
}

static int iob_pipe_close (void *p) {
	return close ((int)(size_t)p);
}

static int iob_pipe_read (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	return recv((int)(size_t)p, buf, count, 0);
}

static int iob_pipe_write (void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	return send((int)(size_t)p, buf, count, 0);
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
