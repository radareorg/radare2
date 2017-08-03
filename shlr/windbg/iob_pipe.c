// Copyright (c) 2014, The Lemon Man, All rights reserved. LGPLv3

#include <stdio.h>
#include <string.h>
#include "r_types.h"

#if __WINDOWS__ || __CYGWIN__ || MINGW32
#include <windows.h>
#include <fcntl.h>
#include "transport.h"

static void *iob_pipe_open (const char *path) {
	HANDLE hPipe;
	hPipe = CreateFileA (path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	eprintf ("iob_pipe_open: invocado %s\n", path);
	if (hPipe != INVALID_HANDLE_VALUE) {
		return (void *)(HANDLE)hPipe;
	} else {
		perror ("pipe");
	}
	return NULL;
}

static int iob_pipe_close (void *p) {
	return CloseHandle (p);
}

static int iob_pipe_read (void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	DWORD c = 0;
	if (!ReadFile (p, buf, count, &c, NULL))
		return -1;
	return c;
}

static int iob_pipe_write (void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	DWORD cbWrited = 0;
	if (!WriteFile (p, buf, count, &cbWrited, NULL))
		return -1;
	return cbWrited;
}

#else

#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
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
	//return recv((int)(size_t)p, buf, count, 0);
	int result;
	fd_set readset;
	int fd=(int)(size_t)p;
	for (;;) {
		FD_ZERO(&readset);
		FD_SET(fd, &readset);
		result = select (fd + 1, &readset, NULL, NULL, NULL);
		if (result <1) { // pipe closed
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (FD_ISSET(fd, &readset)) {
			return  recv((int)(size_t)p, buf, count, 0);
		}
	}
	return EINTR;
}

static int iob_pipe_write (void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	return send((int)(size_t)p, buf, count, 0);
}

#endif

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
