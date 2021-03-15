// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "transport.h"

#if __WINDOWS__
#include <windows.h>

static void *iob_pipe_open(const char *path) {
	HANDLE hPipe;
	LPTSTR path_ = r_sys_conv_utf8_to_win (path);

	hPipe = CreateFile (path_, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	free (path_);
	return hPipe != INVALID_HANDLE_VALUE? (void *)(HANDLE)hPipe : NULL;
}

static bool iob_pipe_close(void *p) {
	return CloseHandle (p);
}

static int iob_pipe_read(void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	DWORD c = 0;
	OVERLAPPED ov = {0};
	ov.hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
	if (!ov.hEvent) {
		return 0;
	}
	if (!ReadFile (p, buf, count, NULL, &ov) &&
		GetLastError () != ERROR_IO_PENDING) {
		r_sys_perror ("ReadFile");
		return -1;
	}
	if (WaitForSingleObject (ov.hEvent, timeout) == WAIT_TIMEOUT) {
		CancelIo (p);
	}
	GetOverlappedResult (p, &ov, &c, TRUE);
	CloseHandle (ov.hEvent);
	return c;
}

static int iob_pipe_write(void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	DWORD cbWrited = 0;
	OVERLAPPED ov = {0};
	if (!WriteFile (p, buf, count, NULL, &ov) &&
		GetLastError () != ERROR_IO_PENDING) {
		r_sys_perror ("WriteFile");
		return -1;
	}
	GetOverlappedResult (p, &ov, &cbWrited, TRUE);
	return cbWrited;
}
#else
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>

static void *iob_pipe_open(const char *path) {
	int sock;
	struct sockaddr_un sa;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror ("socket");
		return 0;
	}

	memset (&sa, 0, sizeof (struct sockaddr_un));

	sa.sun_family = AF_UNIX;
	r_str_ncpy (sa.sun_path, path, sizeof (sa.sun_path) - 1);
	if (connect (sock, (struct sockaddr *) &sa, sizeof (struct sockaddr_un)) == -1) {
		perror ("connect");
		close (sock);
		return 0;
	}
	return (void *) (size_t) sock;
}

static bool iob_pipe_close(void *p) {
	return close ((int)(size_t)p) == 0;
}

static int iob_pipe_read(void *p, uint8_t *buf, const uint64_t count, const int timeout) {
	int result;
	fd_set readset;
	int fd = (int) (size_t) p;
	struct timeval tv;
	tv.tv_sec = 0;
	// Convert from ms
	tv.tv_usec = timeout * 1000;
	for (;;) {
		FD_ZERO (&readset);
		FD_SET (fd, &readset);
		result = select (fd + 1, &readset, NULL, NULL, &tv);
		if (result < 1) {
			if (errno == EINTR) {
				continue;
			}
			if (result == 0) {
				return 0;
			}
			return -1;
		}
		if (FD_ISSET (fd, &readset)) {
			return recv ((int) (size_t) p, buf, count, 0);
		}
	}
	return EINTR;
}

static int iob_pipe_write(void *p, const uint8_t *buf, const uint64_t count, const int timeout) {
	int ret = send ((int) (size_t) p, buf, count, 0);
	if (ret < 1) {
		r_sys_perror ("iob_pipe_write, send");
		if (errno == EPIPE) {
			exit (1);
		}
	}
	return ret;
}
#endif

io_backend_t iob_pipe = {
	.name = "pipe",
	.type = KD_IO_PIPE,
	.init = NULL,
	.deinit = NULL,
	.config = NULL,
	.open = &iob_pipe_open,
	.close = &iob_pipe_close,
	.read = &iob_pipe_read,
	.write = &iob_pipe_write,
};
