/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _POLL_H
#define _POLL_H

#ifdef __cplusplus
extern "C" {
#endif

#define POLLIN 1
#define POLLPRI 2
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 16
#define POLLNVAL 32

typedef unsigned long nfds_t;

struct pollfd {
	int fd;
	short events;
	short revents;
};

int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* _POLL_H */
