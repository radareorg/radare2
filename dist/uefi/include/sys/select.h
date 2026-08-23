/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_SELECT_H
#define _SYS_SELECT_H

#include <sys/types.h>
#include <sys/time.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

struct timeval;

#define FD_SETSIZE 1024

typedef struct {
	unsigned long fds_bits[FD_SETSIZE / (8 * sizeof (unsigned long))];
} fd_set;

#define FD_ZERO(set) memset ((set), 0, sizeof (fd_set))
#define FD_SET(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof (unsigned long))] |= (1UL << ((fd) % (8 * sizeof (unsigned long)))))
#define FD_CLR(fd, set) ((set)->fds_bits[(fd) / (8 * sizeof (unsigned long))] &= ~(1UL << ((fd) % (8 * sizeof (unsigned long)))))
#define FD_ISSET(fd, set) (((set)->fds_bits[(fd) / (8 * sizeof (unsigned long))] & (1UL << ((fd) % (8 * sizeof (unsigned long))))) != 0)

struct timespec;

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const void *sigmask);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SELECT_H */
