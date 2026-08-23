/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_FILE_H
#define _SYS_FILE_H

#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8

int flock(int fd, int operation);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FILE_H */
