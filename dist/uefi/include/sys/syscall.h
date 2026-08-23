/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#ifdef __cplusplus
extern "C" {
#endif

long syscall(long number, ...);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSCALL_H */
