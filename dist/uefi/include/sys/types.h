/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_TYPES_H
#define _SYS_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef long ssize_t;
typedef int64_t off_t;
typedef off_t off64_t;
typedef int pid_t;
typedef unsigned int mode_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef ino_t ino64_t;
typedef unsigned long nlink_t;
typedef long blksize_t;
typedef int64_t blkcnt_t;
typedef int64_t time_t;
typedef long suseconds_t;
typedef unsigned int useconds_t;
typedef unsigned int socklen_t;
typedef unsigned int id_t;
typedef int64_t loff_t;
typedef uint32_t fsblkcnt_t;
typedef uint32_t fsfilcnt_t;
typedef int clockid_t;
typedef long clock_t;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef char *caddr_t;

/* glibc compat: sys/types.h drags the pthread types in */
#include <bits/pthreadtypes.h>

#endif /* _SYS_TYPES_H */
