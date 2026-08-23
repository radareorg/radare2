/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _R2EFI_LIMITS_H
#define _R2EFI_LIMITS_H

/* chain to the clang builtin limits.h for the standard C limits */
#include_next <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef NAME_MAX
#define NAME_MAX 255
#endif
#ifndef PIPE_BUF
#define PIPE_BUF 4096
#endif
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif
#ifndef SSIZE_MAX
#define SSIZE_MAX __LONG_MAX__
#endif
#ifndef ARG_MAX
#define ARG_MAX 131072
#endif
#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

#endif /* _R2EFI_LIMITS_H */
