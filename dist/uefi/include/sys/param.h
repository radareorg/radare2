/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SYS_PARAM_H
#define _SYS_PARAM_H

#include <limits.h>
#include <sys/types.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN PATH_MAX
#endif
#ifndef MAXNAMLEN
#define MAXNAMLEN NAME_MAX
#endif
#ifndef NOFILE
#define NOFILE 256
#endif
#ifndef HZ
#define HZ 100
#endif

#ifndef MIN
#define MIN(a,b) (((a) < (b))? (a): (b))
#endif
#ifndef MAX
#define MAX(a,b) (((a) > (b))? (a): (b))
#endif

#endif /* _SYS_PARAM_H */
