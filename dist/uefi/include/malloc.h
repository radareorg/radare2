/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _MALLOC_H
#define _MALLOC_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t malloc_usable_size(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* _MALLOC_H */
