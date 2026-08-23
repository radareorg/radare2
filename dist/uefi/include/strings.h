/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _STRINGS_H
#define _STRINGS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int strcasecmp(const char *s1, const char *s2);
int strncasecmp(const char *s1, const char *s2, size_t n);
void bzero(void *s, size_t n);
void bcopy(const void *src, void *dest, size_t n);
int ffs(int i);

#ifdef __cplusplus
}
#endif

#endif /* _STRINGS_H */
