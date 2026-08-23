/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _WCHAR_H
#define _WCHAR_H

#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WCHAR_MIN
#define WCHAR_MIN __WCHAR_MIN__
#endif
#ifndef WCHAR_MAX
#define WCHAR_MAX __WCHAR_MAX__
#endif
#ifndef WEOF
#define WEOF 0xffffffffu
#endif

typedef unsigned int wint_t;
typedef struct {
	unsigned int __state;
} mbstate_t;

size_t wcslen(const wchar_t *s);
int wcscmp(const wchar_t *s1, const wchar_t *s2);
int wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t n);
wchar_t *wcscpy(wchar_t *dest, const wchar_t *src);
wchar_t *wcsncpy(wchar_t *dest, const wchar_t *src, size_t n);
wchar_t *wcscat(wchar_t *dest, const wchar_t *src);
wchar_t *wcschr(const wchar_t *s, wchar_t c);
size_t mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);
size_t wcrtomb(char *s, wchar_t wc, mbstate_t *ps);
size_t mbsrtowcs(wchar_t *dest, const char **src, size_t len, mbstate_t *ps);
size_t wcsrtombs(char *dest, const wchar_t **src, size_t len, mbstate_t *ps);
int mbsinit(const mbstate_t *ps);

#ifdef __cplusplus
}
#endif

#endif /* _WCHAR_H */
