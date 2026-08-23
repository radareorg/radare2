/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _WCTYPE_H
#define _WCTYPE_H

#include <wchar.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline int iswspace(wint_t wc) {
	return wc < 0x80 && isspace ((int)wc);
}
static inline int iswdigit(wint_t wc) {
	return wc < 0x80 && isdigit ((int)wc);
}
static inline int iswalpha(wint_t wc) {
	return wc < 0x80 && isalpha ((int)wc);
}
static inline int iswalnum(wint_t wc) {
	return wc < 0x80 && isalnum ((int)wc);
}
static inline int iswprint(wint_t wc) {
	return wc < 0x80 && isprint ((int)wc);
}
static inline int iswupper(wint_t wc) {
	return wc < 0x80 && isupper ((int)wc);
}
static inline int iswlower(wint_t wc) {
	return wc < 0x80 && islower ((int)wc);
}
static inline wint_t towupper(wint_t wc) {
	return wc < 0x80? (wint_t)toupper ((int)wc): wc;
}
static inline wint_t towlower(wint_t wc) {
	return wc < 0x80? (wint_t)tolower ((int)wc): wc;
}

#ifdef __cplusplus
}
#endif

#endif /* _WCTYPE_H */
