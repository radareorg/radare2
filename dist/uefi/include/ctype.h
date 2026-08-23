/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _CTYPE_H
#define _CTYPE_H

#ifdef __cplusplus
extern "C" {
#endif

static inline int isdigit(int c) {
	return c >= '0' && c <= '9';
}
static inline int isupper(int c) {
	return c >= 'A' && c <= 'Z';
}
static inline int islower(int c) {
	return c >= 'a' && c <= 'z';
}
static inline int isalpha(int c) {
	return isupper (c) || islower (c);
}
static inline int isalnum(int c) {
	return isalpha (c) || isdigit (c);
}
static inline int isxdigit(int c) {
	return isdigit (c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static inline int isspace(int c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r';
}
static inline int isblank(int c) {
	return c == ' ' || c == '\t';
}
static inline int iscntrl(int c) {
	return (c >= 0 && c < 0x20) || c == 0x7f;
}
static inline int isprint(int c) {
	return c >= 0x20 && c < 0x7f;
}
static inline int isgraph(int c) {
	return c > 0x20 && c < 0x7f;
}
static inline int ispunct(int c) {
	return isgraph (c) && !isalnum (c);
}
static inline int isascii(int c) {
	return c >= 0 && c < 0x80;
}
static inline int toupper(int c) {
	return islower (c)? c - 0x20: c;
}
static inline int tolower(int c) {
	return isupper (c)? c + 0x20: c;
}
static inline int toascii(int c) {
	return c & 0x7f;
}

#ifdef __cplusplus
}
#endif

#endif /* _CTYPE_H */
