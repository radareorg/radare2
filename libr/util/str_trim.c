/* radare - LGPL - Copyright 2007-2018 - pancake */

#include "r_types.h"
#include "r_util.h"
#include "r_cons.h"
#include "r_bin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

// TODO: simplify this horrible loop
R_API void r_str_trim_path(char *s) {
	char *src, *dst, *p;
	int i = 0;
	if (!s || !*s) {
		return;
	}
	dst = src = s + 1;
	while (*src) {
		if (*(src - 1) == '/' && *src == '.' && *(src + 1) == '.') {
			if (*(src + 2) == '/' || *(src + 2) == '\0') {
				p = dst - 1;
				while (s != p) {
					if (*p == '/') {
						if (i) {
							dst = p + 1;
							i = 0;
							break;
						}
						i = 1;
					}
					p--;
				}
				if (s == p && *p == '/') {
					dst = p + 1;
				}
				src = src + 2;
			} else {
				*dst = *src;
				dst++;
			}
		} else if (*src == '/' && *(src + 1) == '.' && (*(src + 2) == '/' || *(src + 2) == '\0')) {
			src++;
		} else if (*src != '/' || *(src - 1) != '/') {
			*dst = *src;
			dst++;
		}
		src++;
	}
	if (dst > s + 1 && *(dst - 1) == '/') {
		*(dst - 1) = 0;
	} else {
		*dst = 0;
	}
}

R_API char *r_str_trim(char *str) {
	if (!str) {
		return NULL;
	}
	char *nonwhite = str;
	while (*nonwhite && IS_WHITECHAR (*nonwhite)) {
		nonwhite++;
	}
	int len = strlen (str);
	if (str != nonwhite) {
		int delta = (size_t)(nonwhite - str);
		len -= delta;
		memmove (str, nonwhite, len + 1);
	}
	if (len > 0) {
		char *ptr;
		for (ptr = str + len - 1; ptr != str; ptr--) {
			if (!IS_WHITECHAR (*ptr)) {
				break;
			}
			*ptr = '\0';
		}
	}
	return str;
}

// Returns a pointer to the first non-whitespace character of str.
// TODO: rename to r_str_trim_head_ro()
R_API const char *r_str_trim_ro(const char *str) {
	if (str) {
		for (; *str && IS_WHITECHAR (*str); str++);
	}
	return str;
}

// Returns a pointer to the first whitespace character of str.
// TODO: rename to r_str_trim_head_wp()
R_API const char *r_str_trim_wp(const char *str) {
	if (str) {
		for (; *str && !IS_WHITESPACE (*str); str++);
	}
	return str;
}

/* remove spaces from the head of the string.
 * the string is changed in place */
R_API char *r_str_trim_head(char *str) {
	char *p = (char *)r_str_trim_ro (str);;
	if (p) {
		memmove (str, p, strlen (p) + 1);
	}
	return str;
}

// Remove whitespace chars from the tail of the string, replacing them with
// null bytes. The string is changed in-place.
R_API char *r_str_trim_tail(char *str) {
	int length;

	if (!str) {
		return NULL;
	}
	length = strlen (str);
	if (!length) {
		return str;
	}

	while (length--) {
		if (IS_WHITECHAR (str[length])) {
			str[length] = '\0';
		} else {
			break;
		}
	}

	return str;
}

// Removes spaces from the head of the string, and zeros out whitespaces from
// the tail of the string. The string is changed in place.
R_API char *r_str_trim_head_tail(char *str) {
	return r_str_trim_tail (r_str_trim_head (str));
}

// no copy, like trim_head+tail but with trim_head_ro
R_API char *r_str_trim_nc(char *str) {
	char *s = (char *)r_str_trim_ro (str);
	return r_str_trim_tail (s);
}

/* suposed to chop a string with ansi controls to max length of n. */
R_API int r_str_ansi_trim(char *str, int str_len, int n) {
	char ch, ch2;
	int back = 0, i = 0, len = 0;
	if (!str) {
		return 0;
	}
	/* simple case - no need to cut */
	if (str_len < 0) {
		str_len = strlen (str);
	}
	if (n >= str_len) {
		str[str_len] = 0;
		return str_len;
	}
	while ((i < str_len) && str[i] && len < n && n > 0) {
		ch = str[i];
		ch2 = str[i + 1];
		if (ch == 0x1b) {
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (++i; (i < str_len) && str[i]
					&& str[i] != 'J'
					&& str[i] != 'm'
					&& str[i] != 'H';
				     i++);
			}
		} else if ((str[i] & 0xc0) != 0x80) {
			len++;
		}
		i++;
		back = i; 	/* index in the original array */
	}
	str[back] = 0;
	return back;
}

