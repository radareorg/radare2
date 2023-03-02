/* radare - LGPL - Copyright 2007-2022 - pancake */

#include <r_util.h>

// TODO: simplify this horrible loop
R_API void r_str_trim_path(char *s) {
	r_return_if_fail (s);
	char *src, *dst, *p;
	int i = 0;
	if (R_STR_ISEMPTY (s)) {
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

R_API char* r_str_trim_lines(char *str) {
	RList *list = r_str_split_list (str, "\n", 0);
	char *s;
	RListIter *iter;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (list, iter, s) {
		//r_str_ansi_trim (s, -1, 99999);
		r_str_ansi_filter (s, NULL, NULL, -1);
		r_str_trim (s);
		if (*s) {
			r_strbuf_appendf (sb, "%s\n", s);
		}
	}
	r_list_free (list);
	free (str);
	return r_strbuf_drain (sb);
}

R_API void r_str_trim_emptylines(char *str) {
	r_str_trim_tail (str);
	char *r = str;
	while (*r) {
		if (*r == '\n') {
			r++;
			// skip empty lines
			char *nl = r;
			while (*r && *r != '\n') {
				if (!isspace (*r)) {
					break;
				}
				r++;
			}
			if (*r == '\n') {
				r_str_cpy (nl, r + 1);
			}
		}
		if (!*r) {
			break;
		}
		r++;
	}
}

R_API char *r_str_trim_dup(const char *str) {
	char *a = strdup (str);
	r_str_trim (a);
	return a;
}

// Returns a pointer to the first non-whitespace character of str.
// TODO: Find a better name: to r_str_trim_head_ro(), r_str_skip_head or so
R_API const char *r_str_trim_head_ro(const char *str) {
	r_return_val_if_fail (str, NULL);
	for (; *str && IS_WHITECHAR (*str); str++) {
		;
	}
	return str;
}

// TODO: find better name
R_API const char *r_str_trim_head_wp(const char *str) {
	r_return_val_if_fail (str, NULL);
	for (; *str && !IS_WHITESPACE (*str); str++) {
		;
	}
	return str;
}

// remove in-place spaces from the head of the string.
R_API void r_str_trim_head(char *str) {
	r_return_if_fail (str);
	char *p = (char *)r_str_trim_head_ro (str);
	if (p && p != str) {
		memmove (str, p, strlen (p) + 1);
	}
}

static bool is_escapable(char ch) {
	switch (ch) {
	case '@':
	case '"':
	case '\'':
	case '|':
	case ';':
	case '`':
		return true;
	}
	return false;
}

R_API void r_str_trim_args(char *str) {
	r_return_if_fail (str);
	char q = 0;
	bool e = false;
	char *s = str;
	char *d = str;
	while (*s) {
		switch (*s) {
		case '\'':
		case '"':
			if (e) {
				e = false;
			} else {
				if (q) {
					// needs to be escaped
					if (q == *s) {
						q = 0;
						e = false;
						s++;
						continue;
					}
				} else {
					q = *s;
					s++;
					e = false;
					continue;
				}
			}
			break;
		case '\\':
			if (e) {
				e = false;
			} else {
				if (is_escapable (s[1])) {
					e = true;
					s++;
					continue;
				}
			}
			break;
		default:
			e = false;
			break;
		}
		*d = *s;
		s++;
		d++;
	}
	*d = 0;
}

// Remove whitespace chars from the tail of the string, replacing them with
// null bytes. The string is changed in-place.
R_API void r_str_trim_tail(char *str) {
	r_return_if_fail (str);
	size_t length = strlen (str);
	while (length-- > 0) {
		if (IS_WHITECHAR (str[length])) {
			str[length] = '\0';
		} else {
			break;
		}
	}
}

// Removes spaces from the head of the string, and zeros out whitespaces from
// the tail of the string. The string is changed in place.
R_API void r_str_trim(char *str) {
	r_return_if_fail (str);
	r_str_ntrim (str, strlen (str));
}

R_API int r_str_ntrim(char *str, int length) {
	r_return_val_if_fail (str && length >= 0, -1);
	// r_str_trim_head (str);
	char *p = str;
	for (; *p && IS_WHITECHAR (*p) && length > 0; p++) {
		length--;
	}
	if (p != str && length > 0) {
		memmove (str, p, length + 1);
	}
	// r_str_trim_tail (str);
	while (length > 0) {
		const int newlength = length - 1;
		if (IS_WHITECHAR (str[newlength])) {
			str[newlength] = '\0';
		} else {
			break;
		}
		length = newlength;
	}
	str[length] = 0;
	return length;
}

// no copy, like trim_head+tail but with trim_head_ro, beware heap issues
// TODO: rename to r_str_trim_weak() ?
R_API char *r_str_trim_nc(char *str) {
	char *s = (char *)r_str_trim_head_ro (str);
	r_str_trim_tail (s);
	return s;
}

/* supposed to chop a string with ansi controls to max length of n. */
R_API int r_str_ansi_trim(char *str, int str_len, int n) {
	r_return_val_if_fail (str, 0);
	char ch, ch2;
	int back = 0, i = 0, len = 0;
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
				for (i++; (i < str_len) && str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H';
					i++) {
					;
				}
			}
		} else if ((str[i] & 0xc0) != 0x80) {
			len++;
		}
		i++;
		back = i; /* index in the original array */
	}
	str[back] = 0;
	return back;
}
