/* radare - LGPL - Copyright 2011-2018 - pancake */

#include <r_bin.h>

// http://code.google.com/p/smali/wiki/TypesMethodsAndFields
R_API char *r_bin_demangle_java(const char *str) {
	const char *w = NULL;
	int is_array = 0;
	const char *ptr;
	int is_ret = 0;
	int wlen = 0;
	RBuffer *buf;
	int n = 0;
	char *ret;

	ptr = strchr (str, '(');
	if (!ptr) {
		return NULL;
	}
	buf = r_buf_new ();
	if (!buf) {
		return NULL;
	}
	r_buf_append_bytes (buf, (const ut8*)str, (int)(size_t)(ptr-str));
	r_buf_append_bytes (buf, (const ut8*)" (", 2);
	while (*str) {
		switch (*str) {
		case ')':
			is_ret = 1;
			break;
		case '[':
			is_array = 1;
			break;
		case 'L':
			str++;
			ptr = strchr (str, ';');
			if (ptr) {
				w = str;
				wlen = (int)(size_t)(ptr-str);
			}
			str = ptr;
			break;
		case 'I': w = "int"; wlen = 3; break;
		case 'C': w = "char"; wlen = 4; break;
		case 'B': w = "byte"; wlen = 4; break;
		case 'V': w = "void"; wlen = 4; break;
		case 'J': w = "long"; wlen = 4; break;
		case 'F': w = "float"; wlen = 5; break;
		case 'S': w = "short"; wlen = 5; break;
		case 'D': w = "double"; wlen = 6; break;
		case 'Z': w = "boolean"; wlen = 7; break;
		}
		if (w) {
			if (is_ret) {
				r_buf_prepend_bytes (buf, (const ut8*)" ", 1);
				r_buf_prepend_bytes (buf, (const ut8*)w, wlen);
				r_buf_append_bytes (buf, (const ut8*)")", 1);
				break;
			} else {
				if (n++ > 0) {
					r_buf_append_bytes (buf, (const ut8 *)", ", 2);
				}
				r_buf_append_bytes (buf, (const ut8*)w, wlen);
			}
			if (is_array) {
				r_buf_append_bytes (buf, (const ut8*)"[]", 2);
				is_array = 0;
			}
		}
		w = NULL;
		if (!str) {
			break;
		}
		str++;
	}
	ret = r_buf_to_string (buf);
	r_buf_free (buf);
	return ret;
}


