/* radare - LGPL - Copyright 2014-2024 - pancake */

#include <r_cons.h>

static int stiv_printf_cb(const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);
	r_cons_printf_list (NULL, fmt, ap);
	va_end (ap);
	return 0;
}
