/* radare2 - LGPL - Copyright 2025 - Robert Gill */

#include <r_util.h>

// Allocate a buffer of specified buffer size if *buf = NULL. Reallocates as
// necessary to fit string returning new buffer size in &buf_size.
// A preallocated buffer may be used and its size may be specified in
// &buf_size, it will be resized accordingly.
R_API int r_str_vasnprintf(char **buf, R_NONNULL size_t *buf_size, R_NONNULL const char *fmt, va_list ap) {
	va_list aq;
	int ret;

	if (*buf == NULL)
		*buf = r_malloc (*buf_size * sizeof (char));

	va_copy (aq, ap);
	while (true) {
		ret = vsnprintf (*buf, *buf_size, fmt, aq);

		if (ret < 0) {
			free (*buf);
			*buf = NULL;
			return ret;
		}

		if (ret >= *buf_size) {
			// double buffer size and reallocate
			*buf_size += *buf_size;
			*buf = r_realloc (*buf, *buf_size);
			va_copy (aq, ap);
			continue;
		}
		break;
	}

	return ret;
}

R_API int r_str_asnprintf(char **buf, R_NONNULL size_t *buf_size, R_NONNULL const char *fmt, ...) {
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = r_str_vasnprintf (buf, buf_size, fmt, ap);
	va_end (ap);
	return ret;
}

R_API int r_str_vasprintf(char **buf, R_NONNULL const char *fmt, va_list ap) {
	int ret;
	size_t buf_size;

	*buf = NULL;
	buf_size = BUFSIZ;
	ret = r_str_vasnprintf (buf, &buf_size, fmt, ap);
	return ret;
}

R_API int r_str_asprintf(char **buf, R_NONNULL const char *fmt, ...) {
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = r_str_vasprintf (buf, fmt, ap);
	va_end (ap);
	return ret;
}
