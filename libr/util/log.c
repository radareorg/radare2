/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_util.h>

R_API void r_vlog(RLogLevel level, const char *fmt, va_list ap) {
	static const char *headers[R_LOG_MAX_VALUE] = {
		[R_LOG_DEBUG] = "DEBUG: ",
		[R_LOG_INFO] = "INFO: ",
		[R_LOG_WARNING] = "WARNING: ",
		[R_LOG_ERROR] = "ERROR: ",
		[R_LOG_CRITICAL] = "CRITICAL: ",
	};

	const char *hdr = level < R_LOG_MAX_VALUE ? headers[level] : "";
	eprintf (hdr);
	vfprintf (stderr, fmt, ap);
}

R_API void r_log(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	r_vlog (level, fmt, args);
	va_end (args);
}
