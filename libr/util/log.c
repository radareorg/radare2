/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_util.h>

R_API void r_vlog(RLogLevel level, const char *fmt, va_list ap) {
	const char *hdr = "";

	switch (level) {
	case R_LOG_DEBUG:
		hdr = "DEBUG: ";
		break;
	case R_LOG_INFO:
		hdr = "INFO: ";
		break;
	case R_LOG_WARNING:
		hdr = "WARNING: ";
		break;
	case R_LOG_ERROR:
		hdr = "ERROR: ";
		break;
	case R_LOG_CRITICAL:
		hdr = "CRITICAL: ";
		break;
	}

	eprintf (hdr);
	vfprintf (stderr, fmt, ap);
}

R_API void r_log(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	r_vlog (level, fmt, args);
	va_end (args);
}
