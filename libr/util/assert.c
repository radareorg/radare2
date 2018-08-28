#include <r_util.h>

#define S_SIZE 200

R_API void r_log(RLogLevel level, const char *fmt, ...) {
	switch (level) {
	case R_LOG_DEBUG:
		eprintf ("DEBUG: ");
		break;
	case R_LOG_INFO:
		eprintf ("INFO: ");
		break;
	case R_LOG_WARNING:
		eprintf ("WARNING: ");
		break;
	case R_LOG_ERROR:
		eprintf ("ERROR: ");
		break;
	case R_LOG_CRITICAL:
		eprintf ("CRITICAL: ");
		break;
	default:
		eprintf ("UNKNOWN RLOGLEVEL: ");
		break;
	}

	va_list args;
	va_start (args, fmt);
	vfprintf (stderr, fmt, args);
	va_end (args);
}
