/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_util.h>

static RLog log_g = NULL;
static RLogF logf_g = NULL;

R_API void r_log_set(RLog log, RLogF logf) {
	log_g = log;
	logf_g = logf;
}

R_API void r_log(RLogLevel level, const char *str) {
	if (log_g) {
		log_g (level, str);
	} else {
		fprintf (stderr, "%s", str);
	}
}

R_API void r_logf_list(RLogLevel level, const char *format, va_list ap) {
	if (logf_g) {
		logf_g (level, format, ap);
	} else {
		vfprintf (stderr, format, ap);
	}
}

R_API void r_logf(RLogLevel level, const char *format, ...) {
	(void)level;
	va_list ap;
	if (!format || !*format) {
		return;
	}
	va_start (ap, format);
	r_logf_list (level, format, ap);
	va_end (ap);
}