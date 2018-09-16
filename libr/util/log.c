/* radare - LGPL - Copyright 2007-2013 - pancake */

#include <r_util.h>

#define LOG_BUF_SZ 128

static const char *logfile = "radare.log";

R_API void r_log_file(const char *str) {
	FILE *fd = r_sandbox_fopen (logfile, "a+");
	if (fd) {
		fputs (str, fd);
		fclose (fd);
	} else {
		eprintf ("ERR: Cannot open %s\n", logfile);
	}
}

R_API void r_log_msg(const char *str) {
	fputs ("LOG: ", stderr);
	fputs (str, stderr);
	r_log_file (str);
}

R_API void r_log_error(const char *str) {
	fputs ("ERR: ", stderr);
	fputs (str, stderr);
	r_log_file (str);
}

R_API void r_log_progress(const char *str, int percent) {
	printf ("%d%%: %s\n", percent, str);
}

R_API void r_vlogf(RLogLevel level, const char *fmt, va_list ap) {
	static const char *headers[R_LOG_MAX_VALUE] = {
		[R_LOG_DEBUG] = "DEBUG: ",
		[R_LOG_INFO] = "INFO: ",
		[R_LOG_WARNING] = "WARNING: ",
		[R_LOG_ERROR] = "ERROR: ",
		[R_LOG_CRITICAL] = "CRITICAL: ",
	};

	const char *hdr = R_BETWEEN (0, level, R_LOG_MAX_VALUE - 1) ? headers[level] : "";
	size_t len = strlen (hdr);
	char buf[LOG_BUF_SZ];

	snprintf (buf, sizeof (buf), "%s", hdr);
	if (len < sizeof (buf)) {
		vsnprintf (buf + len, sizeof (buf) - len, fmt, ap);
	}
	eprintf ("%s", buf);
}

/*
 * Prints a formatted string on the selected log support (only stderr for now)
 */
R_API void r_logf(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	r_vlogf (level, fmt, args);
	va_end (args);
}
