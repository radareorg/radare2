/* radare2 - LGPL - Copyright 2018-2025 - ret2libc */

#include <r_util.h>

#ifdef R2_ASSERT_STDOUT
static void stdout_log(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) {
	printf ("%s", output);
}

static void print_message(RLogLevel level, const char *origin, const char *fmt, va_list ap) {
	r_log_add_callback (stdout_log);
	r_log_vmessage (level, origin, fmt, ap);
	r_log_del_callback (stdout_log);
}
#else
static void print_message(RLogLevel level, const char *origin, const char *fmt, va_list ap) {
	r_log_vmessage (level, origin, __FILE__, __LINE__, fmt, ap);
}
#endif
/*
 * Prints a message to the log and it provides a single point in
 * case of debugging. All R_RETURN_* macros call this function.
 */
R_API void r_assert_log(RLogLevel level, const char *origin, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	print_message (level, origin, fmt, args);
	va_end (args);
	char *env = r_sys_getenv ("R2_DEBUG_ASSERT");
	if (env) {
		r_sys_backtrace ();
		if (*env && atoi (env)) {
			r_sys_breakpoint ();
		}
		free (env);
	}
}
