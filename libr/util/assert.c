#include <r_util.h>

#ifdef R2_ASSERT_STDOUT
static void stdout_log(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RLogLevel level, const char *tag, const char *fmtstr, ...) {
	printf ("%s", output);
}

static void print_message(RLogLevel level, const char *fmt, va_list args) {
	r_log_add_callback (stdout_log);
	R_VLOG (level, NULL, fmt, args);
	r_log_del_callback (stdout_log);
}
#else
static void print_message(RLogLevel level, const char *fmt, va_list args) {
	R_VLOG (level, NULL, fmt, args);
}
#endif
/*
 * It prints a message to the log and it provides a single point of entrance in
 * case of debugging. All r_return_* functions call this.
 */
R_API void r_assert_log(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	print_message (level, fmt, args);
	va_end (args);
	char *env = r_sys_getenv ("R_DEBUG_ASSERT");
	if (env) {
		r_sys_backtrace ();
		if (*env && atoi (env)) {
			r_sys_breakpoint ();
		}
		free (env);
	}
}
