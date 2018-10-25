#include <r_util.h>

/*
 * It prints a message to the log and it provides a single point of entrance in
 * case of debugging. All r_return_* functions call this.
 */
R_API void r_assert_log(RLogLevel level, const char *fmt, ...) {
	va_list args;
	va_start (args, fmt);
	r_vlogf (level, fmt, args);
	va_end (args);
	char *env = r_sys_getenv ("R_DEBUG_ASSERT");
	if (env) {
		if (*env && atoi (env)) {
			r_sys_breakpoint ();
		}
		free (env);
	}
}
