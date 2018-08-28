#include <r_util.h>

#define S_SIZE 200

R_API void r_log_warn(const char *file, int line, const char *func, const char *warnexpr) {
	char s[S_SIZE];

	s[0] = '\0';
	if (warnexpr) {
		snprintf (s, S_SIZE, "(%s:%d):%s%s runtime check failed: (%s)\n",
			  file, line, func, func[0] ? ":" : "", warnexpr);
	} else {
		snprintf (s, S_SIZE, "(%s:%d):%s%s code should not be reached\n",
			  file, line, func, func[0] ? ":" : "");
	}
	eprintf ("WARNING: %s", s);
}

R_API void r_log_return_warn(const char *func, const char *expr) {
	eprintf ("WARNING: %s: assertion '%s' failed\n", func, expr);
}

R_API void r_log_critical(const char *file, int line, const char *func) {
	eprintf ("CRITICAL: file %s: line %d (%s): should not be reached\n", file, line, func);
}
