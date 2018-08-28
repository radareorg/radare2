#ifndef R_ASSERT_H
#define R_ASSERT_H

R_API void r_log_warn(const char *file, int line, const char *func, const char *warnexpr);
R_API void r_log_return_warn(const char *func, const char *warnexpr);
R_API void r_log_critical(const char *file, int line, const char *func);

#if defined (__GNUC__) && defined (__cplusplus)
#define R_STRFUNC     ((const char*) (__PRETTY_FUNCTION__))
#elif defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define R_STRFUNC     ((const char*) (__func__))
#elif defined (__GNUC__) || (defined(_MSC_VER) && (_MSC_VER > 1300))
#define R_STRFUNC     ((const char*) (__FUNCTION__))
#else
#define R_STRFUNC     ((const char*) ("???"))
#endif

#define r_warn_if_reached() \
	do { \
		r_log_warn (__FILE__, __LINE__, R_STRFUNC, NULL);	\
	} while (0)

#define r_warn_if_fail(expr)					\
	do {								\
		if (!(expr)) {						\
			r_log_warn (__FILE__, __LINE__, R_STRFUNC, #expr);	\
		}							\
	} while (0)

#ifdef R_DISABLE_CHECKS

#define r_return_if_fail(expr) do { (void) 0; } while (0)
#define r_return_val_if_fail(expr, val) do { (void) 0; } while (0)
#define r_return_if_reached() do { return; } while (0)
#define r_return_val_if_reached(val) do { return (val); } while (0)

#else // R_DISABLE_CHECKS

#define r_return_if_fail(expr)					\
	do {							\
		if (!(expr)) {					\
			r_log_return_warn (R_STRFUNC, #expr);	\
			return;					\
		}						\
	} while (0)

#define r_return_val_if_fail(expr, val)				\
	do {							\
		if (!(expr)) {					\
			r_log_return_warn (R_STRFUNC, #expr);	\
			return (val);				\
		}						\
	} while (0)

#define r_return_if_reached()						\
	do {								\
		r_log_critical (__FILE__, __LINE__, R_STRFUNC);	\
		return;							\
	} while (0)

#define r_return_val_if_reached(val)					\
	do {								\
		r_log_critical (__FILE__, __LINE__, R_STRFUNC);	\
		return (val);						\
	} while (0)

#endif // R_DISABLE_CHECKS

#endif
