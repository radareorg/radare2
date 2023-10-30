#ifndef R_ASSERT_H
#define R_ASSERT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "r_log.h"

#define R_STATIC_ASSERT(x) switch (0) { case 0: case (x):; }

R_API void r_assert_log(RLogLevel level, const char *origin, const char *fmt, ...) R_PRINTF_CHECK(3, 4);

#if defined (__GNUC__) && defined (__cplusplus)
#define R_FUNCTION ((const char*) (__PRETTY_FUNCTION__))
#elif defined(__STDC__) && defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define R_FUNCTION ((const char*) (__func__))
#elif defined (__GNUC__) || (defined(_MSC_VER) && (_MSC_VER > 1300))
#define R_FUNCTION ((const char*) (__FUNCTION__))
#else
#warning Do not know how to get function name in this setup
#define R_FUNCTION ((const char*) ("???"))
#endif

#define r_warn_if_reached() \
	do { \
		r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "(%s:%d):%s%s code should not be reached", \
			__FILE__, __LINE__, R_FUNCTION, R_FUNCTION[0] ? ":" : ""); \
	} while (0)

#define r_warn_if_fail(expr) \
	do { \
		if (R_UNLIKELY (!(expr))) { \
			r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "WARNING (%s:%d):%s%s runtime check failed: (%s)", \
				__FILE__, __LINE__, R_FUNCTION, R_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)

/*
 * R_CHECKS_LEVEL determines the behaviour of the r_return_* set of functions.
 *
 * 0: completely disable every function and make them like no-operation
 * 1: silently enable checks. Check expressions and do return, but do not log anything
 * 2: enable checks and logging (DEFAULT)
 * 3: transform them into real assertion
 */
#ifndef R_CHECKS_LEVEL
#define R_CHECKS_LEVEL 2
#endif

#if R_CHECKS_LEVEL == 0

#define r_return_if_fail(expr) do { ; } while(0)
#define r_return_val_if_fail(expr, val) do { ; } while(0)
#define r_return_if_reached() do { ; } while(0)
#define r_return_val_if_reached(val) do { ; } while(0)

#elif R_CHECKS_LEVEL == 1 || R_CHECKS_LEVEL == 2 // R_CHECKS_LEVEL

#if R_CHECKS_LEVEL == 1
#define H_LOG_(loglevel, fmt, ...)
#else
#define H_LOG_(loglevel, fmt, ...) r_assert_log (loglevel, R_LOG_ORIGIN, fmt, __VA_ARGS__)
#endif

/**
 * r_return_if_fail:
 * @expr: the expression to check
 *
 * Verifies that the expression @expr, usually representing a precondition,
 * evaluates to `true`. If the function returns a value, use
 * r_return_val_if_fail() instead.
 *
 * If @expr evaluates to %FALSE, the current function should be considered to
 * have undefined behaviour (a programmer error). The only correct solution
 * to such an error is to change the module that is calling the current
 * function, so that it avoids this incorrect call.
 *
 * To make this undefined behaviour visible, if @expr evaluates to %FALSE,
 * the result is usually that a critical message is logged and the current
 * function returns.
 *
 */
#define r_return_if_fail(expr) \
	do { \
		if (R_UNLIKELY (!(expr))) { \
			H_LOG_ (R_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)", R_FUNCTION, #expr, __LINE__); \
			return; \
		} \
	} while (0)

#define r_return_val_if_fail(expr, val) \
	do { \
		if (R_UNLIKELY (!(expr))) { \
			H_LOG_ (R_LOGLVL_WARN, "%s: assertion '%s' failed (line %d)", R_FUNCTION, #expr, __LINE__); \
			return (val); \
		} \
	} while (0)

#define r_return_if_reached() \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", __FILE__, __LINE__, R_FUNCTION); \
		return; \
	} while (0)

#define r_return_val_if_reached(val) \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", __FILE__, __LINE__, R_FUNCTION); \
		return (val); \
	} while (0)

#else // R_CHECKS_LEVEL

#include <assert.h>

#define r_return_if_fail(expr) do { assert (expr); } while(0)
#define r_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define r_return_if_reached() do { assert (false); } while(0)
#define r_return_val_if_reached(val) do { assert (false); } while(0)

#endif // R_CHECKS_LEVEL

#ifdef __cplusplus
}
#endif

#endif
