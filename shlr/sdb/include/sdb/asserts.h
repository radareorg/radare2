#ifndef SDB_ASSERTS_H
#define SDB_ASSERTS_H

#if defined (__cplusplus)
extern "C" {
#endif

#if defined (__GNUC__) && defined (__cplusplus)
#define SDB_FUNCTION ((const char*) (__PRETTY_FUNCTION__))
#elif defined(__STDC__) && defined (__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define SDB_FUNCTION ((const char*) (__func__))
#elif defined (__GNUC__) || (defined(_MSC_VER) && (_MSC_VER > 1300))
#define SDB_FUNCTION ((const char*) (__FUNCTION__))
#else
#warning Do not know how to get function name in this setup
#define SDB_FUNCTION ((const char*) ("???"))
#endif

/*
 * SDB_CHECKS_LEVEL determines the behaviour of the sdb_return_* set of functions.
 *
 * 0: completely disable every function and make them like no-operation
 * 1: silently enable checks. Check expressions and do return, but do not log anything
 * 2: enable checks and logging (DEFAULT)
 * 3: transform them into real assertion
 */
#ifndef SDB_CHECKS_LEVEL
#define SDB_CHECKS_LEVEL 2
#endif

#if SDB_CHECKS_LEVEL == 0

#define sdb_return_if_fail(expr) do { ; } while(0)
#define sdb_return_val_if_fail(expr, val) do { ; } while(0)

#elif SDB_CHECKS_LEVEL == 1 || SDB_CHECKS_LEVEL == 2 // SDB_CHECKS_LEVEL

#if SDB_CHECKS_LEVEL == 1
#define SDB_LOG_(fmt, ...)
#else
#define SDB_LOG_(fmt, ...) eprintf (fmt, __VA_ARGS__)
#endif

/**
 * sdb_return_if_fail:
 * @expr: the expression to check
 *
 * Verifies that the expression @expr, usually representing a precondition,
 * evaluates to `true`. If the function returns a value, use
 * sdb_return_val_if_fail() instead.
 *
 * If @expr evaluates to %FALSE, the current function should be considered to
 * have undefined behaviour (a programmer error). The only correct solution
 * to such an error is to change the module that is calling the current
 * function, so that it avoids this incorrect call.
 *
 * To make this undefined behaviour visible, if @expr evaluates to %FALSE,
 * the result is usually that a critical message is logged and the current
 * function returns.
 */
#define sdb_return_if_fail(expr) \
	do { \
		if (!(expr)) { \
			SDB_LOG_ ("%s: assertion '%s' failed (line %d)", SDB_FUNCTION, #expr, __LINE__); \
			return; \
		} \
	} while (0)

#define sdb_return_val_if_fail(expr, val) \
	do { \
		if (!(expr)) { \
			SDB_LOG_ ("%s: assertion '%s' failed (line %d)", SDB_FUNCTION, #expr, __LINE__); \
			return (val); \
		} \
	} while (0)

#else // SDB_CHECKS_LEVEL

#include <assert.h>

#define sdb_return_if_fail(expr) do { assert (expr); } while(0)
#define sdb_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define sdb_return_if_reached() do { assert (false); } while(0)
#define sdb_return_val_if_reached(val) do { assert (false); } while(0)

#endif // SDB_CHECKS_LEVEL

#ifdef __cplusplus
}
#endif

#endif
