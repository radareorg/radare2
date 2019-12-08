// minunit.h comes from http://www.jera.com/techinfo/jtns/jtn002.html
//
// You may use the code in this tech note for any purpose,
// with the understanding that it comes with NO WARRANTY.

#ifndef TERMCOLOR_H
#define TERMCOLOR_H

#define TRED     "\x1b[31m"
#define TGREEN   "\x1b[32m"
#define TYELLOW  "\x1b[33m"
#define TBLUE    "\x1b[34m"
#define TMAGENTA "\x1b[35m"
#define TCYAN    "\x1b[36m"
#define TBOLD    "\x1b[1m"
#define TRESET   "\x1b[0m"
#endif

#define MU_PASSED 1
#define MU_ERR 0

#define MU_TEST_UNBROKEN 0
#define MU_TEST_BROKEN 1

void sprint_mem(char *out, const ut8 *buf, size_t len) {
	size_t i;
	*out = '\0';
	for (i = 0; i < len; i++) {
		if (i > 0) {
			sprintf(out + strlen(out), " ");
		}
		sprintf (out + strlen(out), "%02x", buf[i]);
	}
}

#define mu_assert(message, test) do { \
		if (!(test)) { \
						mu_fail(message); \
						mu_test_status = MU_TEST_UNBROKEN; \
					} \
		} while (0)

#define mu_perror(message) do { \
		if (mu_test_status != MU_TEST_BROKEN) { \
			printf(TBOLD TRED "ERR\n[XX] Fail at line %d: " TRESET "%s\n\n", __LINE__, message); \
		} else { \
			printf(TBOLD TYELLOW "Broken at line %d: " TRESET "%s\n\n", __LINE__, message); \
		} \
	} while (0)

#define mu_psyserror(message) do { perror(message); mu_perror(message); } while (0)

#define mu_fail(message) do { mu_perror(message); if (mu_test_status != MU_TEST_BROKEN) return MU_ERR; } while(0)

#define mu_ignore do { printf(TYELLOW "IGN\n" TRESET); return MU_PASSED; } while(0)

#define mu_end do { \
		printf(TGREEN "OK\n" TRESET); \
		return MU_PASSED; \
} while(0)

#define mu_cleanup_end do { \
		if(retval == MU_PASSED) { mu_end; } \
		else { return retval; } \
} while(0)

#define mu_sysfail(message) do { perror(message); mu_fail(message); } while(0)

#define mu_assert_eq(actual, expected, message) do { \
		if ((expected) != (actual)) { \
			char _meqstr[2048]; \
			sprintf(_meqstr, "%s: expected %" PFMT64d ", got %" PFMT64d ".", (message), (ut64)(expected), (ut64)(actual)); \
			mu_assert(_meqstr, false); \
		} \
} while(0)

#define mu_assert_neq(actual, expected, message) do { \
		char _meqstr[2048]; \
		sprintf(_meqstr, "%s: expected not %" PFMT64d ", got %" PFMT64d ".", (message), (expected), (actual)); \
		mu_assert(_meqstr, (expected) != (actual)); \
} while(0)

#define mu_assert_ptreq(actual, expected, message) do {	\
	char _meqstr[2048]; \
	sprintf (_meqstr, "%s: expected %p, got %p.", (message), (expected), (actual)); \
	mu_assert (_meqstr, (expected) == (actual)); \
} while (0)

#define mu_assert_ptrneq(actual, expected, message) do { \
	char _meqstr[2048]; \
	sprintf (_meqstr, "%s: expected not %p, got %p.", (message), (expected), (actual)); \
	mu_assert (_meqstr, (expected) != (actual)); \
} while (0)

#define mu_assert_null(actual, message) do {			\
	char _meqstr[2048];					\
	sprintf(_meqstr, "%s: expected to be NULL but it wasn't.", (message)); \
	mu_assert(_meqstr, (actual) == NULL);		\
} while(0)

#define mu_assert_notnull(actual, message) do {				\
	char _meqstr[2048];					\
	sprintf(_meqstr, "%s: expected to not be NULL but it was.", (message)); \
	mu_assert(_meqstr, (actual) != NULL);			\
} while(0)

#define mu_assert_eq_fmt(actual, expected, message, fmt) do { \
		if ((expected) != (actual)) { \
			char _meqstr[2048]; \
			sprintf(_meqstr, "%s: expected "fmt", got "fmt".", (message), (expected), (actual)); \
			mu_assert(_meqstr, false); \
		} \
} while(0)

#define mu_assert_streq(actual, expected, message) do { \
		char _meqstr[2048]; \
		sprintf(_meqstr, "%s: expected %s, got %s.", (message), (expected), (actual)); \
		mu_assert(_meqstr, strcmp((expected), (actual)) == 0); \
} while(0)

#define mu_assert_memeq(actual, expected, len, message) do { \
		char _meqstr[2048]; \
		sprintf(_meqstr, "%s: expected ", message); \
		sprint_mem(_meqstr + strlen(_meqstr), (expected), (len)); \
		sprintf(_meqstr + strlen(_meqstr), ", got "); \
		sprint_mem(_meqstr + strlen(_meqstr), (actual), (len)); \
		mu_assert(_meqstr, memcmp((expected), (actual), (len)) == 0); \
} while(0)

#define mu_run_test(test) do { int result; \
		printf(TBOLD #test TRESET " "); \
		result = test(); \
		tests_run++; \
		tests_passed += result; \
} while (0)

#define mu_cleanup_fail(label, message) do { mu_perror(message); retval = MU_ERR; goto label; } while(0)
#define mu_cleanup_sysfail(label, message) do { mu_psyserror(message); retval = MU_ERR; goto label; } while(0)
int tests_run = 0;
int tests_passed = 0;
int mu_test_status = MU_TEST_UNBROKEN;
