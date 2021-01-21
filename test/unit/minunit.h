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

#define MU_BUF_SIZE 5120

void snprint_mem(char *out, size_t out_size, const ut8 *buf, size_t len) {
	size_t i;
	*out = '\0';
	for (i = 0; i < len; i++) {
		size_t out_len;
		if (i > 0) {
			out_len = strlen (out);
			snprintf (out + out_len, out_size - out_len, " ");
		}
		out_len = strlen (out);
		snprintf (out + out_len, out_size - out_len, "%02x", buf[i]);
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

#define mu_assert_true(actual, message) do { \
		bool act__ = (actual); \
		if (!(act__)) { \
			char _meqstr[MU_BUF_SIZE]; \
			snprintf (_meqstr, MU_BUF_SIZE, "%s: expected true, got false", (message)); \
			mu_assert (_meqstr, false); \
		} \
	} while (0)

#define mu_assert_false(actual, message) \
	do { \
		bool act__ = (actual); \
		if ((act__)) { \
			char _meqstr[MU_BUF_SIZE]; \
			snprintf (_meqstr, MU_BUF_SIZE, "%s: expected false, got true", (message)); \
			mu_assert (_meqstr, false); \
		} \
	} while (0)

#define mu_assert_eq(actual, expected, message) do { \
		ut64 act__ = (ut64)(actual); \
		ut64 exp__ = (ut64)(expected); \
		if ((exp__) != (act__)) { \
			char _meqstr[MU_BUF_SIZE]; \
			snprintf (_meqstr, MU_BUF_SIZE, "%s: expected %" PFMT64d ", got %" PFMT64d ".", (message), (ut64)(exp__), (ut64)(act__)); \
			mu_assert(_meqstr, false); \
		} \
	} while(0)

#define mu_assert_neq(actual, expected, message) do { \
		char _meqstr[MU_BUF_SIZE]; \
		ut64 act__ = (ut64)(actual); \
		ut64 exp__ = (ut64)(expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected not %" PFMT64d ", got %" PFMT64d ".", (message), (exp__), (act__)); \
		mu_assert(_meqstr, (exp__) != (act__)); \
	} while(0)

#define mu_assert_ptreq(actual, expected, message) do {	\
		char _meqstr[MU_BUF_SIZE]; \
		const void *act__ = (actual); \
		const void *exp__ = (expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected %p, got %p.", (message), (exp__), (act__)); \
		mu_assert (_meqstr, (exp__) == (act__)); \
	} while (0)

#define mu_assert_ptrneq(actual, expected, message) do { \
		char _meqstr[MU_BUF_SIZE]; \
		const void *act__ = (actual); \
		const void *exp__ = (expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected not %p, got %p.", (message), (exp__), (act__)); \
		mu_assert (_meqstr, (exp__) != (act__)); \
	} while (0)

#define mu_assert_null(actual, message) do {			\
		char _meqstr[MU_BUF_SIZE];					\
		const void *act__ = (actual); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected to be NULL but it wasn't.", (message)); \
		mu_assert(_meqstr, (act__) == NULL);		\
	} while(0)

#define mu_assert_notnull(actual, message) do {				\
		char _meqstr[MU_BUF_SIZE];					\
		const void *act__ = (actual); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected to not be NULL but it was.", (message)); \
		mu_assert(_meqstr, (act__) != NULL);			\
	} while(0)

#define mu_assert_eq_fmt(actual, expected, message, fmt) do { \
		ut64 act__ = (ut64)(actual); \
		ut64 exp__ = (ut64)(expected); \
		if ((exp__) != (act__)) { \
			char _meqstr[MU_BUF_SIZE]; \
			snprintf (_meqstr, MU_BUF_SIZE, "%s: expected "fmt", got "fmt".", (message), (exp__), (act__)); \
			mu_assert(_meqstr, false); \
		} \
	} while(0)

#define mu_assert_streq(actual, expected, message) do { \
		char _meqstr[MU_BUF_SIZE]; \
		const char *act__ = (actual); \
		const char *exp__ = (expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected %s, got %s.", (message), (exp__), (act__)); \
		mu_assert(_meqstr, strcmp((exp__), (act__)) == 0); \
} while(0)

#define mu_assert_streq_free(actual, expected, message) do { \
		char *act2__ = (actual); \
		mu_assert_streq (act2__, (expected), (message)); \
		free (act2__); \
} while (0)

#define mu_assert_nullable_streq(actual, expected, message) do { \
		char _meqstr[MU_BUF_SIZE]; \
		const char *act__ = (actual); \
		const char *exp__ = (expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected %s, got %s.", (message), (exp__ ? exp__ : "NULL"), (act__ ? act__ : "NULL")); \
		mu_assert(_meqstr, ((act__) == NULL && (exp__) == NULL) || ((act__) != NULL && (exp__) != NULL && strcmp((exp__), (act__)) == 0)); \
} while(0)

#define mu_assert_memeq(actual, expected, len, message) do { \
		char _meqstr[MU_BUF_SIZE]; \
		size_t _meqstr_len; \
		const ut8 *act__ = (actual); \
		const ut8 *exp__ = (expected); \
		snprintf (_meqstr, MU_BUF_SIZE, "%s: expected ", message); \
		_meqstr_len = strlen (_meqstr); \
		snprint_mem (_meqstr + _meqstr_len, MU_BUF_SIZE - _meqstr_len, (exp__), (len)); \
		_meqstr_len = strlen (_meqstr); \
		snprintf (_meqstr + _meqstr_len, MU_BUF_SIZE - _meqstr_len, ", got "); \
		_meqstr_len = strlen (_meqstr); \
		snprint_mem (_meqstr + _meqstr_len, MU_BUF_SIZE - _meqstr_len, (act__), (len)); \
		mu_assert(_meqstr, memcmp((exp__), (act__), (len)) == 0); \
} while(0)

#define mu_run_test_named(test, name, ...) do { int result; \
		printf(TBOLD "%s" TRESET " ", name); \
		result = test(__VA_ARGS__); \
		tests_run++; \
		tests_passed += result; \
} while (0)

#define mu_run_test(test, ...) mu_run_test_named (test, #test, __VA_ARGS__)

#define mu_cleanup_fail(label, message) do { mu_perror(message); retval = MU_ERR; goto label; } while(0)
#define mu_cleanup_sysfail(label, message) do { mu_psyserror(message); retval = MU_ERR; goto label; } while(0)
int tests_run = 0;
int tests_passed = 0;
int mu_test_status = MU_TEST_UNBROKEN;
