#include <stdio.h>
#include <r_regex.h>
#include "minunit.h"

static int test_regex(void) {
	RRegex rx;
	int rc = r_regex_init (&rx, "hi", R_REGEX_NOSUB);
	if (rc) {
		printf ("error\n");
	} else {
		#define NMATCH 32
		RRegexMatch pmatch[NMATCH] = {0};
		memset (pmatch, 0, sizeof (RRegexMatch) * NMATCH);
		rc = r_regex_exec (&rx, "patata", NMATCH, pmatch, 0);
		mu_assert_eq (rc, R_REGEX_NOMATCH, "'mov eax'~=/patata/");

		rc = r_regex_exec (&rx, "hillow", 0, 0, 0);
		mu_assert_eq (rc, 0, "/hi/~=/hillow/");

		rc = r_regex_exec (&rx, "x", 0, 0, 0);
		mu_assert_eq (rc, 1, "/hi/~=/x/");
	}
	r_regex_fini (&rx);
	mu_end;
}

static int test_or(void) {
	int res;
	res = r_regex_match ("(eax|ebx)", "e", "mov eax");
	mu_assert_eq (res, 1, "mov eax /(eax|ebx)/e");
	// printf ("result (%s) = %d\n", "mov eax", res);

	res = r_regex_match ("(eax|ebx)", "e", "mov ebx");
	mu_assert_eq (res, 1, "mov eax /(eax|ebx)/e");
	// printf ("result (%s) = %d\n", "mov ebx", res);

	res = r_regex_match ("(eax|ebx)", "e", "mov ecx");
	mu_assert_eq (res, 0, "mov eax /(eax|ebx)/e");
	// printf ("result (%s) = %d\n", "mov ecx", res);

	res = r_regex_match ("(eax|ecx)", "e", "mov ebx");
	mu_assert_eq (res, 0, "mov eax /(eax|ebx)/e");
	// printf ("result (%s) = %d\n", "mov ebx", res);

	RRegex *rx = r_regex_new ("(eax|ebx)", "e");
	// expect 0
	res = r_regex_check (rx, "mov eax");
	mu_assert_eq (res, 0, "mov eax /(eax|ebx)/e");
	// expect 0
	res = r_regex_check (rx, "mov ebx");
	mu_assert_eq (res, 0, "mov ebx /(eax|ebx)/e");

	const size_t nmatch = -1;
	RRegexMatch pmatch[32] = {0};

	res = r_regex_exec (rx, "mov eax", nmatch, pmatch, -1);
	if (res == R_REGEX_INVARG) {
		char *e = r_regex_error (rx, res);
		const char *oe = "invalid argument to regex routine";
		mu_assert_streq (e, oe, "r_regex_error");
		free (e);
	} else {
		mu_assert_eq (1, 0, "r_regex_exec compiles invalid regex");
	}

	res = r_regex_exec (rx, "mov eax", nmatch, pmatch, R_REGEX_EXTENDED);
	if (res == R_REGEX_INVARG) {
		char *e = r_regex_error (rx, res);
		const char *oe = "invalid argument to regex routine";
		mu_assert_streq (e, oe, "r_regex_error");
		free (e);
	} else {
		mu_assert_eq (1, 0, "r_regex_exec compiles invalid regex");
	}
	
	r_regex_free (rx);
	rx = r_regex_new ("ebx", "");
	// mu_assert_eq (res, 1, "mov eax001");
	res = r_regex_exec (rx, "mov ebx", 0, NULL, R_REGEX_EXTENDED);
	mu_assert_eq (res, 0, "mov ebx001");

	r_regex_free (rx);
	mu_end;
	return 0;
}

static int test_begin(void) {
	const char *needle = "^hi";
	const char *haystack_1 = "patata";
	const char *haystack_2 = "hillow";
	RRegex *rx = r_regex_new (needle, "");
	if (rx) {
		int res = r_regex_exec (rx, haystack_1, 0, 0, 0);
		mu_assert_eq (res, 1, "result[0]");
		// printf ("result (%s) = %d\n", haystack_1, res);
		// res = r_regex_exec (rx, haystack_2, 0, 0, 0);
		// XXX mu_assert_eq (res, 0, "result[1]");
		// printf ("result (%s) = %d\n", haystack_2, res);

		r_regex_free (rx);
	} else {
		eprintf ("oops, cannot compile regexp\n");
	}
	mu_end;
	return 0;
}

int main(int argc, char **argv) {
	mu_run_test (test_regex);
	mu_run_test (test_or);
	mu_run_test (test_begin);
	return 0;
}
