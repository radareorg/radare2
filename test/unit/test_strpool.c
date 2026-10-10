#include <r_util.h>
#include "minunit.h"

bool test_r_strpool_add_dedups(void) {
	RStrpool *p = r_strpool_new ();
	mu_assert_eq (r_strpool_add (p, "alpha"), 0, "first string");
	mu_assert_eq (r_strpool_add (p, "beta"), 1, "second string");
	mu_assert_eq (r_strpool_add (p, "alpha"), 0, "repeated string returns its first position");
	mu_assert_eq (r_strpool_get (p, "gamma"), -1, "missing string");
	mu_assert_eq (p->count, 2, "no duplicate stored");
	mu_assert_streq (r_strpool_get_nth (p, 1), "beta", "nth lookup");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_append_keeps_first(void) {
	RStrpool *p = r_strpool_new ();
	mu_assert_eq (r_strpool_append (p, "x"), 0, "append");
	mu_assert_eq (r_strpool_append (p, "x"), 1, "append does not dedup");
	mu_assert_eq (r_strpool_get (p, "x"), 0, "get finds the first copy");
	mu_assert_eq (r_strpool_append (p, "y"), 2, "append after the index exists");
	mu_assert_eq (r_strpool_get (p, "y"), 2, "indexed on append");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_many(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 5000; i++) {
		char *s = r_str_newf ("/usr/src/lib/file-%d.c", i);
		mu_assert_eq (r_strpool_add (p, s), i, "distinct strings get fresh positions");
		free (s);
	}
	for (i = 0; i < 5000; i += 7) {
		char *s = r_str_newf ("/usr/src/lib/file-%d.c", i);
		mu_assert_eq (r_strpool_add (p, s), i, "strings survive the pool growing");
		free (s);
	}
	mu_assert_eq (p->count, 5000, "nothing duplicated");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_slice_and_empty(void) {
	RStrpool *p = r_strpool_new ();
	r_strpool_add (p, "a");
	r_strpool_add (p, "b");
	r_strpool_add (p, "c");
	r_strpool_slice_range (p, 1, 3);
	mu_assert_eq (p->count, 2, "two strings left");
	mu_assert_eq (r_strpool_get (p, "b"), 0, "positions shift with the slice");
	mu_assert_eq (r_strpool_get (p, "a"), -1, "sliced-out string is gone");
	mu_assert_eq (r_strpool_add (p, "a"), 2, "re-added after the slice");
	r_strpool_empty (p);
	mu_assert_eq (r_strpool_get (p, "c"), -1, "empty pool finds nothing");
	mu_assert_eq (r_strpool_add (p, "c"), 0, "add after empty");
	r_strpool_free (p);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_strpool_add_dedups);
	mu_run_test (test_r_strpool_append_keeps_first);
	mu_run_test (test_r_strpool_many);
	mu_run_test (test_r_strpool_slice_and_empty);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
