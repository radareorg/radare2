#include <r_util.h>
#include "minunit.h"

static int add_nth(RStrpool *p, int n) {
	char *s = r_str_newf ("/usr/src/lib/file-%d.c", n);
	const int pos = r_strpool_add (p, s);
	free (s);
	return pos;
}

static int get_nth(RStrpool *p, int n) {
	char *s = r_str_newf ("/usr/src/lib/file-%d.c", n);
	const int pos = r_strpool_get (p, s);
	free (s);
	return pos;
}

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

bool test_r_strpool_empty_string_first(void) {
	RStrpool *p = r_strpool_new ();
	mu_assert_eq (r_strpool_add (p, ""), 0, "empty string first");
	mu_assert_eq (p->count, 1, "and it is stored");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_append_keeps_first(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 100; i++) {
		add_nth (p, i);
	}
	mu_assert_eq (r_strpool_append (p, "/usr/src/lib/file-5.c"), 100, "append does not dedup");
	mu_assert_eq (get_nth (p, 5), 5, "get finds the first copy");
	mu_assert_eq (add_nth (p, 5), 5, "add finds the first copy");
	mu_assert_eq (r_strpool_append (p, "y"), 101, "append a new string");
	mu_assert_eq (r_strpool_get (p, "y"), 101, "appended string is found");
	mu_assert_eq (r_strpool_add (p, "y"), 101, "appended string is deduplicated");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_add_returns_first(void) {
	RStrpool *p = r_strpool_new ();
	int first[500];
	int i, next = 0;
	for (i = 0; i < 500; i++) {
		first[i] = -1;
	}
	for (i = 0; i < 3000; i++) {
		const int n = (i * 37) % 500;
		if (first[n] < 0) {
			first[n] = next++;
		}
		mu_assert_eq (add_nth (p, n), first[n], "add returns the first position");
		mu_assert_eq (add_nth (p, n), first[n], "repeated add returns it again");
	}
	mu_assert_eq (p->count, 500, "each string stored once");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_append_duplicates(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 3000; i++) {
		add_nth (p, i);
		r_strpool_append (p, "/usr/src/lib/file-7.c");
	}
	mu_assert_eq (get_nth (p, 7), 1, "get finds the first copy among appended duplicates");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_many(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 5000; i++) {
		mu_assert_eq (add_nth (p, i), i, "distinct strings get fresh positions");
	}
	for (i = 0; i < 5000; i += 7) {
		mu_assert_eq (add_nth (p, i), i, "strings survive the pool reallocating");
	}
	mu_assert_eq (p->count, 5000, "nothing duplicated");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_slice_and_empty(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 100; i++) {
		add_nth (p, i);
	}
	r_strpool_slice_range (p, 50, 100);
	mu_assert_eq (p->count, 50, "fifty strings left");
	mu_assert_eq (get_nth (p, 60), 10, "positions shift with the slice");
	mu_assert_eq (get_nth (p, 10), -1, "sliced-out string is gone");
	mu_assert_eq (add_nth (p, 10), 50, "re-added after the slice");
	r_strpool_slice (p, 20);
	mu_assert_eq (get_nth (p, 75), -1, "string past the slice is gone");
	mu_assert_eq (add_nth (p, 75), 20, "re-added after the slice");
	r_strpool_empty (p);
	mu_assert_eq (get_nth (p, 60), -1, "empty pool finds nothing");
	mu_assert_eq (add_nth (p, 60), 0, "add after empty");
	mu_assert_eq (add_nth (p, 61), 1, "second add after empty");
	mu_assert_eq (add_nth (p, 60), 0, "nothing from before the empty is found");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_truncate(void) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < 100; i++) {
		add_nth (p, i);
	}
	r_strpool_slice_range (p, 0, 10);
	mu_assert_eq (p->count, 10, "ten strings left");
	mu_assert_eq (get_nth (p, 50), -1, "truncated string is gone");
	mu_assert_eq (add_nth (p, 50), 10, "re-added after the truncate");
	r_strpool_free (p);
	mu_end;
}

// append can store duplicates, so a stale previous hit could name a later copy
bool test_r_strpool_last_reset(void) {
	RStrpool *p = r_strpool_new ();
	r_strpool_add (p, "a");
	r_strpool_add (p, "b");
	r_strpool_empty (p);
	r_strpool_append (p, "a");
	r_strpool_append (p, "a");
	mu_assert_eq (r_strpool_add (p, "a"), 0, "first copy after an empty");
	r_strpool_free (p);
	p = r_strpool_new ();
	r_strpool_append (p, "a");
	r_strpool_append (p, "x");
	r_strpool_add (p, "x");
	r_strpool_slice (p, 1);
	r_strpool_append (p, "a");
	mu_assert_eq (r_strpool_add (p, "a"), 0, "first copy after a slice");
	r_strpool_free (p);
	p = r_strpool_new ();
	r_strpool_add (p, "a");
	r_strpool_add (p, "b");
	r_strpool_add (p, "c");
	r_strpool_slice_range (p, 0, 1);
	r_strpool_append (p, "b");
	r_strpool_append (p, "a");
	mu_assert_eq (r_strpool_add (p, "a"), 0, "first copy after a truncate");
	r_strpool_free (p);
	p = r_strpool_new ();
	r_strpool_add (p, "z");
	r_strpool_add (p, "a");
	r_strpool_add (p, "q");
	r_strpool_append (p, "a");
	r_strpool_add (p, "q");
	r_strpool_slice_range (p, 1, 4);
	mu_assert_eq (r_strpool_add (p, "a"), 0, "first copy after a shifting slice");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_last_after_slice(void) {
	RStrpool *p = r_strpool_new ();
	r_strpool_add (p, "a");
	r_strpool_add (p, "b");
	r_strpool_add (p, "c");
	r_strpool_slice_range (p, 1, 3);
	mu_assert_eq (r_strpool_add (p, "c"), 1, "previous hit does not survive a slice");
	mu_assert_eq (r_strpool_add (p, "b"), 0, "previous hit miss falls back to lookup");
	r_strpool_free (p);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_strpool_add_dedups);
	mu_run_test (test_r_strpool_empty_string_first);
	mu_run_test (test_r_strpool_append_keeps_first);
	mu_run_test (test_r_strpool_add_returns_first);
	mu_run_test (test_r_strpool_append_duplicates);
	mu_run_test (test_r_strpool_many);
	mu_run_test (test_r_strpool_slice_and_empty);
	mu_run_test (test_r_strpool_truncate);
	mu_run_test (test_r_strpool_last_reset);
	mu_run_test (test_r_strpool_last_after_slice);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
