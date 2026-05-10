#include <r_util.h>
#include "minunit.h"

bool test_basic_set_test_unset(void) {
	RBitset *b = r_bitset_new ();
	mu_assert_notnull (b, "alloc");
	mu_assert_eq (r_bitset_count (b), 0, "empty count");
	mu_assert_eq (r_bitset_test (b, 42), false, "empty test");

	mu_assert_eq (r_bitset_set (b, 42), true, "newly set");
	mu_assert_eq (r_bitset_set (b, 42), false, "already set");
	mu_assert_eq (r_bitset_test (b, 42), true, "set");
	mu_assert_eq (r_bitset_count (b), 1, "count 1");

	mu_assert_eq (r_bitset_unset (b, 42), true, "unset existed");
	mu_assert_eq (r_bitset_unset (b, 42), false, "unset gone");
	mu_assert_eq (r_bitset_test (b, 42), false, "test after unset");
	mu_assert_eq (r_bitset_count (b), 0, "count 0");
	r_bitset_free (b);
	mu_end;
}

bool test_large_sparse_keys(void) {
	RBitset *b = r_bitset_new ();
	const ut64 keys[] = {
		0, 1, 63, 64, 65,
		4095, 4096, 4097,
		1ULL << 20,
		1ULL << 40,
		(1ULL << 40) + 7,
		UT64_MAX - 1,
	};
	const int n = sizeof (keys) / sizeof (keys[0]);
	int i;
	for (i = 0; i < n; i++) {
		mu_assert_eq (r_bitset_set (b, keys[i]), true, "newly set");
	}
	mu_assert_eq (r_bitset_count (b), n, "count");
	for (i = 0; i < n; i++) {
		mu_assert_eq (r_bitset_test (b, keys[i]), true, "still set");
	}
	mu_assert_eq (r_bitset_test (b, 100), false, "untouched");
	mu_assert_eq (r_bitset_test (b, (1ULL << 40) + 1), false, "near miss");
	r_bitset_free (b);
	mu_end;
}

bool test_find_next_in_order(void) {
	RBitset *b = r_bitset_new ();
	ut64 keys[] = { 0, 5, 100, 4097, 1ULL << 30, (1ULL << 30) + 7 };
	int n = sizeof (keys) / sizeof (keys[0]);
	int i;
	for (i = 0; i < n; i++) {
		r_bitset_set (b, keys[i]);
	}
	ut64 cur = r_bitset_find_next (b, 0);
	for (i = 0; i < n; i++) {
		mu_assert_eq (cur, keys[i], "ordered iteration");
		cur = r_bitset_find_next (b, cur + 1);
	}
	mu_assert_eq (cur, UT64_MAX, "exhausted");

	mu_assert_eq (r_bitset_find_next (b, 1), 5, "skips 0");
	mu_assert_eq (r_bitset_find_next (b, 100), 100, "exact hit");
	mu_assert_eq (r_bitset_find_next (b, 101), 4097, "next chunk");
	mu_assert_eq (r_bitset_find_next (b, (1ULL << 30) + 8), UT64_MAX, "past end");
	r_bitset_free (b);
	mu_end;
}

static bool collect_cb(ut64 bit, void *user) {
	*((ut64 *)user) ^= bit;
	return true;
}

bool test_foreach_visits_all(void) {
	RBitset *b = r_bitset_new ();
	ut64 expected = 0;
	ut64 keys[] = { 7, 63, 64, 4095, 4096, 8192, 1ULL << 30 };
	int n = sizeof (keys) / sizeof (keys[0]);
	int i;
	for (i = 0; i < n; i++) {
		r_bitset_set (b, keys[i]);
		expected ^= keys[i];
	}
	ut64 acc = 0;
	r_bitset_foreach (b, collect_cb, &acc);
	mu_assert_eq (acc, expected, "xor of visited == xor of inserted");
	r_bitset_free (b);
	mu_end;
}

bool test_chunk_freed_when_empty(void) {
	RBitset *b = r_bitset_new ();
	const ut64 base = 1ULL << 40;
	int i;
	for (i = 0; i < 100; i++) {
		r_bitset_set (b, base + i);
	}
	mu_assert_eq (r_bitset_count (b), 100, "100 set");
	for (i = 0; i < 100; i++) {
		r_bitset_unset (b, base + i);
	}
	mu_assert_eq (r_bitset_count (b), 0, "all cleared");
	mu_assert_eq (b->idxs_count, 0, "chunk index array drained");
	mu_assert_eq (r_bitset_find_next (b, 0), UT64_MAX, "no bits");
	r_bitset_free (b);
	mu_end;
}

bool test_reset(void) {
	RBitset *b = r_bitset_new ();
	r_bitset_set (b, 1);
	r_bitset_set (b, 1ULL << 50);
	r_bitset_reset (b);
	mu_assert_eq (r_bitset_count (b), 0, "count after reset");
	mu_assert_eq (r_bitset_test (b, 1), false, "low bit gone");
	mu_assert_eq (r_bitset_test (b, 1ULL << 50), false, "high bit gone");
	r_bitset_set (b, 99);
	mu_assert_eq (r_bitset_test (b, 99), true, "still usable");
	r_bitset_free (b);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_basic_set_test_unset);
	mu_run_test (test_large_sparse_keys);
	mu_run_test (test_find_next_in_order);
	mu_run_test (test_foreach_visits_all);
	mu_run_test (test_chunk_freed_when_empty);
	mu_run_test (test_reset);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
