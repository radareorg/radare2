#define r_strpool_new fault_strpool_new
#define r_strpool_empty fault_strpool_empty
#define r_strpool_slice fault_strpool_slice
#define r_strpool_slice_range fault_strpool_slice_range
#define r_strpool_add fault_strpool_add
#define r_strpool_append fault_strpool_append
#define r_strpool_free fault_strpool_free
#define r_strpool_get_at fault_strpool_get_at
#define r_strpool_get_nth fault_strpool_get_nth
#define r_strpool_lock fault_strpool_lock
#define r_strpool_get fault_strpool_get
#include <r_util.h>
#include "minunit.h"

static int calloc_failures;

static void *fault_calloc(size_t count, size_t size) {
	if (calloc_failures > 0) {
		calloc_failures--;
		return NULL;
	}
	return calloc (count, size);
}

// Keep allocation failures local to the string pool implementation under test.
#define calloc fault_calloc
#include "../../libr/util/strpool.c"
#undef calloc

static RStrpool *filled_pool(int count) {
	RStrpool *p = r_strpool_new ();
	int i;
	for (i = 0; i < count; i++) {
		char name[32];
		snprintf (name, sizeof (name), "entry-%d", i);
		r_strpool_append (p, name);
	}
	return p;
}

bool test_r_strpool_add_after_index_failure(void) {
	RStrpool *p = filled_pool (100);
	calloc_failures = 1;
	mu_assert_eq (r_strpool_add (p, "new"), 100, "add survives failed index creation");
	mu_assert_eq (r_strpool_get (p, "new"), 100, "recovered index includes the new string");
	mu_assert_eq (r_strpool_add (p, "entry-0"), 0, "existing strings still deduplicate");
	mu_assert_eq (r_strpool_add (p, "new"), 100, "new string still deduplicates after another add");
	mu_assert_eq (p->count, 101, "no duplicate stored after recovery");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_add_after_index_growth_failure(void) {
	RStrpool *p = filled_pool (47);
	mu_assert_eq (r_strpool_get (p, "entry-0"), 0, "create index before growth");
	calloc_failures = 1;
	mu_assert_eq (r_strpool_add (p, "new"), 47, "add survives failed index growth");
	mu_assert_eq (r_strpool_get (p, "new"), 47, "recovered index includes the new string");
	mu_assert_eq (r_strpool_get (p, "entry-46"), 46, "recovered index retains existing strings");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_dedup_after_index_failure(void) {
	RStrpool *p = filled_pool (100);
	calloc_failures = 1;
	mu_assert_eq (r_strpool_add (p, "entry-0"), 0, "deduplicate without an index");
	mu_assert_eq (p->count, 100, "failed allocation stores no duplicate");
	mu_assert_eq (r_strpool_get (p, "entry-99"), 99, "later lookup recovers the index");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_lookup_after_index_failure(void) {
	RStrpool *p = filled_pool (100);
	calloc_failures = 2;
	mu_assert_eq (r_strpool_get (p, "entry-0"), 0, "lookup survives failed index creation");
	mu_assert_eq (r_strpool_get (p, "missing"), -1, "missing lookup survives failed index creation");
	mu_assert_eq (r_strpool_get (p, "entry-99"), 99, "lookup recovers after allocation succeeds");
	r_strpool_free (p);
	mu_end;
}

bool test_r_strpool_append_after_index_growth_failure(void) {
	RStrpool *p = filled_pool (47);
	mu_assert_eq (r_strpool_get (p, "entry-0"), 0, "create index before growth");
	calloc_failures = 1;
	mu_assert_eq (r_strpool_append (p, "new"), 47, "append survives failed index growth");
	mu_assert_eq (r_strpool_append (p, "entry-0"), 48, "append still stores duplicates without an index");
	mu_assert_eq (r_strpool_get (p, "new"), 47, "recovered index includes the appended string");
	mu_assert_eq (r_strpool_get (p, "entry-0"), 0, "recovered index returns the first copy");
	r_strpool_free (p);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_strpool_add_after_index_failure);
	mu_run_test (test_r_strpool_add_after_index_growth_failure);
	mu_run_test (test_r_strpool_dedup_after_index_failure);
	mu_run_test (test_r_strpool_lookup_after_index_failure);
	mu_run_test (test_r_strpool_append_after_index_growth_failure);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
