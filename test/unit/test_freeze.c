#include <r_util.h>
#include <r_vec.h>
#include "minunit.h"

typedef struct {
	int value;
	bool freed;
	R_REF_TYPE;
} Item;

R_VEC_TYPE (RVecItemPtr, Item *);

static void item_free(Item *item) {
	item->freed = true;
}

static void item_init(Item *item, int value) {
	*item = (Item){ .value = value };
	r_ref_init (item, item_free);
}

static RFreeze *freeze_items(RFreeze **slot, RVecItemPtr *vec) {
	return r_freeze_vec (slot, vec, Item);
}

static bool test_freeze_borrows(void) {
	Item a, b;
	item_init (&a, 1);
	item_init (&b, 2);
	RVecItemPtr vec;
	RVecItemPtr_init (&vec);
	Item *pa = &a, *pb = &b;
	RVecItemPtr_push_back (&vec, &pa);
	RVecItemPtr_push_back (&vec, &pb);
	RFreeze *slot = NULL;
	RFreeze *frozen = freeze_items (&slot, &vec);
	mu_assert_eq ((size_t)frozen->items, (size_t)R_VEC_START_ITER (&vec), "freezing must not copy");
	mu_assert_false (frozen->owned, "borrowed until detached");
	mu_assert_eq (r_ref_count (&a), 1, "borrowing takes no references");
	RFreeze *again = freeze_items (&slot, &vec);
	mu_assert_eq ((size_t)again, (size_t)frozen, "nested freezes share the view");
	r_freeze_release (again);
	r_freeze_release (frozen);
	mu_assert_null (slot, "release clears the owner slot");
	mu_assert_eq (r_ref_count (&a), 1, "no references leaked");
	RVecItemPtr_fini (&vec);
	mu_end;
}

static bool test_freeze_detach(void) {
	Item a, b;
	item_init (&a, 1);
	item_init (&b, 2);
	RVecItemPtr vec;
	RVecItemPtr_init (&vec);
	Item *pa = &a, *pb = &b;
	RVecItemPtr_push_back (&vec, &pa);
	RVecItemPtr_push_back (&vec, &pb);
	RFreeze *slot = NULL;
	RFreeze *frozen = freeze_items (&slot, &vec);
	// owner removes an element: detach first, then drop its reference
	r_freeze_detach (&slot);
	mu_assert_null (slot, "detach clears the owner slot");
	mu_assert_true (frozen->owned, "detached view owns a copy");
	mu_assert_eq (r_ref_count (&b), 2, "detached view references each item");
	RVecItemPtr_pop_back (&vec);
	Item *pb_owned = &b;
	r_unref (pb_owned);
	mu_assert_false (b.freed, "frozen view keeps removed items alive");
	RVecItemPtr_fini (&vec);
	Item *item;
	size_t i, sum = 0;
	r_freeze_foreach (frozen, i, item) {
		sum += item->value;
	}
	mu_assert_eq (sum, 3, "iterates the snapshot after the owner changed");
	r_freeze_detach (&slot);
	r_freeze_release (frozen);
	mu_assert_true (b.freed, "last release frees removed items");
	mu_assert_eq (r_ref_count (&a), 1, "kept items return to their owner refcount");
	mu_end;
}

static bool test_freeze_empty(void) {
	RFreeze *slot = NULL;
	RFreeze *frozen = r_freeze_acquire (&slot, NULL, 0, R_REF_LAYOUT_NONE);
	void *item;
	size_t i, n = 0;
	r_freeze_detach (&slot);
	r_freeze_foreach (frozen, i, item) {
		n++;
	}
	mu_assert_eq (n, 0, "empty view");
	r_freeze_release (frozen);
	r_freeze_release (NULL);
	mu_end;
}

static bool test_freeze_raw(void) {
	Item a;
	item_init (&a, 7);
	RVecItemPtr vec;
	RVecItemPtr_init (&vec);
	Item *pa = &a;
	RVecItemPtr_push_back (&vec, &pa);
	RFreeze *slot = NULL;
	RFreeze *frozen = r_freeze_vec_raw (&slot, &vec);
	r_freeze_detach (&slot);
	RVecItemPtr_fini (&vec);
	mu_assert_eq (r_ref_count (&a), 1, "raw views do not reference items");
	mu_assert_eq (((Item *)frozen->items[0])->value, 7, "raw view keeps the pointers");
	r_freeze_release (frozen);
	mu_assert_eq (r_ref_count (&a), 1, "raw release does not unreference");
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_freeze_borrows);
	mu_run_test (test_freeze_detach);
	mu_run_test (test_freeze_empty);
	mu_run_test (test_freeze_raw);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
