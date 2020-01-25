#include <r_anal.h>
#include "minunit.h"

#include "test_anal_block_invars.inl"

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_pp_count(void *user, const void *k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

static bool function_check_invariants(RAnal *anal) {
	if (!block_check_invariants (anal)) {
		return false;
	}

	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, it, fcn) {
		mu_assert_ptreq (ht_up_find (anal->ht_addr_fun, fcn->addr, NULL), fcn, "function in addr ht");
		mu_assert_ptreq (ht_pp_find (anal->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach (anal->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq (addr_count, r_list_length (anal->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_pp_foreach (anal->ht_name_fun, ht_pp_count, &name_count);
	mu_assert_eq (name_count, r_list_length (anal->fcns), "function name ht count");

	return true;
}

#define check_invariants function_check_invariants
#define check_leaks block_check_leaks

#define assert_invariants(anal) do { if (!check_invariants (anal)) { return false; } } while (0)
#define assert_leaks(anal) do { if (!check_leaks (anal)) { return false; } } while (0)

bool test_r_anal_function_relocate() {
	RAnal *anal = r_anal_new ();
	assert_invariants (anal);

	RAnalFunction *fa = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);
	assert_invariants (anal);
	RAnalFunction *fb = r_anal_create_function (anal, "do_something_else", 0xdeadbeef, 0, NULL);
	assert_invariants (anal);
	RAnalFunction *fc = r_anal_create_function (anal, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants (anal);

	bool success = r_anal_function_relocate (fa, fb->addr);
	assert_invariants (anal);
	mu_assert ("failed relocate", !success);
	mu_assert_eq (fa->addr, 0x1337, "failed relocate addr");

	success = r_anal_function_relocate (fa, 0x1234);
	assert_invariants (anal);
	mu_assert ("successful relocate", success);
	mu_assert_eq (fa->addr, 0x1234, "successful relocate addr");

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}


int all_tests() {
	mu_run_test (test_r_anal_function_relocate);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
