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
	r_anal_create_function (anal, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants (anal);

	bool success = r_anal_function_relocate (fa, fb->addr);
	assert_invariants (anal);
	mu_assert_false (success, "failed relocate");
	mu_assert_eq (fa->addr, 0x1337, "failed relocate addr");

	success = r_anal_function_relocate (fa, 0x1234);
	assert_invariants (anal);
	mu_assert_true (success, "successful relocate");
	mu_assert_eq (fa->addr, 0x1234, "successful relocate addr");

	assert_leaks (anal);
	r_anal_free (anal);
	mu_end;
}

bool test_r_anal_function_labels() {
	RAnal *anal = r_anal_new ();

	RAnalFunction *f = r_anal_create_function (anal, "do_something", 0x1337, 0, NULL);

	bool s = r_anal_function_set_label (f, "smartfriend", 0x1339);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x133c);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "the", 0x1340);
	mu_assert_true (s, "set label");
	s = r_anal_function_set_label (f, "stray", 0x1234);
	mu_assert_false (s, "set label (existing name)");
	s = r_anal_function_set_label (f, "henlo", 0x133c);
	mu_assert_false (s, "set label (existing addr)");

	ut64 addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, 0x133c, "get label");
	addr = r_anal_function_get_label (f, "skies");
	mu_assert_eq (addr, UT64_MAX, "get label (unknown)");

	const char *name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_streq (name, "stray", "get label at");
	name = r_anal_function_get_label_at (f, 0x1234);
	mu_assert_null (name, "get label at (unknown)");

	r_anal_function_delete_label (f, "stray");
	addr = r_anal_function_get_label (f, "stray");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x133c);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_function_delete_label_at (f, 0x1340);
	addr = r_anal_function_get_label (f, "the");
	mu_assert_eq (addr, UT64_MAX, "get label (deleted)");
	name = r_anal_function_get_label_at (f, 0x340);
	mu_assert_null (name, "get label at (deleted)");
	addr = r_anal_function_get_label (f, "smartfriend");
	mu_assert_eq (addr, 0x1339, "get label (unaffected by delete)");
	name = r_anal_function_get_label_at (f, 0x1339);
	mu_assert_streq (name, "smartfriend", "get label at (unaffected by delete)");

	r_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_anal_function_relocate);
	mu_run_test (test_r_anal_function_labels);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
