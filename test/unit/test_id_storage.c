#include <r_util.h>
#include "minunit.h"


bool test_r_id_storage_prev_next_eq_0(void) {
	// test if next reverts prev
	ut32 id, _id;
	RIDStorage *ids = r_id_storage_new (0, 15);
	r_id_storage_add (ids, "aaa", &_id);
	r_id_storage_add (ids, "bbb", &id);
	r_id_storage_add (ids, "ccc", &_id);
	_id = id;
	r_id_storage_get_prev (ids, &_id);
	r_id_storage_get_next (ids, &_id);
	r_id_storage_free (ids);
	
	mu_assert_eq (id, _id, "r_id_storage_{next/prev} reversal 0");
	mu_end;
}

bool test_r_id_storage_prev_next_eq_1(void) {
	// test if next reverts prev (modulo wrap 1)
	ut32 id, _id;
	RIDStorage *ids = r_id_storage_new (0, 15);
	r_id_storage_add (ids, "bbb", &id);
	r_id_storage_add (ids, "aaa", &_id);
	r_id_storage_add (ids, "ccc", &_id);
	_id = id;
	r_id_storage_get_prev (ids, &_id);
	r_id_storage_get_next (ids, &_id);
	r_id_storage_free (ids);
	
	mu_assert_eq (id, _id, "r_id_storage_{next/prev} reversal 1");
	mu_end;
}

bool test_r_id_storage_prev_next_eq_2(void) {
	// test if next reverts prev (modulo wrap 2)
	ut32 id, _id;
	RIDStorage *ids = r_id_storage_new (0, 15);
	r_id_storage_add (ids, "aaa", &_id);
	r_id_storage_add (ids, "ccc", &_id);
	r_id_storage_add (ids, "bbb", &id);
	_id = id;
	r_id_storage_get_prev (ids, &_id);
	r_id_storage_get_next (ids, &_id);
	r_id_storage_free (ids);
	
	mu_assert_eq (id, _id, "r_id_storage_{next/prev} reversal 2");
	mu_end;
}

int all_tests() {
	mu_run_test(test_r_id_storage_prev_next_eq_0);
	mu_run_test(test_r_id_storage_prev_next_eq_1);
	mu_run_test(test_r_id_storage_prev_next_eq_2);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
