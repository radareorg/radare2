#include <r_util.h>
#include "minunit.h"

bool test_r_id_storage_add0(void) {
	char *str = "lol";
	RIDStorage *ids = r_id_storage_new (5, 23);
	ut32 id;
	bool success = r_id_storage_add (ids, str, &id);
	void *ptr = r_id_storage_get (ids, id);
	r_id_storage_free (ids);
	mu_assert ("id_storage_add 0", success && (ptr == str));
	mu_end;
}

bool test_r_id_storage_add1(void) {
	char *str = "lol";
	RIDStorage *ids = r_id_storage_new (0, 4);
	ut32 id;
	r_id_storage_add (ids, str, &id);
	r_id_storage_add (ids, str, &id);
	r_id_storage_add (ids, str, &id);
	r_id_storage_add (ids, str, &id);
	bool success = r_id_storage_add (ids, str, &id);
	r_id_storage_free (ids);
	mu_assert ("id_storage_add 1", !success);
	mu_end;
}

bool test_r_id_storage_set(void) {
	char *str = "lol";
	RIDStorage *ids = r_id_storage_new (5, 23);
	r_id_storage_set (ids, str, 1);
	void *ptr = r_id_storage_get (ids, 1);
	r_id_storage_free (ids);
	mu_assert_ptreq (ptr, str, "id_storage_set");
	mu_end;
}

bool test_r_id_storage_delete(void) {
	RIDStorage *ids = r_id_storage_new (5, 23);
	ut32 id;
	r_id_storage_add (ids, "lol", &id);
	r_id_storage_delete (ids, id);
	void *ptr = r_id_storage_get (ids, id);
	r_id_storage_free (ids);
	mu_assert_ptreq (ptr, NULL, "id_storage_delete");
	mu_end;
}

bool test_r_id_storage_take0(void) {
	char *str = "lol";
	RIDStorage *ids = r_id_storage_new (5, 23);
	ut32 id;
	r_id_storage_add (ids, str, &id);
	void *ptr = r_id_storage_take (ids, id);
	r_id_storage_free (ids);
	mu_assert_ptreq (ptr, str, "id_storage_take 0");
	mu_end;
}

bool test_r_id_storage_take1(void) {
	char *str = "lol";
	RIDStorage *ids = r_id_storage_new (5, 23);
	ut32 id;
	r_id_storage_add (ids, str, &id);
	r_id_storage_take (ids, id);
	void *ptr = r_id_storage_get (ids, id);
	r_id_storage_free (ids);
	mu_assert_ptreq (ptr, NULL, "id_storage_take 1");
	mu_end;
}


int all_tests() {
	mu_run_test (test_r_id_storage_add0);
	mu_run_test (test_r_id_storage_add1);
	mu_run_test (test_r_id_storage_set);
	mu_run_test (test_r_id_storage_delete);
	mu_run_test (test_r_id_storage_take0);
	mu_run_test (test_r_id_storage_take1);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
