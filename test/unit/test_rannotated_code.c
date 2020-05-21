#include <r_util.h>
#include <r_vector.h>
#include <AnnotatedCode.h>
#include "minunit.h"



// static bool test_vector_init() {
// 	RVector v;
// 	r_vector_init (&v, 42, (void *)1337, (void *)42);
// 	mu_assert_eq (v.elem_size, 42UL, "init elem_size");
// 	mu_assert_eq (v.len, 0UL, "init len");
// 	mu_assert_null (v.a, "init a");
// 	mu_assert_eq (v.capacity, 0UL, "init capacity");
// 	mu_assert_eq (v.free, (void *)1337, "init free");
// 	mu_assert_eq (v.free_user, (void *)42, "init free_user");
// 	mu_end;
// }

// static bool test_

static int all_tests() {
    return false;
	// mu_run_test (test_vector_init);
	// mu_run_test (test_vector_new);
	// mu_run_test (test_vector_fini);
	
    // mu_run_test(test_);

	return tests_passed != tests_run;
}


int main(int argc, char **argv) {
	return all_tests();
}