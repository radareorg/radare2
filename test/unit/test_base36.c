#include <r_util.h>
#include <r_util/r_base36.h>
#include "minunit.h"

bool test_b36_tonum_valid(void) {
	mu_assert_eq (b36_tonum ("0_0"), 0, "single digit 0");
	mu_assert_eq (b36_tonum ("0_9"), 9, "single digit 9");
	mu_assert_eq (b36_tonum ("0_a"), 10, "single digit a");
	mu_assert_eq (b36_tonum ("0_z"), 35, "single digit z");
	mu_assert_eq (b36_tonum ("0_A"), 10, "uppercase A");
	mu_assert_eq (b36_tonum ("0_Z"), 35, "uppercase Z");
	// digits weigh 36^pos from the left, so position 1 adds 36
	mu_assert_eq (b36_tonum ("0_01"), 36, "second position weighs 36");
	mu_end;
}

bool test_b36_tonum_invalid_byte(void) {
	// a 0xff byte used to index index36[255], one int past the table
	mu_assert_eq (b36_tonum ("0_\xff"), 0, "0xff byte stops parsing");
	mu_assert_eq (b36_tonum ("0_a\xff"), 10, "0xff byte stops after a valid digit");
	mu_assert_eq (b36_tonum ("0_\x80\x81"), 0, "high bytes are not digits");
	mu_end;
}

bool test_b36_tonum_long_input(void) {
	// more valid digits than pow36 has slots used to walk pos past the end of
	// pow36[36]; the extra digits must be ignored rather than read out of bounds
	const char *d37 = "0_1111111111111111111111111111111111111";
	const char *d64 = "0_1111111111111111111111111111111111111111111111111111111111111111";
	mu_assert_eq (b36_tonum (d64), b36_tonum (d37), "digits past the pow36 bound are ignored");
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_b36_tonum_valid);
	mu_run_test (test_b36_tonum_invalid_byte);
	mu_run_test (test_b36_tonum_long_input);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
