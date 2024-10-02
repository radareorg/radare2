#include <r_bin.h>
#include <r_core.h>
#include <math.h>
#include "../../libr/include/r_heap_glibc.h"
#define R_INCLUDE_BEGIN 1
#include "../../libr/core/dmh_glibc.inc.c"
#undef R_INCLUDE_BEGIN
#include "minunit.h"
// Adapted https://github.com/radareorg/radare2/pull/22516/commits/d59c813cc4fc574c85aa210aed4aa0636fac3184 by MewtR

bool test_get_glibc_version (void) {
	RCore *core = r_core_new ();

	double version = 0.0f;
	int glibc_version = 0;

	// 2.27
	version = GH (get_glibc_version) (core, "bins/elf/libc-2.27.so");
	glibc_version = (int)round ((version * 100));
	mu_assert_eq (glibc_version, 227, "Incorrect libc version, expected 2.27");


	// 2.28
	version = GH (get_glibc_version) (core, "bins/elf/libc.so.6");
	glibc_version = (int)round ((version * 100));
	mu_assert_eq (glibc_version, 228, "Incorrect libc version, expected 2.28");

	// 2.31
	version = GH (get_glibc_version) (core, "bins/elf/libc-2.31.so");
	glibc_version = (int)round ((version * 100));
	mu_assert_eq (glibc_version, 231, "Incorrect libc version, expected 2.31");

	// 2.32
	version = GH (get_glibc_version) (core, "bins/elf/libc-2.32.so");
	glibc_version = (int)round ((version * 100));
	mu_assert_eq (glibc_version, 232, "Incorrect libc version, expected 2.32");

	r_core_free (core);
	mu_end;
}

bool all_tests (void) {
	mu_run_test (test_get_glibc_version);
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
