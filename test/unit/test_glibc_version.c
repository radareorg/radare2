#include <r_bin.h>
#include <r_core.h>
#include <math.h>
#include "../../libr/include/r_heap_glibc.h"
#include "minunit.h"

bool test_glibc_version (void) {
	RCore *core = r_core_new ();

	double version = 0.0f;
	int glibc_version = 0;

	// 2.27
	version = get_glibc_version (core, "bins/elf/libc-2.27.so");
	glibc_version = (int)round ((version * 100));

	mu_assert_eq (227, glibc_version, "Incorrect libc version, expected 2.27");

	// 2.31
	version = get_glibc_version (core, "bins/elf/libc-2.31.so");
	glibc_version = (int)round ((version * 100));

	mu_assert_eq (231, glibc_version, "Incorrect libc version, expected 2.31");

	// 2.32
	version = get_glibc_version (core, "bins/elf/libc-2.32.so");
	glibc_version = (int)round ((version * 100));

	mu_assert_eq (232, glibc_version, "Incorrect libc version, expected 2.32");

	// 2.28
	version = get_glibc_version (core, "bins/elf/libc.so.6");
	glibc_version = (int)round ((version * 100));

	mu_assert_eq (228, glibc_version, "Incorrect libc version, expected 2.28");

	r_core_free (core);
	mu_end;
}

bool all_tests () {
	mu_run_test (test_glibc_version);
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
