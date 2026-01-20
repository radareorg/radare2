#include <r_core.h>
#include "minunit.h"

bool test_r_core_read_at_buf(void) {
	RCore *core = r_core_new ();
	core->io->va = false;
	RIODesc *desc = r_io_open_at (core->io, "malloc://16", R_PERM_RW, 0644, 0x0);
	mu_assert_notnull (desc, "malloc file should open");
	r_io_write_at (core->io, 0, (const ut8 *)"0123456789ABCDEF", 16);

	ut8 buf[8];
	bool ret = r_core_read_at_buf (core, 0, buf, 8);
	mu_assert_true (ret, "should read at offset 0");
	mu_assert_memeq (buf, (ut8 *)"01234567", 8, "data at offset 0");

	ret = r_core_read_at_buf (core, 8, buf, 8);
	mu_assert_true (ret, "should read at offset 8");
	mu_assert_memeq (buf, (ut8 *)"89ABCDEF", 8, "data at offset 8");

	ret = r_core_read_at_buf (core, 4, buf, 4);
	mu_assert_true (ret, "should read at offset 4");
	mu_assert_memeq (buf, (ut8 *)"4567", 4, "data at offset 4");

	r_core_free (core);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_core_read_at_buf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
