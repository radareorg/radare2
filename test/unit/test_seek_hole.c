#include <r_io.h>
#include "minunit.h"

bool test_r_io_seek_hole_virtual(void) {
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "io should be created");
	io->va = true;

	/* create two maps: [0..9] and [20..29], so hole [10..19] exists */
	RIODesc *fd0 = r_io_open_at (io, "malloc://10", R_PERM_R, 0, 0);
	mu_assert ("open_at failed", fd0);
	RIODesc *fd1 = r_io_open_at (io, "malloc://10", R_PERM_R, 0, 20);
	mu_assert ("open_at failed", fd1);

	/* offset at start of file -> first hole starts at 10 */
	ut64 res = r_io_seek (io, 0, R_IO_SEEK_HOLE);
	mu_assert_eq (res, 10ULL, "SEEK_HOLE from 0 should return 10");

	/* offset inside hole -> should return the same offset */
	res = r_io_seek (io, 12, R_IO_SEEK_HOLE);
	mu_assert_eq (res, 12ULL, "SEEK_HOLE from 12 should return 12");

	/* offset inside first map -> should return start of next hole (10) */
	res = r_io_seek (io, 5, R_IO_SEEK_HOLE);
	mu_assert_eq (res, 10ULL, "SEEK_HOLE from 5 should return 10");

	/* offset after last map -> should return offset (virtual hole at EOF) */
	res = r_io_seek (io, 30, R_IO_SEEK_HOLE);
	mu_assert_eq (res, 30ULL, "SEEK_HOLE from 30 should return 30 (EOF hole)");

	r_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_io_seek_hole_virtual);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
