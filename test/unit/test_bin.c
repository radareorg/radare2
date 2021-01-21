#include <r_util.h>
#include "minunit.h"
#include <r_bin.h>

//TODO test r_str_chop_path

bool test_r_bin(void) {
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);

	RBinOptions opt = {0};
	bool res = r_bin_open (bin, "bins/elf/ioli/crackme0x00", &opt);
	mu_assert ("crackme0x00 binary could not be opened", res);

	RList *sections = r_bin_get_sections (bin);
	// XXX this is wrong, because its returning the sections and the segments, we need another api here
	mu_assert_eq (r_list_length (sections), 39, "r_bin_get_sections");

	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}


bool all_tests() {
	mu_run_test(test_r_bin);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
