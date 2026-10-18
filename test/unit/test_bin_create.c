#include <r_bin.h>
#include "minunit.h"

bool test_mach064_create(void) {
	const ut8 code[] = {0x90, 0xc3};
	const ut8 data[] = "hello";
	const int codelens[] = {2, 0, 2};
	const int datalens[] = {0, 1, sizeof (data)};
	RBin *bin = r_bin_new ();
	RBinArchOptions opt = { .arch = "x86", .bits = 64 };
	int i;
	for (i = 0; i < R_ARRAY_SIZE (datalens); i++) {
		int codelen = codelens[i];
		int datalen = datalens[i];
		RBuffer *buf = r_bin_create (bin, "mach064", code, codelen, data, datalen, &opt);
		mu_assert_notnull (buf, "Create Mach-O buffer");
		mu_assert_eq (r_buf_size (buf), 4096 + codelen + datalen, "File size");
		mu_assert_eq (r_buf_read_le64_at (buf, 0xd8), codelen, "__text size");
		if (datalen) {
			mu_assert_eq (r_buf_read_le64_at (buf, 0x170), datalen, "__data size");
			mu_assert_eq (r_buf_read_le32_at (buf, 0x178), 4096 + codelen, "__data offset");
			ut8 actual[sizeof (data)];
			mu_assert_eq (r_buf_read_at (buf, 4096 + codelen, actual, datalen), datalen, "Read data");
			mu_assert_memeq (actual, data, datalen, "Data contents");
		}
		r_unref (buf);
	}
	r_bin_free (bin);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_mach064_create);
	return tests_passed != tests_run;
}
