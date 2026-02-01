#include <r_core.h>
#include <r_util.h>
#include "minunit.h"

static bool test_xpatch_hexpairs_format(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Should create core");

	const char *test_file = "/tmp/test_xpatch_unit.bin";
	ut8 data[] = {0x4f, 0xf2, 0xba, 0xfc, 0x30, 0x40};
	r_file_dump (test_file, data, sizeof (data), false);

	// Test applying hexpairs patch (xpatch opens the file from patch header)
	const char *patch =
		"--- /tmp/test_xpatch_unit.bin\n"
		"+++ /tmp/test_xpatch_unit.bin\n"
		"@@ -0x0,4 +0x0,4 @@\n"
		"- '4f f2 ba fc'\n"
		"+ 'ff fe fd fc'\n"
		"@@ -0x4,1 +0x4,1 @@\n"
		"- 30\n"
		"+ 31\n";

	bool result = r_core_patch_unified (core, patch, 0, false);
	mu_assert_true (result, "Should apply patch successfully");

	// Verify the changes by reading the file directly
	ut8 buffer[6];
	r_io_read_at (core->io, 0, buffer, 6);

	ut8 expected[] = {0xff, 0xfe, 0xfd, 0xfc, 0x31, 0x40};
	mu_assert_memeq (buffer, expected, 6, "Data should match expected values after patch");

	r_core_free (core);
	unlink (test_file);

	return true;
}

static bool test_xpatch_hexpairs_wrong_data(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Should create core");

	const char *test_file = "/tmp/test_xpatch_wrong.bin";
	ut8 data[] = {0x11, 0x22, 0x33, 0x44, 0x50, 0x60};
	r_file_dump (test_file, data, sizeof (data), false);

	// Test applying hexpairs patch (should fail because data doesn't match)
	const char *patch =
		"--- /tmp/test_xpatch_wrong.bin\n"
		"+++ /tmp/test_xpatch_wrong.bin\n"
		"@@ -0x0,4 +0x0,4 @@\n"
		"- '4f f2 ba fc'\n"  // This doesn't match the actual data
		"+ 'ff fe fd fc'\n";

	bool result = r_core_patch_unified (core, patch, 0, false);
	mu_assert_false (result, "Should fail to apply patch with wrong data");

	r_core_free (core);
	unlink (test_file);

	return true;
}

static bool test_xpatch_single_byte_format(void) {
	RCore *core = r_core_new ();
	mu_assert_notnull (core, "Should create core");

	const char *test_file = "/tmp/test_xpatch_single.bin";
	ut8 data[] = {0x4f, 0xf2, 0x30, 0x40, 0x50, 0x60};
	r_file_dump (test_file, data, sizeof (data), false);

	// Test applying single byte patch
	const char *patch =
		"--- /tmp/test_xpatch_single.bin\n"
		"+++ /tmp/test_xpatch_single.bin\n"
		"@@ -0x2,1 +0x2,1 @@\n"
		"- 30\n"
		"+ aa\n"
		"@@ -0x3,1 +0x3,1 @@\n"
		"- 40\n"
		"+ bb\n";

	bool result = r_core_patch_unified (core, patch, 0, false);
	mu_assert_true (result, "Should apply single byte patch successfully");

	// Verify the changes
	ut8 buffer[6];
	r_io_read_at (core->io, 0, buffer, 6);

	ut8 expected[] = {0x4f, 0xf2, 0xaa, 0xbb, 0x50, 0x60};
	mu_assert_memeq (buffer, expected, 6, "Data should match expected values after single byte patch");

	r_core_free (core);
	unlink (test_file);

	return true;
}

static int test_all(void) {
	mu_run_test (test_xpatch_hexpairs_format);
	mu_run_test (test_xpatch_hexpairs_wrong_data);
	mu_run_test (test_xpatch_single_byte_format);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return test_all ();
}
