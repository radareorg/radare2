#include <r_fs.h>
#include <r_io.h>
#include <r_userconf.h>
#include "minunit.h"

static bool test_r_fs_ext2_read_bounds(void) {
#if WITH_GPL
	RIO *io = r_io_new ();
	RFS *fs = r_fs_new ();
	r_io_bind (io, &fs->iob);
	mu_assert_notnull (r_io_open (io, "bins/fs/ext2.img", R_PERM_R, 0), "open ext2 image");
	mu_assert_notnull (r_fs_mount (fs, "ext2", "/mnt", 0), "mount ext2 image");
	RFSFile *file = r_fs_open (fs, "/mnt/README.md", false);
	mu_assert_notnull (file, "open ext2 file");
	mu_assert_eq (r_fs_read (fs, file, 0, 16), 16, "read within file");
	mu_assert_memeq (file->data, (const ut8 *)"This", 4, "read file contents");
	memset (file->data, 0xa5, 16);
	mu_assert_eq (r_fs_read (fs, file, file->size - 2, 4), 2, "clamp read at EOF");
	mu_assert_eq (file->data[2], 0xa5, "short read preserves following bytes");

	ut8 untouched[16];
	memset (untouched, 0xa5, sizeof (untouched));
	const ut64 offsets[] = { file->size, file->size + 1, file->size + 2, UT32_MAX + 1ULL, UT64_MAX };
	r_fs_close (fs, file);
	r_fs_file_free (file);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (offsets); i++) {
		file = r_fs_open (fs, "/mnt/README.md", false);
		mu_assert_notnull (file, "reopen file after read error");
		mu_assert_eq (r_fs_read (fs, file, 0, 16), 16, "read before boundary check");
		memcpy (file->data, untouched, sizeof (untouched));
		mu_assert_eq (r_fs_read (fs, file, offsets[i], 2), -1, "reject read at or beyond EOF");
		mu_assert_memeq (file->data, untouched, sizeof (untouched), "rejected read preserves buffer");
		r_fs_close (fs, file);
		r_fs_file_free (file);
	}
	r_fs_free (fs);
	r_io_free (io);
#endif
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_fs_ext2_read_bounds);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
