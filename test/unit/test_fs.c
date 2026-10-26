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
	mu_assert_eq (r_fs_read (fs, file, 0, 1), 1, "read a single byte");
	mu_assert_eq (r_fs_read (fs, file, 0, 16), 16, "read within file");
	mu_assert_memeq (file->data, (const ut8 *)"This", 4, "read file contents");
	mu_assert_eq (r_fs_read (fs, file, 0, 32), R_MIN (file->size, 32), "grow read buffer again");
	mu_assert_memeq (file->data, (const ut8 *)"This", 4, "read contents after growing buffer");
	mu_assert_eq (file->data[32], 0, "read buffer terminator");
	memset (file->data, 0xa5, 16);
	mu_assert_eq (r_fs_read (fs, file, file->size - 2, 4), 2, "clamp read at EOF");
	mu_assert_eq (file->data[2], 0, "short read leaves zero padding");
	mu_assert_eq (file->data[4], 0, "short read buffer terminator");

	const ut8 empty[3] = { 0 };
	const ut64 offsets[] = { file->size, file->size + 1, file->size + 2, UT32_MAX + 1ULL, UT64_MAX };
	r_fs_close (fs, file);
	r_fs_file_free (file);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (offsets); i++) {
		file = r_fs_open (fs, "/mnt/README.md", false);
		mu_assert_notnull (file, "reopen file after read error");
		mu_assert_eq (r_fs_read (fs, file, 0, 16), 16, "read before boundary check");
		memset (file->data, 0xa5, 16);
		mu_assert_eq (r_fs_read (fs, file, offsets[i], 2), -1, "reject read at or beyond EOF");
		mu_assert_memeq (file->data, empty, sizeof (empty), "rejected read leaves a zeroed buffer");
		r_fs_close (fs, file);
		r_fs_file_free (file);
	}
	r_fs_free (fs);
	r_io_free (io);
#endif
	mu_end;
}

static void bfs_put_run(ut8 *p, ut16 start, ut16 len) {
	r_write_le32 (p, 0);
	r_write_le16 (p + 4, start);
	r_write_le16 (p + 6, len);
}

static void bfs_put_inode(ut8 *img, int block, ut32 mode, ut16 start, ut16 len, ut64 size) {
	ut8 *inode = img + block * 1024;
	r_write_le32 (inode, 0x3bbe0ad9);
	r_write_le32 (inode + 20, mode);
	bfs_put_run (inode + 72, start, len);
	r_write_le64 (inode + 208, size);
}

static bool test_r_fs_bfs_read_whole_file(void) {
	ut8 img[12 * 1024] = { 0 };
	// superblock: 1024 byte blocks, root directory inode at block 2
	r_write_le32 (img + 512 + 32, 0x42465331);
	r_write_le32 (img + 512 + 40, 1024);
	r_write_le32 (img + 512 + 44, 10);
	r_write_le32 (img + 512 + 76, 10);
	bfs_put_run (img + 512 + 116, 2, 1);
	// root directory b+tree in blocks 3-4 with one entry "a" -> inode at block 5
	bfs_put_inode (img, 2, 0x41ed, 3, 2, 2048);
	r_write_le32 (img + 3 * 1024, 0x69f6c2e8);
	r_write_le32 (img + 3 * 1024 + 4, 1024);
	r_write_le32 (img + 3 * 1024 + 8, 1);
	r_write_le64 (img + 3 * 1024 + 16, 1024);
	ut8 *node = img + 4 * 1024;
	r_write_le64 (node + 8, UT64_MAX);
	r_write_le16 (node + 24, 2);
	r_write_le16 (node + 26, 2);
	node[28] = 'a';
	node[29] = 'b';
	r_write_le16 (node + 32, 1);
	r_write_le16 (node + 34, 2);
	r_write_le64 (node + 36, 5);
	r_write_le64 (node + 44, 11);
	// Two multi-block runs separated by a block that is not part of the file.
	bfs_put_inode (img, 5, 0x81a4, 6, 2, 3500);
	bfs_put_run (img + 5 * 1024 + 80, 9, 2);
	memset (img + 6 * 1024, 'A', 1024);
	memset (img + 7 * 1024, 'B', 1024);
	memset (img + 8 * 1024, 'X', 1024);
	memset (img + 9 * 1024, 'C', 1024);
	memset (img + 10 * 1024, 'D', 1024);
	bfs_put_inode (img, 11, 0x81a4, 6, 1, 0x10000);
	ut8 expected[3500];
	memset (expected, 'A', 1024);
	memset (expected + 1024, 'B', 1024);
	memset (expected + 2048, 'C', 1024);
	memset (expected + 3072, 'D', sizeof (expected) - 3072);

	RIO *io = r_io_new ();
	RFS *fs = r_fs_new ();
	r_io_bind (io, &fs->iob);
	mu_assert_notnull (r_io_open (io, "malloc://12288", R_PERM_RW, 0), "open bfs image");
	r_io_write_at (io, 0, img, sizeof (img));
	mu_assert_notnull (r_fs_mount (fs, "bfs", "/mnt", 0), "mount bfs image");
	RFSFile *file = r_fs_open (fs, "/mnt/a", false);
	mu_assert_notnull (file, "open bfs file");
	mu_assert_eq (file->size, sizeof (expected), "bfs file size");
	mu_assert_eq (r_fs_read (fs, file, 0, file->size), sizeof (expected), "read all runs");
	mu_assert_memeq (file->data, expected, sizeof (expected), "whole file contents");
	mu_assert_eq (file->data[file->size], 0, "whole file terminator");
	mu_assert_eq (r_fs_read (fs, file, 1000, 1100), 1100, "unaligned read across both runs");
	mu_assert_memeq (file->data, expected + 1000, 1100, "unaligned contents");
	mu_assert_eq (r_fs_read (fs, file, 3490, 100), 10, "clamp to file tail");
	mu_assert_memeq (file->data, expected + 3490, 10, "tail contents");
	r_fs_close (fs, file);
	r_fs_file_free (file);
	file = r_fs_open (fs, "/mnt/b", false);
	mu_assert_notnull (file, "open file with missing runs");
	mu_assert_eq (r_fs_read (fs, file, 0, 1024), 1024, "read backed part of truncated file");
	mu_assert_eq (file->data[1023], 'A', "first block contents");
	mu_assert_eq (r_fs_read (fs, file, 0, file->size), -1, "reject read beyond available runs");
	mu_assert_eq (file->data[file->size - 1], 0, "failed read buffer covers the whole file");
	r_fs_close (fs, file);
	r_fs_file_free (file);
	r_fs_free (fs);
	r_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_r_fs_ext2_read_bounds);
	mu_run_test (test_r_fs_bfs_read_whole_file);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
