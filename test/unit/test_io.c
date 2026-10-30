#include <r_io.h>
#include <r_util.h>
#include "minunit.h"

bool test_r_io_cache(void) {
#if 0
	RIO *io = r_io_new ();
	r_io_open (io, "malloc://15", R_PERM_RW, 0);
	r_io_write_at (io, 0, (ut8 *)"ZZZZZZZZZZZZZZZ", 15);
	mu_assert_false (r_io_cache_at (io, 0), "Cache shouldn't exist at 0");
	mu_assert_false (r_io_cache_at (io, 10), "Cache shouldn't exist at 10");
	mu_assert_true (r_io_cache_write_at (io, 0, (ut8 *)"AAAAA", 5), "Cache write at 0 failed");
	mu_assert_true (r_io_cache_write_at (io, 10, (ut8 *)"BBBBB", 5), "Cache write at 10 failed");
	mu_assert_true (r_io_cache_at (io, 0), "Cache should exist at 0 (beginning of cache)");
	mu_assert_true (r_io_cache_at (io, 4), "Cache should exist at 4 (end of cache)");
	mu_assert_false (r_io_cache_at (io, 8), "Cache shouldn't exist at 8 (between 2 caches)");
	mu_assert_true (r_io_cache_at (io, 12), "Cache should exist at 12 (middle of cache)");
	ut8 buf[15];
	memset (buf, 'Z', sizeof (buf));
	mu_assert_true (r_io_cache_read_at (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"AAAAAZZZZZBBBBB", sizeof (buf), "Cache read doesn't match expected output");
	memset (buf, 'Z', sizeof (buf));
	mu_assert_true (r_io_cache_write_at (io, 0, (ut8 *)"CC", 2), "Overlapped cache write at 0 failed");
	mu_assert_true (r_io_cache_write_at (io, 4, (ut8 *)"DD", 2), "Overlapped cache write at 4 failed");
	mu_assert_true (r_io_cache_write_at (io, 8, (ut8 *)"EEE", 3), "Cache write at 4 failed");
	mu_assert_true (r_io_cache_read_at (io, 0, buf, 2), "Cache read at 0 failed");
	mu_assert_true (r_io_cache_read_at (io, 2, buf + 2, 2), "Cache read at 2 failed");
	mu_assert_true (r_io_cache_read_at (io, 4, buf + 4, 2), "Cache read at 4 failed");
	// mu_assert_true (r_io_cache_read_at (io, 6, buf + 6, 2), "Cache read at 6 failed");
	mu_assert_true (r_io_cache_read_at (io, 8, buf + 8, 3), "Cache read at 8 failed");
	mu_assert_true (r_io_cache_read_at (io, 11, buf + 11, 4), "Cache read at 11 failed");
	mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "Cache read doesn't match expected output");
	mu_assert_true (r_io_cache_write_at (io, 0, (ut8 *)"FFFFFFFFFFFFFFF", 15), "Cache write failed");
	mu_assert_true (r_io_cache_read_at (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof (buf), "Cache read doesn't match expected output");

	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"ZZZZZZZZZZZZZZZ", sizeof (buf), "IO read without cache doesn't match expected output");
	r_io_cache_push (io);
	r_io_cache_write_at (io, 0, (const ut8*)"buggy", 5);
	mu_assert_true (r_io_cache_read_at (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"buggyFFFFFFFFFF", sizeof (buf), "Cache read doesn't match expected output");
	r_io_cache_pop (io);

	mu_assert_true (r_io_cache_read_at (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof (buf), "Cache read doesn't match expected output");

#if 0
	// io->cache.mode = R_PERM_R;
	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof (buf), "IO read with cache doesn't match expected output");
	r_io_cache_invalidate (io, 6, 1, false);
#endif
	r_io_cache_invalidate (io, 6, 10, false);
	memset (buf, 'Z', sizeof (buf));
	r_io_read_at (io, 0, buf, sizeof (buf));
	// mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "IO read after cache invalidate doesn't match expected output");
	r_io_cache_commit (io, 0, 15, false);
	memset (buf, 'Z', sizeof (buf));
	io->cache.mode = 0;
	r_io_read_at (io, 0, buf, sizeof (buf));
	// mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "IO read after cache commit doesn't match expected output");
	r_io_free (io);
	mu_end;
#endif
	return true;
}

bool test_r_io_nread_at(void) {
	char *filename = r_file_temp ("r2-io-nread");
	mu_assert_notnull (filename, "temporary filename should be created");
	mu_assert_true (r_file_dump (filename, (const ut8 *)"abc", 3, false), "physical contents should be written");
	char *uri = r_str_newf ("file://%s", filename);
	RIO *io = r_io_new ();
	RIODesc *desc = r_io_open (io, uri, R_PERM_R, 0);
	mu_assert_notnull (desc, "physical IO should open");
	ut8 buf[6] = { 0 };
	mu_assert_eq (r_io_nread_at (io, 0, buf, 4), 3, "physical short read should return its byte count");
	mu_assert_memeq (buf, (const ut8 *)"abc", 3, "physical short read contents");
	RIOBind bind = { 0 };
	r_io_bind (io, &bind);
	mu_assert_eq (bind.read_at (io, 0, buf, 4), 3, "RIOBind should expose the byte count");
	io->cache.mode |= R_PERM_R;
	mu_assert_true (r_io_cache_write_at (io, 3, (const ut8 *)"def", 3), "adjacent cache write should succeed");
	mu_assert_eq (r_io_nread_at (io, 0, buf, sizeof (buf)), 6, "cached data should extend a physical read prefix");
	mu_assert_memeq (buf, (const ut8 *)"abcdef", sizeof (buf), "physical and cached data should be combined");
	mu_assert_true (r_io_cache_write_at (io, 8, (const ut8 *)"cache", 5), "cache write should succeed");
	mu_assert_eq (r_io_nread_at (io, 8, buf, sizeof (buf)), 5, "cached data should form a read prefix past the descriptor");
	mu_assert_memeq (buf, (const ut8 *)"cache", 5, "cached data should be returned");
	r_io_free (io);
	free (uri);
	r_file_rm (filename);
	free (filename);

	io = r_io_new ();
	io->va = true;
	io->ff = true;
	io->Oxff = 0xff;
	int fd0 = r_io_fd_open (io, "malloc://2", R_PERM_RW, 0);
	int fd1 = r_io_fd_open (io, "malloc://2", R_PERM_RW, 0);
	mu_assert_neq (fd0, -1, "first virtual IO should open");
	mu_assert_neq (fd1, -1, "second virtual IO should open");
	mu_assert_notnull (r_io_map_add (io, fd0, R_PERM_R, 0, 0, 2), "first adjacent map should be added");
	mu_assert_notnull (r_io_map_add (io, fd1, R_PERM_R, 0, 2, 2), "second adjacent map should be added");
	mu_assert_eq (r_io_fd_write_at (io, fd0, 0, (const ut8 *)"ab", 2), 2, "first virtual contents should be written");
	mu_assert_eq (r_io_fd_write_at (io, fd1, 0, (const ut8 *)"cd", 2), 2, "second virtual contents should be written");
	memset (buf, 0, sizeof (buf));
	mu_assert_eq (r_io_nread_at (io, 0, buf, 4), 4, "adjacent maps should form one read prefix");
	mu_assert_memeq (buf, (const ut8 *)"abcd", 4, "adjacent map contents");
	r_io_map_remap (io, r_io_map_get_at (io, 2)->id, 4);
	memset (buf, 0, sizeof (buf));
	mu_assert_eq (r_io_nread_at (io, 0, buf, sizeof (buf)), 2, "a virtual hole should stop the read prefix");
	mu_assert_memeq (buf, (const ut8 *)"ab\xff\xff\xff\xff", sizeof (buf), "io.ff should only fill the unread tail");
	r_io_free (io);

	io = r_io_new ();
	desc = r_io_open (io, "malloc://4", R_PERM_RW, 0);
	mu_assert_notnull (desc, "masked physical IO should open");
	mu_assert_eq (r_io_fd_write_at (io, desc->fd, 0, (const ut8 *)"abcd", 4), 4, "masked contents should be written");
	io->mask = 3;
	memset (buf, 0, sizeof (buf));
	mu_assert_eq (r_io_nread_at (io, 2, buf, 4), 4, "masked reads should wrap and preserve their count");
	mu_assert_memeq (buf, (const ut8 *)"cdab", 4, "masked read contents");
	r_io_free (io);
	mu_end;
}

bool test_r_io_fd_seek_read(void) {
	char *filename = r_file_temp ("r2-io-seek");
	mu_assert_true (r_file_dump (filename, (const ut8 *)"abcdefgh", 8, false), "file contents should be written");
	char *uri = r_str_newf ("file://%s", filename);
	RIO *io = r_io_new ();
	RIODesc *desc = r_io_open (io, uri, R_PERM_RW, 0);
	mu_assert_notnull (desc, "file should open");
	ut8 buf[4] = { 0 };
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 2, R_IO_SEEK_SET), 2, "SEEK_SET should move to the offset");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 3, R_IO_SEEK_CUR), 5, "SEEK_CUR should add to the last position");
	mu_assert_eq (r_io_fd_read (io, desc->fd, buf, 2), 2, "read should return its byte count");
	mu_assert_memeq (buf, (const ut8 *)"fg", 2, "read should start at the tracked position");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 0, R_IO_SEEK_CUR), 7, "read should advance the position");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 0, R_IO_SEEK_END), 8, "SEEK_END should report the size");
	mu_assert_eq (r_io_fd_read_at (io, desc->fd, 1, buf, 2), 2, "positional read should return its byte count");
	mu_assert_memeq (buf, (const ut8 *)"bc", 2, "positional read should ignore the previous position");
#if R2__UNIX__ && !__wasi__
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 0x8000000000000000ULL, R_IO_SEEK_SET), UT64_MAX, "a seek past the largest file offset should fail");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 1, R_IO_SEEK_CUR), 4, "a refused seek should keep the position");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 16, R_IO_SEEK_SET), 16, "a seek past the end should reach the kernel");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 2, R_IO_SEEK_SET), 2, "a seek back inside the file should not need the kernel");
	mu_assert_eq (r_io_fd_seek (io, desc->fd, 100, R_IO_SEEK_CUR), 102, "a relative seek past the end should start from the tracked position");
	mu_assert_eq (r_io_fd_write_at (io, desc->fd, 5, (const ut8 *)"XY", 2), 2, "write should return its byte count");
	mu_assert_eq (r_io_fd_read_at (io, desc->fd, 4, buf, 4), 4, "read after write should return its byte count");
	mu_assert_memeq (buf, (const ut8 *)"eXYh", 4, "write should land at its position");
#endif
	r_io_free (io);
	free (uri);
	r_file_rm (filename);
	free (filename);
#if __linux__
	io = r_io_new ();
	desc = r_io_open (io, "file:///dev/ptmx", R_PERM_R, 0);
	if (desc) {
		mu_assert_eq (r_io_fd_seek (io, desc->fd, 0, R_IO_SEEK_SET), UT64_MAX, "a terminal should refuse to seek");
	}
	r_io_free (io);
	io = r_io_new ();
	desc = r_io_open (io, "file:///dev/zero", R_PERM_R, 0);
	mu_assert_notnull (desc, "a character device should open");
	memset (buf, 0xff, sizeof (buf));
	mu_assert_eq (r_io_fd_read_at (io, desc->fd, 0, buf, 4), 4, "a character device should read through lseek");
	mu_assert_memeq (buf, (const ut8 *)"\0\0\0\0", 4, "a character device read should return its bytes");
	desc = r_io_open (io, "file:///dev/null", R_PERM_RW, 0);
	mu_assert_notnull (desc, "a character device should open for writing");
	mu_assert_eq (r_io_fd_write_at (io, desc->fd, 0, (const ut8 *)"XY", 2), 2, "a character device should write through lseek");
	r_io_free (io);
#endif
	mu_end;
}

bool test_r_io_mapsplit (void) {
	RIO *io = r_io_new ();
	io->va = true;
	r_io_open_at (io, "null://2", R_PERM_R, 0LL, UT64_MAX);
	mu_assert_true (r_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_notnull (r_io_map_get_at (io, 0x0), "Found no map at 0x0");
	mu_assert_notnull (r_io_map_get_at (io, UT64_MAX), "Found no map at UT64_MAX");
	r_io_free (io);
	mu_end;
}

bool test_r_io_mapsplit2 (void) {
	RIO *io = r_io_new ();
	io->va = true;
	r_io_open_at (io, "null://2", R_PERM_R, 0LL, 0LL);
	mu_assert_true (r_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (r_io_map_is_mapped (io, 0x1), "0x1 not mapped");
	r_io_map_remap (io, r_io_map_get_at (io, 0LL)->id, UT64_MAX);
	mu_assert_true (r_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_false (r_io_map_is_mapped (io, 0x1), "0x1 mapped");
	mu_assert_notnull (r_io_map_get_at (io, 0x0), "Found no map at 0x0");
	mu_assert_notnull (r_io_map_get_at (io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_null (r_io_map_get_at (io, 0x1), "Found map at 0x1");
	r_io_free (io);
	mu_end;
}

bool test_r_io_mapsplit3 (void) {
	RIO *io = r_io_new ();
	io->va = true;
	const int fd = r_io_fd_open (io, "null://3", R_PERM_R, 0);
	r_io_map_add (io, fd, R_PERM_R, 0LL, UT64_MAX - 1, 2);
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	r_io_map_resize (io, r_io_map_get_at (io, UT64_MAX)->id, 3);
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX - 1), "UT64_MAX - 1 not mapped");
	mu_assert_true (r_io_map_is_mapped (io, UT64_MAX), "UT64_MAX not mapped");
	mu_assert_true (r_io_map_is_mapped (io, 0x0), "0x0 not mapped");
	mu_assert_false (r_io_map_is_mapped (io, 0x1), "0x1 mapped");
	mu_assert_notnull (r_io_map_get_at (io, UT64_MAX), "Found no map at UT64_MAX");
	mu_assert_notnull (r_io_map_get_at (io, 0x0), "Found no map at 0x0");
	r_io_free (io);
	mu_end;
}

bool test_r_io_pcache (void) {
	RIO *io = r_io_new ();
	io->ff = 1;
	ut8 buf[8];
	int fd = r_io_fd_open (io, "malloc://3", R_PERM_RW, 0);
	r_io_map_add (io, fd, R_PERM_RW, 0LL, 0LL, 1); //8
	r_io_map_add (io, fd, R_PERM_RW, 1, 1, 1); //=
	r_io_map_add (io, fd, R_PERM_RW, 1, 2, 1); //=
	r_io_map_add (io, fd, R_PERM_RW, 1, 3, 1); //=
	r_io_map_add (io, fd, R_PERM_RW, 1, 4, 1); //=
	r_io_map_add (io, fd, R_PERM_RW, 1, 5, 1); //=
	r_io_map_add (io, fd, R_PERM_RW, 2, 6, 1); //D
	io->p_cache = 2;
	io->va = true;
	r_io_fd_write_at (io, fd, 0, (const ut8*)"8=D", 3);
	r_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "", "pcache read happened, but it shouldn't");
	io->p_cache = 1;
	r_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	r_io_fd_write_at (io, fd, 0, (const ut8*)"XXX", 3);
	r_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "8=====D", "expected an ascii-pn from pcache");
	io->p_cache = 0;
	r_io_read_at (io, 0x0, buf, 8);
	mu_assert_streq ((const char *)buf, "XXXXXXX", "expected censorship of the ascii-pn");
	r_io_free (io);
	mu_end;
}

bool test_r_io_desc_exchange (void) {
	RIO *io = r_io_new ();
	int fd = r_io_fd_open (io, "malloc://3", R_PERM_R, 0),
	    fdx = r_io_fd_open (io, "malloc://6", R_PERM_R, 0);
	r_io_desc_exchange (io, fd, fdx);
	mu_assert ("Desc-exchange is broken", (r_io_fd_size (io, fd) == 6));
	r_io_free (io);
	mu_end;
}

bool test_va_malloc_zero(void) {
	RIO *io;
	ut64 buf;
	bool ret;

	io = r_io_new ();
	io->va = false;
	r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	r_io_free (io);

	io = r_io_new ();
	io->va = true;
	r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0x0);
	buf = 0xdeadbeefcafebabe;
	ret = r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_test_status = MU_TEST_BROKEN;
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	r_io_free (io);

	mu_end;
}

bool test_r_io_priority(void) {
	RIO *io = r_io_new();
	ut32 map0, map1, map_big;
	ut64 buf;
	bool ret;

	io->va = true;
	r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0x0);
	map0 = r_io_map_get_at (io, 0)->id;
	ret = r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	buf = 0x9090909090909090;
	r_io_write_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "0x90 should have been written");

	r_io_open_at (io, "malloc://2", R_PERM_RW, 0644, 0x4);
	map1 = r_io_map_get_at (io, 4)->id;
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x00\x00\x90\x90", 8, "0x00 from map1 should overlap");

	buf ^= UT64_MAX;
	r_io_write_at (io, 0, (ut8 *)&buf, 8);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\xff\xff\x6f\x6f", 8, "memory has been xored");

	r_io_map_priorize (io, map0);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map0 should have been prioritized");

	r_io_map_remap (io, map1, 0x2);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\x6f\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped");

	r_io_map_priorize (io, map1);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x6f\x6f\xff\xff\x90\x90\x6f\x6f", 8, "map1 should have been prioritized");

	r_io_open_at (io, "malloc://2", R_PERM_RW, 0644, 0x0);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\xff\x90\x90\x6f\x6f", 8, "0x00 from map2 at start should overlap");

	r_io_map_remap (io, map1, 0x1);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped and partially hidden");

	r_io_open_at (io, "malloc://2", R_PERM_RW, 0644, 0x4);
	r_io_open_at (io, "malloc://2", R_PERM_RW, 0644, 0x6);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x00\x00\x00\x00", 8, "Multiple maps opened");

	buf = 0x9090909090909090;
	r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0x10);
	map_big = r_io_map_get_at (io, 0x10)->id;
	r_io_write_at (io, 0x10, (ut8 *)&buf, 8);
	r_io_map_remap (io, map_big, 0x1);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything from 0x1");

	r_io_map_remap (io, map_big, 0x10);
	r_io_map_remap (io, map_big, 0);
	r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "map_big should cover everything");

	r_io_free (io);
	mu_end;
}

bool test_r_io_priority2(void) {
	RIO *io = r_io_new();
	ut32 map0;
	ut8 buf[2];
	bool ret;

	io->va = true;
	RIODesc *desc0 = r_io_open_at (io, "malloc://1024", R_PERM_RW, 0644, 0x0);
	mu_assert_notnull (desc0, "first malloc should be opened");
	map0 = r_io_map_get_at (io, 0)->id;
	ret = r_io_read_at (io, 0, (ut8 *)&buf, 2);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq (buf, (ut8 *)"\x00\x00", 2, "0 should be there initially");
	r_io_write_at (io, 0, (const ut8 *)"\x90\x90", 2);
	r_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x90\x90", 2, "0x90 was written");

	RIODesc *desc1 = r_io_open_at (io, "malloc://1024", R_PERM_R, 0644, 0x0);
	mu_assert_notnull (desc1, "second malloc should be opened");
	r_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x00\x00", 2, "0x00 from map1 should be on top");

	r_io_map_priorize (io, map0);
	r_io_read_at (io, 0, buf, 2);
	mu_assert_memeq (buf, (ut8 *)"\x90\x90", 2, "0x90 from map0 should be on top after prioritize");

	r_io_free (io);
	mu_end;
}

bool test_r_io_overlay_write_through(void) {
	RIO *io = r_io_new ();
	RIODesc *desc = r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0);
	mu_assert_notnull (desc, "malloc should open");
	mu_assert_true (r_io_vwrite_to_overlay_at (io, 2, (const ut8 *)"\xaa\xaa", 2), "overlay write");
	mu_assert_true (r_io_vwrite_at (io, 1, (const ut8 *)"\x11\x22\x33\x44", 4), "write across the overlay");
	mu_assert_true (r_io_vwrite_at (io, 5, (const ut8 *)"\x55\x66", 2), "write beside the overlay");
	mu_assert_true (r_io_vwrite_at (io, 3, (const ut8 *)"\xbb\xcc", 2), "write over the overlay's end");
	const ut8 *exp = (const ut8 *)"\x00\x11\x22\xbb\xcc\x55\x66\x00";
	ut8 buf[8] = {0};
	mu_assert_true (r_io_vread_at (io, 0, buf, sizeof (buf)), "overlaid read");
	mu_assert_memeq (buf, exp, sizeof (buf), "the overlaid view shows the writes");
	memset (buf, 0, sizeof (buf));
	mu_assert_eq (r_io_fd_read_at (io, desc->fd, 0, buf, sizeof (buf)), sizeof (buf), "fd read");
	mu_assert_memeq (buf, exp, sizeof (buf), "the fd holds the writes");
	r_io_fd_write_at (io, desc->fd, 4, (const ut8 *)"\x77", 1);
	r_io_vread_at (io, 4, buf, 1);
	mu_assert_eq (buf[0], 0x77, "a write across the overlay does not extend it");
	io->overlay = false;
	mu_assert_true (r_io_vwrite_at (io, 2, (const ut8 *)"\xdd", 1), "write with the overlay ignored");
	io->overlay = true;
	r_io_vread_at (io, 2, buf, 1);
	mu_assert_eq (buf[0], 0xdd, "the overlay does not hide a write made while it was ignored");
	r_io_free (io);
	mu_end;
}

bool test_seek_history_mapped(void) {
	RIO *io = r_io_new ();
	r_io_undo_enable (io, true, false);
	RIODesc *desc = r_io_open_at (io, "malloc://256", R_PERM_RW, 0, 0x1000);
	mu_assert_notnull (desc, "open mapped IO");
	RIOMap *map = r_io_map_get_at (io, 0x1000);
	mu_assert_notnull (map, "find map");
	map->delta = 0x20;
	int va;
	for (va = 0; va <= 1; va++) {
		io->va = va;
		r_io_sundo_reset (io);
		r_io_sundo_push (io, 0x1010, 0);
		r_io_seek (io, 0x1020, R_IO_SEEK_SET);
		RIOUndos *undo = r_io_sundo (io, io->off);
		mu_assert_notnull (undo, "undo mapped seek");
		mu_assert_eq (io->off, 0x1010, "undo preserves seek address space");
		undo = r_io_sundo_redo (io);
		mu_assert_notnull (undo, "redo mapped seek");
		mu_assert_eq (io->off, 0x1020, "redo preserves seek address space");
	}
	r_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_seek_history_mapped);
	mu_run_test(test_r_io_cache);
	mu_run_test(test_r_io_nread_at);
	mu_run_test(test_r_io_fd_seek_read);
	mu_run_test(test_r_io_mapsplit);
	mu_run_test(test_r_io_mapsplit2);
	mu_run_test(test_r_io_mapsplit3);
	mu_run_test(test_r_io_pcache);
	mu_run_test(test_r_io_desc_exchange);
	//mu_run_test(test_r_io_priority);
	// mu_run_test(test_r_io_priority2);
	mu_run_test(test_va_malloc_zero);
	mu_run_test(test_r_io_overlay_write_through);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
