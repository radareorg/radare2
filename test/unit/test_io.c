#include <r_io.h>
#include "minunit.h"

bool test_r_io_cache(void) {
	RIO *io = r_io_new ();
	r_io_open (io, "malloc://15", R_PERM_RW, 0);
	r_io_write (io, (ut8 *)"ZZZZZZZZZZZZZZZ", 15);
	mu_assert_false (r_io_cache_at (io, 0), "Cache shouldn't exist at 0");
	mu_assert_false (r_io_cache_at (io, 10), "Cache shouldn't exist at 10");
	mu_assert_true (r_io_cache_write (io, 0, (ut8 *)"AAAAA", 5), "Cache write at 0 failed");
	mu_assert_true (r_io_cache_write (io, 10, (ut8 *)"BBBBB", 5), "Cache write at 10 failed");
	mu_assert_true (r_io_cache_at (io, 0), "Cache should exist at 0 (beggining of cache)");
	mu_assert_true (r_io_cache_at (io, 4), "Cache should exist at 4 (end of cache)");
	mu_assert_false (r_io_cache_at (io, 8), "Cache shouldn't exist at 8 (between 2 caches)");
	mu_assert_true (r_io_cache_at (io, 12), "Cache should exist at 12 (middle of cache)");
	ut8 buf[15];
	memset (buf, 'Z', sizeof (buf));
	mu_assert_true (r_io_cache_read (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"AAAAAZZZZZBBBBB", sizeof (buf), "Cache read doesn't match expected output");
	memset (buf, 'Z', sizeof (buf));
	mu_assert_true (r_io_cache_write (io, 0, (ut8 *)"CC", 2), "Overlapped cache write at 0 failed");
	mu_assert_true (r_io_cache_write (io, 4, (ut8 *)"DD", 2), "Overlapped cache write at 4 failed");
	mu_assert_true (r_io_cache_write (io, 8, (ut8 *)"EEE", 3), "Cache write at 4 failed");
	mu_assert_true (r_io_cache_read (io, 0, buf, 2), "Cache read at 0 failed");
	mu_assert_true (r_io_cache_read (io, 2, buf + 2, 2), "Cache read at 2 failed");
	mu_assert_true (r_io_cache_read (io, 4, buf + 4, 2), "Cache read at 4 failed");
	mu_assert_true (r_io_cache_read (io, 6, buf + 6, 2), "Cache read at 6 failed");
	mu_assert_true (r_io_cache_read (io, 8, buf + 8, 3), "Cache read at 8 failed");
	mu_assert_true (r_io_cache_read (io, 11, buf + 11, 4), "Cache read at 11 failed");
	mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "Cache read doesn't match expected output");
	mu_assert_true (r_io_cache_write (io, 0, (ut8 *)"FFFFFFFFFFFFFFF", 15), "Cache write failed");
	mu_assert_true (r_io_cache_read (io, 0, buf, sizeof (buf)), "Cache read failed");
	mu_assert_memeq (buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof (buf), "Cache read doesn't match expected output");
	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"ZZZZZZZZZZZZZZZ", sizeof (buf), "IO read without cache doesn't match expected output");
	io->cached = R_PERM_R;
	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"FFFFFFFFFFFFFFF", sizeof (buf), "IO read with cache doesn't match expected output");
	r_io_cache_invalidate (io, 6, 1);
	memset (buf, 'Z', sizeof (buf));
	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "IO read after cache invalidate doesn't match expected output");
	r_io_cache_commit (io, 0, 15);
	memset (buf, 'Z', sizeof (buf));
	io->cached = 0;
	r_io_read_at (io, 0, buf, sizeof (buf));
	mu_assert_memeq (buf, (ut8 *)"CCAADDZZEEEBBBB", sizeof (buf), "IO read after cache commit doesn't match expected output");
	r_io_free (io);
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
	r_io_open_at (io, "null://2", R_PERM_R, 0LL, UT64_MAX - 1);
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
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\xff\x6f\x90\x90\x6f\x6f", 8, "map1 should have been remapped and partialy hidden");

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

int all_tests() {
	mu_run_test(test_r_io_cache);
	mu_run_test(test_r_io_mapsplit);
	mu_run_test(test_r_io_mapsplit2);
	mu_run_test(test_r_io_mapsplit3);
	mu_run_test(test_r_io_pcache);
	mu_run_test(test_r_io_desc_exchange);
	mu_run_test(test_r_io_priority);
	mu_run_test(test_r_io_priority2);
	mu_run_test(test_va_malloc_zero);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
