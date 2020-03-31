#include <r_io.h>
#include "minunit.h"

bool test_r_io_mapsplit (void) {
	RIO *io = r_io_new ();
	io->va = true;
	r_io_open_at (io, "null://2", R_PERM_R, 0LL, UT64_MAX);
	mu_assert ("Found no map at UT64", r_io_map_get (io, UT64_MAX));
	mu_assert ("Found no map at 0x0", r_io_map_get (io, 0x0));
	r_io_free (io);
	mu_end;
}

bool test_r_io_mapsplit2 (void) {
	RIO *io = r_io_new ();
	io->va = true;
	r_io_open_at (io, "null://2", R_PERM_R, 0LL, 0LL);
	r_io_map_remap (io, r_io_map_get (io, 0LL)->id, UT64_MAX);
	mu_assert ("Found no map at UT64", r_io_map_get (io, UT64_MAX));
	mu_assert ("Found no map at 0x0", r_io_map_get (io, 0x0));
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
	ut32 map0, map1;
	ut64 buf;
	bool ret;

	io->va = true;
	r_io_open_at (io, "malloc://8", R_PERM_RW, 0644, 0x0);
	map0 = r_io_map_get (io, 0)->id;
	ret = r_io_read_at (io, 0, (ut8 *)&buf, 8);
	mu_assert ("should be able to read", ret);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, "0 should be there initially");
	buf = 0x9090909090909090;
	r_io_write_at (io, 0, (ut8 *)&buf, 8);
	mu_assert_memeq ((ut8 *)&buf, (ut8 *)"\x90\x90\x90\x90\x90\x90\x90\x90", 8, "0x90 should have been written");

	r_io_open_at (io, "malloc://2", R_PERM_RW, 0644, 0x4);
	map1 = r_io_map_get (io, 4)->id;
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
	map0 = r_io_map_get (io, 0)->id;
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
	mu_run_test(test_r_io_mapsplit);
	mu_run_test(test_r_io_mapsplit2);
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
