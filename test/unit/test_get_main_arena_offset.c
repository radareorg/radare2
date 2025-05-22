#include <r_bin.h>
#include <r_core.h>
#include <math.h>
#include "../../libr/include/r_heap_glibc.h"
#define R_INCLUDE_BEGIN 1
#include "../../libr/core/dmh_glibc.inc.c"
#undef R_INCLUDE_BEGIN
#include "minunit.h"

bool test_get_main_arena_offset_with_symbol(void) {
	RCore * core = r_core_new();
	GHT arena_offset;

	// 2.21
	arena_offset = 0;
	arena_offset = GH (get_main_arena_offset_with_symbol) (core, "bins/elf/libc-2.21-debug.so");
	mu_assert_eq (arena_offset, 0x003c4c00, "Incorrect main_arena_offset for debug 2.21");

	// 2.26
	arena_offset = 0;
	arena_offset = GH (get_main_arena_offset_with_symbol) (core, "bins/elf/libc-2.26-debug.so");
	mu_assert_eq (arena_offset, 0x003dac20, "Incorrect main_arena_offset for debug 2.26");

	r_core_free (core);
	mu_end;
}

bool test_get_main_arena_offset_with_relocs(void) {
	RCore *core = r_core_new ();

	GHT arena_offset;
	core->dbg->glibc_version_resolved = true;

	// 2.21
	arena_offset = 0;
	core->dbg->glibc_version_d = 2.21;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.21.so");
	mu_assert_eq (arena_offset, 0x3c4c00, "Incorrect main_arena_offset for 2.21");

	// 2.23
	arena_offset = 0;
	core->dbg->glibc_version_d = 2.23;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.23.so");
	mu_assert_eq (arena_offset, 0x3c4b20, "Incorrect main_arena_offset for 2.23");

	// 2.26
	arena_offset = 0;
	core->dbg->glibc_version_d = 2.26;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.26.so");
	mu_assert_eq (arena_offset, 0x3dac20, "Incorrect main_arena_offset for 2.26");

	// 2.27
	arena_offset = 0;
	core->dbg->glibc_version_d = 2.27;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.27.so");
	mu_assert_eq (arena_offset, 0x3ebc40, "Incorrect main_arena_offset for 2.27");

	// 2.28
	arena_offset = 0;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc.so.6");
	mu_assert_eq (arena_offset, 0x1beaa0, "Incorrect main_arena_offset for 2.28");

	// 2.31
	arena_offset = 0;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.31.so");
	mu_assert_eq (arena_offset, 0x1bf9e0, "Incorrect main_arena_offset for 2.31");

	// 2.32
	arena_offset = 0;
	arena_offset = GH (get_main_arena_offset_with_relocs) (core, "bins/elf/libc-2.32.so");
	mu_assert_eq (arena_offset, 0x1c2a00, "Incorrect main_arena_offset for 2.32");

	r_core_free (core);
	mu_end;
}

bool all_tests (void) {
	mu_run_test (test_get_main_arena_offset_with_symbol);
#if R_SYS_ENDIAN == 0
	// XXX this thing fails on big endian machines
	mu_run_test (test_get_main_arena_offset_with_relocs);
#endif
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
