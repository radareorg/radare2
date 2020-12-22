#include <r_debug.h>
#include "minunit.h"
#if __linux__
#include <sys/user.h>

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

#endif //__linux__

bool test_r_debug_use(void) {
	RDebug *dbg;
	bool res;

	dbg = r_debug_new (true);
	mu_assert_notnull (dbg, "r_debug_new () failed");

	res = r_debug_use (dbg, "null");
	mu_assert_eq (res, true, "r_debug_use () failed");

	r_debug_free (dbg);
	mu_end;
}

bool test_r_debug_reg_offset(void) {
#if __linux__
#ifdef __x86_64__
#define FPREGS struct user_fpregs_struct
	FPREGS regs;
	mu_assert_eq (sizeof (regs.cwd), 2, "cwd size");
	mu_assert_eq (offsetof (FPREGS, cwd), 0, "cwd offset");

	mu_assert_eq (sizeof (regs.rip), 8, "rip size");
	mu_assert_eq (offsetof (FPREGS, rip), 8, "rip offset");

	mu_assert_eq (sizeof (regs.mxcsr), 4, "mxcsr size");
	mu_assert_eq (offsetof (FPREGS, mxcsr), 24, "mxcsr offset");

	mu_assert_eq (sizeof (regs.mxcr_mask), 4, "mxcr_mask size");
	mu_assert_eq (offsetof (FPREGS, mxcr_mask), 28, "mxcr_mask offset");

	mu_assert_eq (sizeof (regs.st_space[0]) * 2, 8, "st0 size");
	mu_assert_eq (offsetof (FPREGS, st_space[0]), 32, "st0 offset");

	mu_assert_eq (sizeof (regs.xmm_space[0]) * 4, 16, "xmm0 size");
	mu_assert_eq (offsetof (FPREGS, xmm_space[0]), 160, "xmm0 offset");

	mu_assert_eq (offsetof (FPREGS, padding[0]), 416, "x64");
#endif //__x86_64__
#endif //__linux__
	mu_end;
}

int all_tests() {
	mu_run_test (test_r_debug_use);
	mu_run_test (test_r_debug_reg_offset);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
