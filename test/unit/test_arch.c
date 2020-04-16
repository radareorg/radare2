#include <r_arch.h>
#include "minunit.h"

bool test_arch_bf(void) {
	RArchInstruction ins;
	bool res;

	RArch *a = r_arch_new ();
	mu_assert_notnull (a, "r_arch_new");

	res = r_arch_use (a, "bf");
	mu_assert ("r_arch_use", res);

	r_arch_instruction_init (&ins);

	r_strbuf_setf (&ins.code, "nop");
	res = r_arch_encode (a, &ins, R_ARCH_OPTION_CODE);
	mu_assert ("r_arch_encode", res);
	mu_assert_eq (ins.size, 1, "encoded instruction size");
	mu_assert_eq (r_strbuf_get (&ins.data)[0], (char)0x90, "encoded instruction size");

	r_strbuf_setbin (&ins.data, (const ut8*)"\x2b", 1);
	res = r_arch_decode (a, &ins, R_ARCH_OPTION_CODE);
	mu_assert ("r_arch_decode", res);

	const char *opstr = r_strbuf_get (&ins.code);
	mu_assert_streq (opstr, "inc [ptr]", "invalid decoded instruction");

	r_arch_instruction_fini (&ins);

	r_arch_free (a);

	mu_end;
}

int all_tests() {
	mu_run_test (test_arch_bf);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
