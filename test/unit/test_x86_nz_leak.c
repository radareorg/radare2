#include <r_asm.h>
#include <r_anal.h>
#include "minunit.h"

static void make_x86_asm(RAsm **out_asm, RAnal **out_anal) {
	RAsm *a = r_asm_new ();
	RAnal *anal = r_anal_new ();
	r_unref (anal->config);
	a->num = r_num_new (NULL, NULL, NULL);
	anal->config = r_ref_ptr (a->config);
	r_anal_bind (anal, &a->analb);
	r_asm_use (a, "x86");
	r_asm_set_bits (a, 32);
	*out_asm = a;
	*out_anal = anal;
}

static void free_x86_asm(RAsm *a, RAnal *anal) {
	r_num_free (a->num);
	a->num = NULL;
	r_asm_free (a);
	r_anal_free (anal);
}

// Inputs that previously leaked out->mnemonic on the parseOpcode -1 return:
// they tokenize past the mnemonic (so r_str_ndup runs) but then fail inside
// parseOperand. If the fix regresses, ASan+LSan at program exit will report
// the leak and flip this test from PASS to the LSan-induced nonzero exit.
static int test_failed_assemble_no_leak(void) {
	RAsm *a;
	RAnal *anal;
	make_x86_asm (&a, &anal);

	const char *bad[] = {
		"movl $33, %eax",
		"addl %eax, %ebx",
		"mov %nonsense, %eax",
		NULL
	};
	int i;
	for (i = 0; bad[i]; i++) {
		RAsmCode *code = r_asm_assemble (a, bad[i]);
		bool failed = !code || code->len <= 0;
		mu_assert_true (failed, bad[i]);
		r_asm_code_free (code);
	}

	free_x86_asm (a, anal);
	mu_end;
}

static int test_clean_assemble_still_works(void) {
	RAsm *a;
	RAnal *anal;
	make_x86_asm (&a, &anal);

	const char *good[] = { "mov eax, 1", "ret", "nop", NULL };
	int i;
	for (i = 0; good[i]; i++) {
		RAsmCode *code = r_asm_assemble (a, good[i]);
		mu_assert_notnull (code, good[i]);
		mu_assert_true (code->len > 0, good[i]);
		r_asm_code_free (code);
	}

	free_x86_asm (a, anal);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_failed_assemble_no_leak);
	mu_run_test (test_clean_assemble_still_works);
	return tests_passed != tests_run;
}
