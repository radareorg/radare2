#include <r_anal.h>
#include <r_reg.h>
#include <r_io.h>
#include <r_esil.h>
#include <r_util.h>
#include "minunit.h"

bool test_filter_regs(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 32);
	r_anal_set_reg_profile (anal, NULL);
#if USE_NEW_ESIL
	RIO *io = r_io_new ();
	r_io_bind (io, &anal->iob);
	REsil *esil = r_esil_new_simple (1, anal->reg, &anal->iob);
#else
	REsil *esil = r_esil_new (4096, 0, 1);
#endif
	esil->anal = anal;

	// create expected results
	r_esil_parse (esil, "0x9090,ax,:=,0xff,ah,:=");
	const ut64 ax = r_reg_getv (anal->reg, "ax");
	const ut64 ah = r_reg_getv (anal->reg, "ah");
	const ut64 al = r_reg_getv (anal->reg, "al");
	r_reg_setv (anal->reg, "eax", 0);

	RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (anal, NULL, "0x9090,ax,:=,0xff,ah,:=", false, false);

	// filter for ax register
	RStrBuf *filtered_expr = r_anal_esil_dfg_filter (dfg, "ax");
	r_esil_parse (esil, r_strbuf_get (filtered_expr));
	const ut64 filtered_ax = r_reg_getv (anal->reg, "ax");
	r_strbuf_free (filtered_expr);
	r_reg_setv (anal->reg, "eax", 0);

	// filter for ah register
	filtered_expr = r_anal_esil_dfg_filter (dfg, "ah");
	r_esil_parse (esil, r_strbuf_get (filtered_expr));
	const ut64 filtered_ah = r_reg_getv (anal->reg, "ah");
	r_strbuf_free (filtered_expr);
	r_reg_setv (anal->reg, "eax", 0);

	// filter for al register
	filtered_expr = r_anal_esil_dfg_filter (dfg, "al");
	r_esil_parse (esil, r_strbuf_get (filtered_expr));
	const ut64 filtered_al = r_reg_getv (anal->reg, "al");
	r_strbuf_free (filtered_expr);

	r_anal_esil_dfg_free (dfg);
	r_esil_free (esil);
	r_anal_free (anal);
#if USE_NEW_ESIL
	r_io_free (io);
#endif

	mu_assert ("filtering for ax failed", ax == filtered_ax);
	mu_assert ("filtering for ah failed", ah == filtered_ah);
	mu_assert ("filtering for al failed", al == filtered_al);
	mu_end;
}

bool test_lemon_const_folder(void) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 32);
	r_anal_set_reg_profile (anal, NULL);

#if USE_NEW_ESIL
	RIO *io = r_io_new ();
	r_io_bind (io, &anal->iob);
#endif

	RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (anal, NULL, "4,!,3,ebx,:=,!,1,+,eax,:=", false, false);
	r_anal_esil_dfg_fold_const (anal, dfg);
	RStrBuf *filtered = r_anal_esil_dfg_filter (dfg, "eax");
	const bool cmp_result = !strcmp (r_strbuf_get(filtered), "0x2,eax,:=");
	r_strbuf_free (filtered);
	r_anal_esil_dfg_free (dfg);
	r_anal_free (anal);
#if USE_NEW_ESIL
	r_io_free (io);
#endif

	mu_assert_true (cmp_result, "esil dfg const folding is broken");
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_filter_regs);
	mu_run_test (test_lemon_const_folder);
	return tests_passed != tests_run;
}
