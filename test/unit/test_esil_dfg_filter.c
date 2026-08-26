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
	RIO *io = r_io_new ();
	r_io_bind (io, &anal->iob);
	REsilOptions opt = r_esil_options (anal->reg, &anal->iob);
	opt.addrsize = 1;
	REsil *esil = r_esil_new (&opt);
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
	r_io_free (io);

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

	RIO *io = r_io_new ();
	r_io_bind (io, &anal->iob);

	RAnalEsilDFG *dfg = r_anal_esil_dfg_expr (anal, NULL, "4,!,3,ebx,:=,!,1,+,eax,:=", false, false);
	r_anal_esil_dfg_fold_const (anal, dfg);
	RStrBuf *filtered = r_anal_esil_dfg_filter (dfg, "eax");
	const bool cmp_result = !strcmp (r_strbuf_get(filtered), "0x2,eax,:=");
	r_strbuf_free (filtered);
	r_anal_esil_dfg_free (dfg);
	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (cmp_result, "esil dfg const folding is broken");
	mu_end;
}

static RAnal *dfg_anal_new(RIO **io) {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 32);
	r_anal_set_reg_profile (anal, NULL);
	*io = r_io_new ();
	r_io_bind (*io, &anal->iob);
	return anal;
}

static bool filter_is(RAnal *anal, const char *expr, const char *reg, const char *expected) {
	RStrBuf *filtered = r_anal_esil_dfg_filter_expr (anal, expr, reg, false, false);
	const bool ok = filtered && !strcmp (r_strbuf_get (filtered), expected);
	if (!ok) {
		eprintf ("%s [%s] => '%s', expected '%s'\n", expr, reg,
			filtered? r_strbuf_get (filtered): "(null)", expected);
	}
	r_strbuf_free (filtered);
	return ok;
}

// the guarded body of a conditional must reach the graph, dropping a
// predicated write loses the dependency entirely
bool test_dfg_conditional(void) {
	RIO *io;
	RAnal *anal = dfg_anal_new (&io);

	const bool body = filter_is (anal, "zf,?{,1,eax,+=,}", "eax", "1,eax,+=");
	const bool assign = filter_is (anal, "zf,?{,3,eax,=,}", "eax", "3,eax,=");
	// "}{" toggles esil->skip, so only the first branch is taken
	const bool taken = filter_is (anal, "zf,?{,1,eax,=,}{,2,eax,=,}", "eax", "1,eax,=");

	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (body, "conditional body was dropped");
	mu_assert_true (assign, "conditional assignment was dropped");
	mu_assert_true (taken, "conditional followed the branch not taken");
	mu_end;
}

// comparisons must build nodes instead of folding operands to a concrete
// boolean, and must feed the flag ops through old/cur
bool test_dfg_compare(void) {
	RIO *io;
	RAnal *anal = dfg_anal_new (&io);

	const bool cmp = filter_is (anal, "ebx,eax,<,ecx,=", "ecx", "ebx,eax,<,ecx,=");
	const bool keep = filter_is (anal, "ebx,eax,==,7,ecx,=", "ecx", "7,ecx,=");
	RStrBuf *zf = r_anal_esil_dfg_filter_expr (anal, "ebx,eax,==,$z,zf,=", "zf", false, false);
	const bool flag = zf && r_strbuf_length (zf) > 0;
	r_strbuf_free (zf);

	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (cmp, "comparison was folded to a constant");
	mu_assert_true (keep, "comparison truncated the expression");
	mu_assert_true (flag, "comparison did not feed the zero flag");
	mu_end;
}

// BREAK and GOTO must not truncate or unroll the graph
bool test_dfg_control_flow(void) {
	RIO *io;
	RAnal *anal = dfg_anal_new (&io);

	const bool brk = filter_is (anal, "ecx,!,?{,BREAK,},7,eax,=", "eax", "7,eax,=");
	const bool jmp = filter_is (anal, "eax,--=,zf,!,?{,0,GOTO,}", "eax", "eax,--=");

	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (brk, "BREAK truncated the graph");
	mu_assert_true (jmp, "GOTO broke the graph");
	mu_end;
}

// read-modify-write ops on a register operand must update the register
bool test_dfg_reg_rmw(void) {
	RIO *io;
	RAnal *anal = dfg_anal_new (&io);

	const bool shr = filter_is (anal, "3,eax,>>=", "eax", "3,eax,>>=");
	const bool shl = filter_is (anal, "3,eax,<<=", "eax", "3,eax,<<=");
	const bool neg = filter_is (anal, "eax,!=", "eax", "eax,!=");

	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (shr, ">>= did not write the register");
	mu_assert_true (shl, "<<= did not write the register");
	mu_assert_true (neg, "!= did not write the register");
	mu_end;
}

// POP discards a value, so it must not contribute anything to the graph
bool test_dfg_pop(void) {
	RIO *io;
	RAnal *anal = dfg_anal_new (&io);

	const bool before = filter_is (anal, "ebx,POP,3,eax,=", "eax", "3,eax,=");
	const bool after = filter_is (anal, "3,eax,=,ebx,POP", "eax", "3,eax,=");

	RAnalEsilDFG *plain = r_anal_esil_dfg_expr (anal, NULL, "3,eax,=", false, false);
	RAnalEsilDFG *popped = r_anal_esil_dfg_expr (anal, NULL, "3,eax,=,ebx,POP", false, false);
	const bool same = r_list_length (r_graph_get_nodes (plain->flow))
		== r_list_length (r_graph_get_nodes (popped->flow));
	r_anal_esil_dfg_free (plain);
	r_anal_esil_dfg_free (popped);

	r_anal_free (anal);
	r_io_free (io);

	mu_assert_true (before, "POP cut the expression short");
	mu_assert_true (after, "POP changed the filtered expression");
	mu_assert_true (same, "POP added nodes for a discarded value");
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_filter_regs);
	mu_run_test (test_lemon_const_folder);
	mu_run_test (test_dfg_conditional);
	mu_run_test (test_dfg_compare);
	mu_run_test (test_dfg_control_flow);
	mu_run_test (test_dfg_reg_rmw);
	mu_run_test (test_dfg_pop);
	return tests_passed != tests_run;
}
