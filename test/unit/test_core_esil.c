#include <r_core.h>
#include "minunit.h"

static bool handled_fault(REsil *esil, ut64 addr, ut8 *buf, int len) {
	memset (buf, 0, len);
	r_esil_set_fault (esil, R_ANAL_TRAP_READ_ERR, addr);
	return true;
}

bool test_core_fault_state(void) {
	const char *arches[] = { "x86", "arm", "riscv" };
	size_t i;
	int revert;
	for (i = 0; i < R_ARRAY_SIZE (arches); i++) {
		RCore *core = r_core_new ();
		r_config_set (core->config, "asm.arch", arches[i]);
		r_config_set_i (core->config, "asm.bits", 64);
		RIODesc *file = r_core_file_open (core, "malloc://64", R_PERM_RWX, 0);
		mu_assert_notnull (file, "open instruction memory");
		mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0, 64), "map instruction memory");
		r_core_esil_load_arch (core);
		r_anal_hint_set_size (core->anal, 0, 4);
		for (revert = 0; revert < 2; revert++) {
			r_config_set_b (core->config, "esil.traprevert", revert);
			r_reg_setv (core->anal->reg, "PC", 0);
			r_anal_hint_set_esil (core->anal, 0, "0x100000005,[1]");
			ut64 stop_addr = UT64_MAX;
			RCoreEsilStepStatus status = r_core_esil_step_until (core, UT64_MAX, NULL, NULL, false, &stop_addr);
			mu_assert_eq (status, R_CORE_ESIL_STEP_STATUS_IOTRAP, "fault address low bits do not determine stop type");
			mu_assert_eq (stop_addr, 0, "stop identifies instruction address");
			mu_assert_eq (core->dbg->reason.type, R_DEBUG_REASON_READERR, "debugger records read error");
			mu_assert_eq (core->dbg->reason.addr, 0x100000005ULL, "debugger retains 64-bit fault address");
			mu_assert_eq (core->dbg->reason.ptr, 0x100000005ULL, "debugger retains fault pointer");
			mu_assert_true (core->esil.esil.trap_addr_valid, "fault survives optional rollback");
			mu_assert_eq (core->esil.esil.trap_addr, 0x100000005ULL, "rollback retains full address");
			mu_assert_eq (core->anal->esil->trap_addr, 0x100000005ULL, "legacy VM receives full trap record");
			mu_assert_true (core->anal->esil->trap_addr_valid, "legacy VM receives address validity");
			mu_assert_false (r_core_esil_run_expr_at (core, "42,0xfffffffd00290000,=[1]", 0), "expression reports failed write");
			mu_assert_eq (core->esil.esil.trap, R_ANAL_TRAP_WRITE_ERR, "write fault survives expression rollback");
			mu_assert_eq (core->esil.esil.trap_addr, 0xfffffffd00290000ULL, "expression rollback retains full address");
			mu_assert_true (core->esil.esil.trap_addr_valid, "expression fault has an address");
			mu_assert_true (r_core_esil_run_expr_at (core, "1,1,+", 0), "successful expression after fault");
			mu_assert_false (core->esil.esil.trap_addr_valid, "successful expression clears old address");
			core->esil.esil.cb.hook_mem_read = handled_fault;
			mu_assert_false (r_core_esil_run_expr_at (core, "0x100000002,[1]", 0), "handled hook fault stops successful parse");
			mu_assert_eq (core->esil.esil.trap_addr, 0x100000002ULL, "hook address survives rollback");
			core->esil.esil.cb.hook_mem_read = NULL;
			r_anal_hint_set_esil (core->anal, 0, "2,3,TRAP");
			r_reg_setv (core->anal->reg, "PC", 0);
			status = r_core_esil_step_until (core, UT64_MAX, NULL, NULL, false, &stop_addr);
			mu_assert_eq (status, R_CORE_ESIL_STEP_STATUS_TRAP, "breakpoint-valued code cannot override division trap type");
			mu_assert_eq (core->dbg->reason.type, R_DEBUG_REASON_DIVBYZERO, "debugger uses trap type, not code");
			mu_assert_false (core->esil.esil.trap_addr_valid, "non-memory trap has no stale address");
			mu_assert_false (r_core_esil_run_expr_at (core, "0,3,TRAP", 0), "trap with code zero stops");
			mu_assert_eq (core->esil.esil.trap_code, 0, "zero trap code survives rollback");
		}
		r_reg_setv (core->anal->reg, "PC", 0x100000000ULL);
		mu_assert_false (r_core_esil_single_step (core), "unmapped instruction fetch traps");
		mu_assert_eq (core->esil.esil.trap, R_ANAL_TRAP_EXEC_ERR, "execute fault type");
		mu_assert_eq (core->esil.esil.trap_addr, 0x100000000ULL, "full instruction fault address");
		mu_assert_true (core->esil.esil.trap_addr_valid, "execute fault has address");
		r_core_free (core);
	}
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_core_fault_state);
	return tests_passed != tests_run;
}
