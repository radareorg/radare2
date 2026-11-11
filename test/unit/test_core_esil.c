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

typedef struct {
	ut8 bytes[64];
	int reads;
	int writes;
	int errors;
	bool read_ok;
	bool write_ok;
} VectorTarget;

static bool vector_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	VectorTarget *target = dbg->current->plugin_data;
	target->reads++;
	if (!target->read_ok || type != R_REG_TYPE_FPU) {
		return false;
	}
	memset (buf, 0, size);
	memcpy (buf, target->bytes, R_MIN (size, sizeof (target->bytes)));
	return true;
}

static bool vector_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	VectorTarget *target = dbg->current->plugin_data;
	target->writes++;
	if (!target->write_ok || type != R_REG_TYPE_FPU) {
		return false;
	}
	memcpy (target->bytes, buf, R_MIN (size, sizeof (target->bytes)));
	return true;
}

static bool vector_sync_error(void *user, int type, const char *origin, const char *msg) {
	VectorTarget *target = user;
	if (type == R_LOG_LEVEL_ERROR && msg && strstr (msg, "debugger vector registers")) {
		target->errors++;
	}
	return true;
}

bool test_vector_debug_sync(void) {
	RCore *core = r_core_new ();
	r_config_set_b (core->config, "cfg.debug", true);
	mu_assert_true (r_reg_set_profile_string (core->dbg->reg,
		"gpr rax .64 0 0\nvec128@fpu xmm0 .128 0 4\nfpu xmm0l .64 0 8\nvec256@fpu ymm0 .256 0 4\n"), "vector profile");
	core->dbg->reg->endian = R_SYS_ENDIAN_LITTLE;
	VectorTarget target = { 0 };
	RDebugPlugin plugin = {
		.meta = { .name = "vector-test" },
		.reg_read = vector_reg_read,
		.reg_write = vector_reg_write,
	};
	RDebugPluginSession session = { .plugin = &plugin, .plugin_data = &target };
	RDebugPluginSession *previous = core->dbg->current;
	core->dbg->current = &session;
	core->dbg->pid = 123;
	r_log_add_callback (vector_sync_error, &target);
	mu_assert_false (r_debug_reg_sync (core->dbg, R_REG_TYPE_VEC128, false), "backend read failure propagates through redirected arena");
	char *output = r_core_cmd_str (core, "drvj xmm0");
	mu_assert_streq (output, "", "failed read emits no stale JSON");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "failed read sets command status");
	free (output);
	r_core_cmd0 (core, "drv xmm0 0 = 51");
	mu_assert_eq (target.writes, 0, "failed preread prevents write");
	mu_assert_eq (target.errors, 2, "both commands report read failure");

	target.read_ok = true;
	r_write_le64 (target.bytes, 17);
	r_write_le64 (target.bytes + 8, 34);
	r_core_cmd0 (core, "drv xmm0 0 = 51");
	mu_assert_eq (target.writes, 1, "backend write attempted");
	mu_assert_eq (target.errors, 3, "write failure reported");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "failed write sets command status");
	RRegItem *item = r_reg_get (core->dbg->reg, "xmm0", R_REG_TYPE_ALL);
	mu_assert_eq (r_reg_get_pack (core->dbg->reg, item, 0, 64), 17, "failed write restores last synchronized lane");
	mu_assert_eq (r_reg_get_pack (core->dbg->reg, item, 1, 64), 34, "preread loads untouched lane");
	target.write_ok = true;
	r_write_le64 (target.bytes + 8, 68);
	r_core_cmd0 (core, "drv xmm0 0 = 51");
	mu_assert_eq (r_read_le64 (target.bytes), 51, "write updates selected lane");
	mu_assert_eq (core->rc, R_CMD_RC_SUCCESS, "successful write clears command failure");
	mu_assert_eq (r_read_le64 (target.bytes + 8), 68, "write preserves target changes in other lanes");
	r_core_cmd0 (core, "drv ymm0 3 = 85");
	mu_assert_eq (r_read_le64 (target.bytes + 24), 85, "wide writes use backend capability");

	target.write_ok = false;
	output = r_core_cmd_str (core, "drv* ymm0 3");
	mu_assert_streq (output, "drv ymm0 3 64 = 0x55\n", "wide restore export only reads registers");
	free (output);
	mu_assert_eq (target.writes, 3, "export does not write debugger registers");
	int reads = target.reads;
	output = r_core_cmd_str (core, "drvq");
	mu_assert_notnull (strstr (output, "xmm0"), "list includes XMM");
	mu_assert_notnull (strstr (output, "ymm0"), "list includes YMM");
	mu_assert_null (strstr (output, "xmm0l"), "list omits overlapping scalar aliases");
	mu_assert_eq (target.reads, reads + 1, "list reads a shared arena once");
	free (output);
	target.read_ok = false;
	output = r_core_cmd_str (core, "drv");
	mu_assert_streq (output, "", "failed list read emits no stale text");
	free (output);
	reads = target.reads;
	output = r_core_cmd_str (core, "drvj");
	mu_assert_notnull (strstr (output, "xmm0"), "discovery works without live register values");
	mu_assert_null (strstr (output, "xmm0l"), "JSON discovery omits the same aliases");
	mu_assert_eq (target.reads, reads, "discovery does not synchronize");
	free (output);
	r_unref (item);
	r_log_del_callback (vector_sync_error);
	core->dbg->current = previous;
	r_core_free (core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_core_fault_state);
	mu_run_test (test_vector_debug_sync);
	return tests_passed != tests_run;
}
