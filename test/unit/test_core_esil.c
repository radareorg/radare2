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
	output = r_core_cmd_str (core, "dr xmm0=0x112233445566778899aabbccddeeff00");
	mu_assert_streq_free (output, "", "whole-register preread failure emits no success");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "whole-register preread failure status");
	target.read_ok = true;
	output = r_core_cmd_str (core, "dr xmm0=0x112233445566778899aabbccddeeff00");
	mu_assert_streq_free (output, "", "whole-register backend write failure emits no success");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "whole-register write failure status");
	mu_assert_eq (r_reg_get_pack (core->dbg->reg, item, 0, 64), 51, "failed write restores low chunk");
	mu_assert_eq (r_reg_get_pack (core->dbg->reg, item, 1, 64), 68, "failed write restores high chunk");
	target.write_ok = true;
	output = r_core_cmd_str (core, "dr xmm0=0x112233445566778899aabbccddeeff00");
	mu_assert_streq_free (output, "0x00000000000000440000000000000033 -> 0x112233445566778899aabbccddeeff00\n", "whole-register change output");
	mu_assert_eq (r_read_le64 (target.bytes), 0x99aabbccddeeff00ULL, "whole-register low chunk synchronized");
	mu_assert_eq (r_read_le64 (target.bytes + 8), 0x1122334455667788ULL, "whole-register high chunk synchronized");
	mu_assert_eq (r_read_le64 (target.bytes + 24), 85, "overlapping YMM upper chunk preserved");
	int writes = target.writes;
	r_core_cmd0 (core, "dr xmm0=0x100000000000000000000000000000000");
	mu_assert_eq (core->rc, R_CMD_RC_FAILURE, "overflow is a command failure");
	mu_assert_eq (target.writes, writes, "invalid value does not reach backend");
	r_unref (item);
	r_log_del_callback (vector_sync_error);
	core->dbg->current = previous;
	r_core_free (core);
	mu_end;
}

bool test_wide_register_restore(void) {
	RCore *core = r_core_new ();
	r_core_esil_load_arch (core);
	RReg *reg = core->anal->reg;
	mu_assert_true (r_reg_set_profile_string (reg, "=PC pc\ngpr pc .64 0 0\nfpu wide .384 0 0\nfpu tail .80 48 0\n"), "restore profile");
	RRegItem *wide = r_reg_get (reg, "wide", R_REG_TYPE_ALL);
	RRegItem *tail = r_reg_get (reg, "tail", R_REG_TYPE_ALL);
	const char modes[] = { 'R', '.', 'e' };
	int endian, mode;
	for (endian = 0; endian < 2; endian++) {
		reg->endian = endian? R_SYS_ENDIAN_BIG: R_SYS_ENDIAN_LITTLE;
		for (mode = 0; mode < R_ARRAY_SIZE (modes); mode++) {
			mu_assert_true (r_reg_set_pack (reg, wide, 0, 64, 0x11), "restore low lane");
			mu_assert_true (r_reg_set_pack (reg, wide, 5, 64, 0x22), "restore high lane");
			mu_assert_true (r_reg_set_pack (reg, tail, 0, 64, 0x33), "partial low chunk");
			mu_assert_true (r_reg_set_pack (reg, tail, 4, 16, 0xabcd), "partial high chunk");
			RReg *previous = core->dbg->reg;
			core->dbg->reg = reg;
			char *commands = r_debug_reg_list (core->dbg, R_REG_TYPE_FPU, 0, NULL, modes[mode], NULL);
			core->dbg->reg = previous;
			r_reg_arena_zero (reg);
			if (modes[mode] == 'e') {
				r_core_cmdf (core, "ae %s", commands);
			} else {
				r_core_cmd0 (core, commands);
			}
			free (commands);
			mu_assert_eq (r_reg_get_pack (reg, wide, 0, 64), 0x11, "restored low lane");
			mu_assert_eq (r_reg_get_pack (reg, wide, 5, 64), 0x22, "restored high lane");
			mu_assert_eq (r_reg_get_pack (reg, tail, 0, 64), 0x33, "restored partial low chunk");
			mu_assert_eq (r_reg_get_pack (reg, tail, 4, 16), 0xabcd, "restored partial high chunk");
		}
	}
	r_unref (wide);
	r_unref (tail);
	r_core_free (core);
	mu_end;
}

bool test_x86_vector_instructions(void) {
	enum { XOR = 1, MASK = 2, ZERO = 4, LOAD = 8, STORE = 16, BROADCAST = 32, LEGACY = 64, ALIAS1 = 128, ALIAS2 = 256 };
	const struct { const char *hex; int width; int element; int flags; } cases[] = {
		{ "660fefc2", 16, 4, XOR | LEGACY | ALIAS1 },
		{ "0f28c1", 16, 4, LEGACY },
		{ "660f10c1", 16, 8, LEGACY },
		{ "c5f1efc2", 16, 4, XOR },
		{ "c5f5efc2", 32, 4, XOR },
		{ "c5fdefc2", 32, 4, XOR | ALIAS1 },
		{ "c5f5efc0", 32, 4, XOR | ALIAS2 },
		{ "62f17548efc2", 64, 4, XOR },
		{ "62f17549efc2", 64, 4, XOR | MASK },
		{ "62f175c9efc2", 64, 4, XOR | MASK | ZERO },
		{ "62f175c9efc0", 64, 4, XOR | MASK | ZERO | ALIAS2 },
		{ "62f1f5c9efc2", 64, 8, XOR | MASK | ZERO },
		{ "62f174c957c2", 64, 4, XOR | MASK | ZERO },
		{ "62f1f52957c2", 32, 8, XOR | MASK },
		{ "c5fe6f00", 32, 4, LOAD },
		{ "c5fe7f08", 32, 4, STORE },
		{ "62f17fc96fc1", 64, 1, MASK | ZERO },
		{ "62f1ff496fc1", 64, 2, MASK },
		{ "62f17ec96f00", 64, 4, MASK | ZERO | LOAD },
		{ "62f1fe496f00", 64, 8, MASK | LOAD },
		{ "62f17f497f08", 64, 1, MASK | STORE },
		{ "62f1ff497f08", 64, 2, MASK | STORE },
		{ "62f17e497f08", 64, 4, MASK | STORE },
		{ "62f1fe497f08", 64, 8, MASK | STORE },
		{ "62f17cc910c1", 64, 4, MASK | ZERO },
		{ "62f1fd2910c1", 32, 8, MASK },
		{ "62f17518ef00", 16, 4, XOR | LOAD | BROADCAST },
		{ "62f175d9ef00", 64, 4, XOR | MASK | ZERO | LOAD | BROADCAST },
		{ "62f1f559ef00", 64, 8, XOR | MASK | LOAD | BROADCAST },
		{ "62f17d486fc1", 64, 4, 0 },
		{ "62f1fda96fc1", 32, 8, MASK | ZERO },
		{ "62f17c4828c1", 64, 4, 0 },
		{ "62f1fd8928c1", 16, 8, MASK | ZERO },
	};
	int bits;
	for (bits = 32; bits <= 64; bits += 32) {
		RCore *core = r_core_new ();
		r_config_set (core->config, "asm.arch", "x86");
		r_config_set_i (core->config, "asm.bits", bits);
		RIODesc *file = r_core_file_open (core, "malloc://256", R_PERM_RWX, 0);
		mu_assert_notnull (file, "vector memory");
		mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0, 256), "vector memory map");
		r_core_esil_load_arch (core);
		RReg *reg = core->anal->reg;
		RRegItem *dst = r_reg_get (reg, "zmm0", R_REG_TYPE_ALL);
		RRegItem *src1 = r_reg_get (reg, "zmm1", R_REG_TYPE_ALL);
		RRegItem *src2 = r_reg_get (reg, "zmm2", R_REG_TYPE_ALL);
		const ut64 masks[] = { 0, UT64_MAX, 0x80000000a55a5aa5ULL };
		size_t c, m;
		int i;
		int syntax;
		for (syntax = 0; syntax < 2; syntax++) {
			r_config_set (core->config, "asm.syntax", syntax? "att": "intel");
			for (c = 0; c < R_ARRAY_SIZE (cases); c++) {
				ut8 code[16];
				const int len = r_hex_str2bin (cases[c].hex, code);
				const int flags = cases[c].flags;
				RAnalOp op;
				mu_assert_eq (r_anal_op (core->anal, &op, 0, code, len, R_ARCH_OP_MASK_ESIL), len, cases[c].hex);
				mu_assert_true (r_strbuf_length (&op.esil) > 0, cases[c].hex);
				for (m = 0; m < R_ARRAY_SIZE (masks); m++) {
					ut8 original[64], first[64], second[64], expected[64], actual[64];
					memset (original, 0xa5, sizeof (original));
					memcpy (expected, original, sizeof (expected));
					for (i = 0; i < 64; i++) {
						first[i] = flags & ALIAS1? original[i]: i * 3 + 1;
						second[i] = flags & ALIAS2? original[i]: i * 5 + 7;
						if (i < cases[c].width) {
							if (!(flags & MASK) || (masks[m] & (1ULL << (i / cases[c].element)))) {
								const int source = flags & BROADCAST? i % cases[c].element: i;
								expected[i] = flags & XOR? first[i] ^ second[source]: first[i];
							} else if (flags & ZERO) {
								expected[i] = 0;
							}
						} else if (!(flags & (LEGACY | STORE))) {
							expected[i] = 0;
						}
					}
					mu_assert_true (r_reg_set_value_bytes (reg, dst, original, 64), "seed destination");
					mu_assert_true (r_reg_set_value_bytes (reg, src1, first, 64), "seed first source");
					mu_assert_true (r_reg_set_value_bytes (reg, src2, second, 64), "seed second source");
					mu_assert_true (r_io_write_at (core->io, 128, flags & STORE? original: flags & XOR? second: first, 64), "seed vector memory");
					r_reg_setv (reg, bits == 64? "rax": "eax", 128);
					r_reg_setv (reg, "k1", masks[m]);
					r_reg_setv (reg, "eflags", 0xad7);
					mu_assert_true (r_core_esil_run_expr_at (core, r_strbuf_get (&op.esil), 0), cases[c].hex);
					if (flags & STORE) {
						mu_assert_true (r_io_read_at (core->io, 128, actual, 64), "read stored vector");
					} else {
						mu_assert_true (r_reg_get_value_bytes (reg, dst, actual, 64), "read vector result");
					}
					mu_assert_memeq (actual, expected, 64, cases[c].hex);
					mu_assert_eq (r_reg_getv (reg, "eflags"), 0xad7, "vector operations preserve flags");
				}
				r_anal_op_fini (&op);
			}
		}
		r_unref (dst);
		r_unref (src1);
		r_unref (src2);
		r_core_free (core);
	}
	mu_end;
}

bool test_x86_vector_masked_memory(void) {
	const char *instructions[] = { "62f17ec96f00", "62f17e497f08", "62f175c9ef00", "62f175d9ef00" };
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	RIODesc *file = r_core_file_open (core, "malloc://64", R_PERM_RWX, 0);
	mu_assert_notnull (file, "masked memory");
	mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0, 64), "masked memory map");
	r_core_esil_load_arch (core);
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (instructions); i++) {
		ut8 code[16];
		int len = r_hex_str2bin (instructions[i], code);
		RAnalOp op;
		mu_assert_eq (r_anal_op (core->anal, &op, 0, code, len, R_ARCH_OP_MASK_ESIL), len, "decode masked memory instruction");
		r_reg_setv (core->anal->reg, "rax", 64);
		r_reg_setv (core->anal->reg, "k1", 0);
		mu_assert_true (r_core_esil_run_expr_at (core, r_strbuf_get (&op.esil), 0), "inactive lanes do not touch unmapped memory");
		r_reg_setv (core->anal->reg, "k1", 1);
		r_reg_setv (core->anal->reg, "rax", 60);
		mu_assert_true (r_core_esil_run_expr_at (core, r_strbuf_get (&op.esil), 0), "only the active element needs to be mapped");
		r_reg_setv (core->anal->reg, "rax", 64);
		mu_assert_false (r_core_esil_run_expr_at (core, r_strbuf_get (&op.esil), 0), "active unmapped element still faults");
		r_anal_op_fini (&op);
	}
	r_core_free (core);
	mu_end;
}

bool test_x86_vector_address_size(void) {
	RCore *core = r_core_new ();
	r_config_set (core->config, "asm.arch", "x86");
	r_config_set_i (core->config, "asm.bits", 64);
	RIODesc *file = r_core_file_open (core, "malloc://64", R_PERM_RWX, 0);
	mu_assert_notnull (file, "address-size memory");
	mu_assert_notnull (r_io_map_add (core->io, file->fd, R_PERM_RWX, 0, 0xfffffffc, 64), "vector crossing 4 GiB");
	ut8 expected[32], actual[32];
	int i;
	for (i = 0; i < 32; i++) {
		expected[i] = i + 1;
	}
	mu_assert_true (r_io_write_at (core->io, 0xfffffffc, expected, 32), "seed crossing vector");
	r_core_esil_load_arch (core);
	const ut8 code[] = { 0x67, 0xc5, 0xfe, 0x6f, 0x40, 0x08 };
	RAnalOp op;
	mu_assert_eq (r_anal_op (core->anal, &op, 0, code, sizeof (code), R_ARCH_OP_MASK_ESIL), sizeof (code), "decode address-size override");
	r_reg_setv (core->anal->reg, "rax", 0x1fffffff4ULL);
	mu_assert_true (r_core_esil_run_expr_at (core, r_strbuf_get (&op.esil), 0), "truncate effective address before adding lane offsets");
	RRegItem *ymm0 = r_reg_get (core->anal->reg, "ymm0", R_REG_TYPE_ALL);
	mu_assert_true (r_reg_get_value_bytes (core->anal->reg, ymm0, actual, 32), "read crossing vector");
	mu_assert_memeq (actual, expected, 32, "vector bytes stay contiguous across 4 GiB");
	r_unref (ymm0);
	r_anal_op_fini (&op);
	r_core_free (core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_core_fault_state);
	mu_run_test (test_vector_debug_sync);
	mu_run_test (test_wide_register_restore);
	mu_run_test (test_x86_vector_instructions);
	mu_run_test (test_x86_vector_masked_memory);
	mu_run_test (test_x86_vector_address_size);
	return tests_passed != tests_run;
}
