/* radare2 - BSD - Copyright 2017-2024 - pancake */

#include <r_arch.h>
#include <r_lib.h>

#include "lua53.h"
#include "lua_bc.h"

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut32 words[2];
	int size;
	const LuaBCVersion *v = lua_bc_version (as->config->cpu);
	if (!v || !lua_bc_assemble (v, op->mnemonic, words, &size)) {
		return false;
	}
	ut8 bytes[8];
	r_write_le32 (bytes, words[0]);
	if (size == 8) {
		r_write_le32 (bytes + 4, words[1]);
	}
	return r_anal_op_set_bytes (op, op->addr, bytes, size);
}

static bool decode_bc(const LuaBCVersion *v, RAnalOp *op, RArchDecodeMask mask) {
	const int len = op->size;
	const ut32 word = r_read_le32 (op->bytes);
	const int id = lua_bc_id (v, word);
	op->size = 4;
	if (id == LUA_OP_COUNT) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return false;
	}
	const ut32 next = len >= 8? r_read_le32 (op->bytes + 4): 0;
	const bool pair = len >= 8 && lua_bc_pair (v, word, next);
	if (pair) {
		op->size = 8;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char *first = lua_bc_disasm_word (v, word, next, pair);
		if (pair && id != LUA_OP_LOADKX) {
			char *second = lua_bc_disasm_word (v, next, 0, false);
			op->mnemonic = r_str_newf ("%s ; %s", first, second);
			free (first);
			free (second);
		} else {
			op->mnemonic = first;
		}
	}
	op->type = lua_bc_ops[id].type;
	op->eob = false;
	const ut64 pc = op->addr + 4;
	if (id == LUA_OP_JMP) {
		op->jump = pc + (st64)lua_bc_get (v, word, LUA_ARG_SJ) * 4;
	} else if (id == LUA_OP_LFALSESKIP) {
		op->jump = pc + 4;
	} else if (id == LUA_OP_FORPREP || id == LUA_OP_TFORPREP) {
		op->jump = pc + (ut64)(lua_bc_get (v, word, LUA_ARG_BX) + (id == LUA_OP_FORPREP)) * 4;
	} else if (id == LUA_OP_FORLOOP || id == LUA_OP_TFORLOOP) {
		op->jump = pc - (ut64)lua_bc_get (v, word, LUA_ARG_BX) * 4;
	} else if (op->type == R_ANAL_OP_TYPE_CJMP) {
		op->jump = pc + 4;
	}
	if (op->type == R_ANAL_OP_TYPE_CJMP) {
		op->fail = pc;
	}
	if (op->type == R_ANAL_OP_TYPE_RET) {
		op->eob = true;
		if (id == LUA_OP_TAILCALL) {
			op->type2 = R_ANAL_OP_TYPE_RCALL;
		}
	}
	return true;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (!op) {
		return 0;
	}
	const ut8 *data = op->bytes;
	const int len = op->size;
	if (len < 4) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("truncated");
		}
		return false;
	}

	const LuaBCVersion *v = lua_bc_version (as->config->cpu);
	if (v && v != &lua_bc_53) {
		return decode_bc (v, op, mask);
	}
	if (!v) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	const ut32 instruction = r_read_le32 (data);
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->eob = false;
	if (GET_OPCODE (instruction) > OP_EXTRAARG) {
		return op->size;
	}
	if ((GET_OPCODE (instruction) == OP_LOADKX || (GET_OPCODE (instruction) == OP_SETLIST && !GETARG_C (instruction)))
			&& len >= 8 && GET_OPCODE (r_read_le32 (data + 4)) == OP_EXTRAARG) {
		op->size = 8;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = lua_bc_disasm_word (v, instruction, op->size == 8? r_read_le32 (data + 4): 0, op->size == 8);
	}
	const OpCode opcode = GET_OPCODE (instruction);
	op->type = lua_bc_ops[lua_bc_id (v, instruction)].type;
	switch (opcode) {
	case OP_LOADBOOL:
		op->val = !!GETARG_B (instruction);
		if (GETARG_C (instruction)) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = op->addr + 8;
		}
		break;
	case OP_JMP:
	case OP_FORPREP:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * GETARG_sBx (instruction);
		break;
	case OP_EQ:
	case OP_LT:
	case OP_LE:
	case OP_TEST:
	case OP_TESTSET:
	case OP_FORLOOP:
	case OP_TFORLOOP:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = op->addr + (opcode == OP_FORLOOP || opcode == OP_TFORLOOP? 4 + 4 * GETARG_sBx (instruction): 8);
		op->fail = op->addr + 4;
		break;
	case OP_TAILCALL:
		op->type2 = R_ANAL_OP_TYPE_RCALL;
		// fall through
	case OP_RETURN:
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = true;
		break;
	default:
		break;
	}

	return op->size;
}

static int archinfo(RArchSession *cfg, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_ISVM:
		return true;
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_FUNC_ALIGN:
		return 1;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 8;
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_INVOP_SIZE:
		return 4;
	}
	return 0;
}

static char *regs(RArchSession *s) {
	RStrBuf *p = r_strbuf_new (
		"=PC pc\n=SP sp\n=A0 r0\n=A1 r1\n=A2 r2\n=R0 r0\n=R1 r1\n"
		"gpr pc .32 0 0\ngpr sp .32 4 0\n");
	int i;
	for (i = 0; i <= MAXARG_A; i++) {
		r_strbuf_appendf (p, "gpr r%d .64 %d 0\n", i, 8 + i * 8);
	}
	return r_strbuf_drain (p);
}

const RArchPlugin r_arch_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "Lua bytecode (5.3, 5.4, 5.5)",
		.license = "MIT",
		.author = "pancake",
	},
	.arch = "lua",
	.bits = R_SYS_BITS_PACK (32),
	.addr_bits = R_SYS_BITS_PACK (32),
	.info = archinfo,
	.encode = encode,
	.decode = decode,
	.regs = regs,
	.cpus = "5.3,5.4,5.5",
	.endian = R_SYS_ENDIAN_LITTLE,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_lua,
	.version = R2_VERSION
};
#endif
