/* radare2 - BSD - Copyright 2017-2024 - pancake */

#include <r_arch.h>
#include <r_lib.h>

// XXX should be dynlink
#include "lua53.c"

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	PluginData *pd = as->data;

	pd->current_write_index = 0;
	if (parseNextInstruction (pd, op->mnemonic) < 0) {
		return false;
	}
	// one word, or two for LOADKX with its EXTRAARG
	const int size = pd->current_write_index * 4;
	ut8 *bytes = malloc (size);
	if (!bytes) {
		return false;
	}
	ut32 i;
	for (i = 0; i < pd->current_write_index; i++) {
		setInstruction (pd->instructions[i], bytes + i * 4);
	}
	free (op->bytes);
	op->bytes = bytes;
	op->size = size;
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

	const ut32 instruction = getInstruction (data);
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->eob = false;
	if (GET_OPCODE (instruction) > OP_EXTRAARG) {
		return op->size;
	}
	if ((GET_OPCODE (instruction) == OP_LOADKX || (GET_OPCODE (instruction) == OP_SETLIST && !GETARG_C (instruction)))
			&& len >= 8 && GET_OPCODE (getInstruction (data + 4)) == OP_EXTRAARG) {
		op->size = 8;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = lua53disasm (instruction, op->size == 8? getInstruction (data + 4): 0, op->size == 8);
	}
	static const ut32 types[OP_EXTRAARG + 1] = {
		[OP_MOVE] = R_ANAL_OP_TYPE_MOV,
		[OP_LOADK] = R_ANAL_OP_TYPE_LOAD,
		[OP_LOADKX] = R_ANAL_OP_TYPE_LOAD,
		[OP_LOADBOOL] = R_ANAL_OP_TYPE_MOV,
		[OP_LOADNIL] = R_ANAL_OP_TYPE_MOV,
		[OP_GETUPVAL] = R_ANAL_OP_TYPE_LOAD,
		[OP_GETTABUP] = R_ANAL_OP_TYPE_LOAD,
		[OP_GETTABLE] = R_ANAL_OP_TYPE_LOAD,
		[OP_SETTABUP] = R_ANAL_OP_TYPE_STORE,
		[OP_SETUPVAL] = R_ANAL_OP_TYPE_STORE,
		[OP_SETTABLE] = R_ANAL_OP_TYPE_STORE,
		[OP_NEWTABLE] = R_ANAL_OP_TYPE_NEW,
		[OP_ADD] = R_ANAL_OP_TYPE_ADD,
		[OP_SUB] = R_ANAL_OP_TYPE_SUB,
		[OP_MUL] = R_ANAL_OP_TYPE_MUL,
		[OP_MOD] = R_ANAL_OP_TYPE_MOD,
		[OP_DIV] = R_ANAL_OP_TYPE_DIV,
		[OP_IDIV] = R_ANAL_OP_TYPE_DIV,
		[OP_BAND] = R_ANAL_OP_TYPE_AND,
		[OP_BOR] = R_ANAL_OP_TYPE_OR,
		[OP_BXOR] = R_ANAL_OP_TYPE_XOR,
		[OP_SHL] = R_ANAL_OP_TYPE_SHL,
		[OP_SHR] = R_ANAL_OP_TYPE_SHR,
		[OP_BNOT] = R_ANAL_OP_TYPE_CPL,
		[OP_NOT] = R_ANAL_OP_TYPE_NOT,
		[OP_CALL] = R_ANAL_OP_TYPE_RCALL,
		[OP_TFORCALL] = R_ANAL_OP_TYPE_RCALL,
		[OP_SETLIST] = R_ANAL_OP_TYPE_STORE,
	};
	const OpCode opcode = GET_OPCODE (instruction);
	op->type = types[opcode]? types[opcode]: R_ANAL_OP_TYPE_UNK;
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

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "LUA Bytecode (5.3)",
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
	.init = init,
	.fini = fini,
	.cpus = "5.3", // ,5.4"
	.endian = R_SYS_ENDIAN_LITTLE,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_lua,
	.version = R2_VERSION
};
#endif
