/* radare2 - LGPL - Copyright 2022-2023 - pancake, Sylvain Pelissier */

#define R_LOG_ORIGIN "arch.evm"

#include <r_asm.h>
#include <r_lib.h>

#include "./evm.c"

#include <capstone/capstone.h>
#if CS_API_MAJOR >= 5
#include <capstone/evm.h>

// TODO :Rename CSINC to something meaningful
#define CSINC EVM
#include "../capstone.inc.c"

typedef struct {
	Sdb *pushs_db;
	csh cs_handle;
} EvmPluginData;

static void set_opdir(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		op->direction = R_ANAL_OP_DIR_READ;
		break;
	case R_ANAL_OP_TYPE_STORE:
		op->direction = R_ANAL_OP_DIR_WRITE;
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

/* Jumps/calls in EVM are done via first pushing dst value
 * on the stack, and then calling a jump/jumpi instruction, for example:
 *   0x0000000d push 0x42
 *   0x0000000f jumpi
 *
 * we are storing the value in push instruction to db, but not at the
 * addr of the push instruction, but at the addr of next jumpi instruction.
 * So in our example we are inserting (0xf, 0x42)
 */
static int evm_add_push_to_db(RArchSession *s, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	EvmPluginData *epd = (EvmPluginData*)s->data;
	ut64 dst_addr = 0;
	size_t i;

	size_t push_size = op->id - EVM_INS_PUSH1;
	ut64 next_cmd_addr = addr + push_size + 2;

	for (i = 0; i < push_size + 1; i++) {
		dst_addr <<= 8;
		dst_addr |= buf[i + 1];
	}

	sdb_num_nset (epd->pushs_db, next_cmd_addr, dst_addr, 0);

	return 0;
}

static ut64 evm_get_jmp_addr(RArchSession *s, ut64 addr) {
	EvmPluginData *epd = (EvmPluginData*)s->data;
	return sdb_num_nget (epd->pushs_db, addr, 0);
}

static bool encode(RArchSession *s, RAnalOp *op, RAnalOpMask mask) {
	ut8 buf[64];
	int asmlen = evm_asm (op->mnemonic, buf, sizeof (buf));
	if (asmlen > 0) {
		op->size = asmlen;
		r_anal_op_set_bytes (op, op->addr, buf, asmlen);
		return true;
	}
	return false;
}

static bool decode(RArchSession *s, RAnalOp *op, RAnalOpMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op && s->data, false);
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	EvmPluginData *epd = (EvmPluginData*)s->data;

	int opsize = -1;
	cs_insn *insn;
	char *str;

	op->addr = addr;
	if (len < 1) {
		return false;
	}
	op->size = 1;
	op->type = R_ANAL_OP_TYPE_UNK;
	int n = cs_disasm (epd->cs_handle, (ut8 *)buf, len, addr, 1, &insn);
	opsize = 1;
	if (n < 1 || insn->size < 1) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		goto beach;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (r_str_startswith (insn->op_str, "0x")) {
			str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " ": "", insn->op_str);
		} else {
			str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " 0x": "", insn->op_str);
		}
		op->mnemonic = str;
	}
	opsize = op->size = insn->size;
	op->id = insn->id;
	switch (insn->id) {
	case EVM_INS_SUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case EVM_INS_MOD:
	case EVM_INS_SMOD:
		op->type = R_ANAL_OP_TYPE_MOD;
		break;
	case EVM_INS_JUMP:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->fail = op->addr + 1;
		op->jump = evm_get_jmp_addr (s, addr);
		esilprintf (op, "32,sp,-=,sp,[1],pc,:=");
		break;
	case EVM_INS_JUMPDEST:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case EVM_INS_JUMPI:
		op->fail = op->addr + 1;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = evm_get_jmp_addr (s, addr);
		break;
	case EVM_INS_MLOAD:
	case EVM_INS_SLOAD:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case EVM_INS_MSTORE:
	case EVM_INS_MSTORE8:
	case EVM_INS_SSTORE:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case EVM_INS_LT:
	case EVM_INS_GT:
	case EVM_INS_SLT:
	case EVM_INS_SGT:
	case EVM_INS_EQ:
	case EVM_INS_ISZERO:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case EVM_INS_COINBASE:
	case EVM_INS_BLOCKHASH:
		break;
	case EVM_INS_SHA3:
		op->type = R_ANAL_OP_TYPE_CRYPTO;
		break;
	case EVM_INS_CODECOPY:
	case EVM_INS_SWAP1:
	case EVM_INS_SWAP2:
	case EVM_INS_SWAP3:
	case EVM_INS_SWAP4:
	case EVM_INS_SWAP5:
	case EVM_INS_SWAP6:
	case EVM_INS_SWAP7:
	case EVM_INS_SWAP8:
	case EVM_INS_SWAP9:
	case EVM_INS_SWAP10:
	case EVM_INS_SWAP11:
	case EVM_INS_SWAP12:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case EVM_INS_GAS:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case EVM_INS_MUL:
	case EVM_INS_EXP:
	case EVM_INS_MULMOD:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case EVM_INS_STOP:
#if CS_API_MAJOR >= 6	
	case EVM_INS_SELFDESTRUCT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
#else
	case EVM_INS_SUICIDE:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
#endif
	case EVM_INS_DELEGATECALL:
	case EVM_INS_CALLDATACOPY:
	case EVM_INS_CALLDATALOAD:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case EVM_INS_DIV:
	case EVM_INS_SDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case EVM_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case EVM_INS_OR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case EVM_INS_XOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case EVM_INS_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case EVM_INS_REVERT:
	case EVM_INS_RETURN:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case EVM_INS_DUP1:
	case EVM_INS_DUP2:
	case EVM_INS_DUP3:
	case EVM_INS_DUP4:
	case EVM_INS_DUP5:
	case EVM_INS_DUP6:
	case EVM_INS_DUP7:
	case EVM_INS_DUP8:
	case EVM_INS_DUP9:
	case EVM_INS_DUP10:
	case EVM_INS_DUP11:
	case EVM_INS_DUP12:
	case EVM_INS_DUP13:
	case EVM_INS_DUP14:
	case EVM_INS_DUP15:
	case EVM_INS_DUP16:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
#if CS_API_MAJOR >= 6
	case EVM_INS_PUSH0:
		esilprintf (op, "0x0,sp,=[1],32,sp,+=");
		op->type = R_ANAL_OP_TYPE_PUSH;
		evm_add_push_to_db (s, op, addr, buf, len);
		break;
#endif
	case EVM_INS_PUSH1:
		esilprintf (op, "0x%s,sp,=[1],32,sp,+=", insn->op_str);
		op->type = R_ANAL_OP_TYPE_PUSH;
		evm_add_push_to_db (s, op, addr, buf, len);
		break;
	case EVM_INS_PUSH2:
	case EVM_INS_PUSH3:
	case EVM_INS_PUSH4:
	case EVM_INS_PUSH5:
	case EVM_INS_PUSH6:
	case EVM_INS_PUSH9:
	case EVM_INS_PUSH10:
	case EVM_INS_PUSH11:
	case EVM_INS_PUSH12:
	case EVM_INS_PUSH13:
	case EVM_INS_PUSH14:
	case EVM_INS_PUSH15:
	case EVM_INS_PUSH16:
	case EVM_INS_PUSH17:
	case EVM_INS_PUSH18:
	case EVM_INS_PUSH19:
	case EVM_INS_PUSH20:
	case EVM_INS_PUSH21:
	case EVM_INS_PUSH22:
	case EVM_INS_PUSH23:
		op->type = R_ANAL_OP_TYPE_PUSH;
		evm_add_push_to_db (s, op, addr, buf, len);
		break;
	// Handle https://github.com/capstone-engine/capstone/pull/1231. Can be removed when merged.
	case EVM_INS_PUSH24:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 25;
		break;
	case EVM_INS_PUSH25:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 26;
		break;
	case EVM_INS_PUSH26:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 27;
		break;
	case EVM_INS_PUSH27:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 28;
		break;
	case EVM_INS_PUSH28:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 29;
		break;
	case EVM_INS_PUSH29:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 30;
		break;
	case EVM_INS_PUSH30:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 31;
		break;
	case EVM_INS_PUSH31:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 32;
		break;
	case EVM_INS_PUSH32:
		op->type = R_ANAL_OP_TYPE_PUSH;
		opsize = op->size = 33;
		break;
	case EVM_INS_ADD:
	case EVM_INS_ADDMOD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case EVM_INS_POP:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case EVM_INS_CODESIZE:
		op->type = R_ANAL_OP_TYPE_LENGTH;
		break;
	case EVM_INS_LOG0:
	case EVM_INS_LOG1:
	case EVM_INS_LOG2:
	case EVM_INS_LOG3:
	case EVM_INS_LOG4:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	}
beach:
	set_opdir (op);
#if 0
	if (insn && mask & R_ARCH_OP_MASK_OPEX) {
		opex (&op->opex, hndl, insn);
	}
	if (mask & R_ARCH_OP_MASK_ESIL) {
		if (archop_esil (arch, op, addr, buf, len, &hndl, insn) != 0) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		op_fillval (arch, op, &hndl, insn);
	}
#endif
	cs_free (insn, n);
	op->size = opsize;
	return true;
}

static char *regs(RArchSession *as) {
	return strdup (
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=A0	r0\n"
		"=SN	r0\n"

		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	bp	.32	8	0\n"
		"gpr	r0	.32	12	0\n"
	);
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	s->data = R_NEW0 (EvmPluginData);
	EvmPluginData *epd = (EvmPluginData*)s->data;
	if (!r_arch_cs_init (s, &epd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (s->data);
		return false;
	}
	epd->pushs_db = sdb_new0 ();
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	EvmPluginData *epd = (EvmPluginData*)s->data;
	sdb_free (epd->pushs_db);
	cs_close (&epd->cs_handle);
	R_FREE (s->data);
	return true;
}

static int archinfo(RArchSession *a, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 33;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 0;
}

static char *mnemonics(RArchSession *s, int id, bool json) {
	EvmPluginData *epd = (EvmPluginData*)s->data;
	return r_arch_cs_mnemonics (s, epd->cs_handle, id, json);
}

const RArchPlugin r_arch_plugin_evm = {
	.meta = {
		.name = "evm",
		.author = "pancake,Sylvain Pelissier",
		.desc = "EthereumVM bytecode (EVM)",
		.license = "BSD-3-Clause",
	},
	.arch = "evm",
	.regs = regs,
	.info = archinfo,
	.bits = 32,
	.decode = &decode,
	.encode = &encode,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_evm,
	.version = R2_VERSION
};
#endif

#else
const RArchPlugin r_arch_plugin_evm = { 0 };
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.version = R2_VERSION
};
#endif
#endif
