/* radare2 - LGPL - Copyright 2022 - pancake */

#include <r_asm.h>
#include <r_lib.h>

#include <capstone.h>
#if CS_API_MAJOR >= 5
#include <evm.h>

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

static int analop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int n, ret, opsize = -1;
	static csh hndl = 0;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn;
	int mode = 0;
	if (mode != omode || anal->bits != obits) {
		cs_close (&hndl);
		hndl = 0;
		omode = mode;
		obits = anal->bits;
	}
	op->addr = addr;
	if (len < 1) {
		return -1;
	}
	op->size = 4;
	if (hndl == 0) {
		ret = cs_open (CS_ARCH_EVM, mode, &hndl);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option (hndl, CS_OPT_DETAIL, CS_OPT_ON);
	}
	op->type = R_ANAL_OP_TYPE_UNK;
	n = cs_disasm (hndl, (ut8*)buf, len, addr, 1, &insn);
	opsize = 1;
	if (n < 1 || insn->size < 1) {
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		goto beach;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		char *str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " ": "", insn->op_str);
		op->mnemonic = str;
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case EVM_INS_SLOAD:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case EVM_INS_MSTORE8:
	case EVM_INS_SSTORE:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
	case EVM_INS_ISZERO:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case EVM_INS_COINBASE:
	case EVM_INS_BLOCKHASH:
		break;
	case EVM_INS_CODECOPY:
	case EVM_INS_SWAP1:
	case EVM_INS_SWAP2:
	case EVM_INS_SWAP12:
	case EVM_INS_REVERT:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case EVM_INS_GAS:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case EVM_INS_MULMOD:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case EVM_INS_STOP:
	case EVM_INS_SUICIDE:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case EVM_INS_DELEGATECALL:
	case EVM_INS_CALLDATACOPY:
	case EVM_INS_CALLDATALOAD:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case EVM_INS_SDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
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
	case EVM_INS_PUSH1:
	case EVM_INS_PUSH2:
	case EVM_INS_PUSH3:
	case EVM_INS_PUSH4:
	case EVM_INS_PUSH5:
	case EVM_INS_PUSH6:
	case EVM_INS_PUSH9:
	case EVM_INS_PUSH10:
	case EVM_INS_PUSH26:
	case EVM_INS_PUSH32:
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case EVM_INS_ADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case EVM_INS_POP:
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	}
beach:
	set_opdir (op);
#if 0
	if (insn && mask & R_ANAL_OP_MASK_OPEX) {
		opex (&op->opex, hndl, insn);
	}
	if (mask & R_ANAL_OP_MASK_ESIL) {
		if (analop_esil (anal, op, addr, buf, len, &hndl, insn) != 0) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ANAL_OP_MASK_VAL) {
		op_fillval (anal, op, &hndl, insn);
	}
#endif
	cs_free (insn, n);
	//cs_close (&handle);
fin:
	return opsize;
}

static char *get_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	bp\n"
		"=A0	r0\n"

		"gpr	pc	.32	0	0\n"
		"gpr	sp	.32	4	0\n"
		"gpr	bp	.32	8	0\n"
		"gpr	r0	.32	12	0\n"
		;
	return (p && *p)? strdup (p): NULL;
}

static int archinfo(RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 4;
	default:
		return 1;
	}
	return 1;
}

RAnalPlugin r_anal_plugin_evm_cs = {
	.name = "evm.cs",
	.desc = "Capstone ETHEREUM VM arch plugin",
	.license = "BSD",
	.esil = true,
	.arch = "evm",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.bits = 32,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_evm_cs,
	.version = R2_VERSION
};
#endif

#else
RAnalPlugin r_anal_plugin_evm_cs = {0};
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif
