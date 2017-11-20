#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

#include "evm.h"


static unsigned opcodes_types[] = {
    [EVM_OP_STOP] = R_ANAL_OP_TYPE_TRAP,
    [EVM_OP_ADD] = R_ANAL_OP_TYPE_ADD,
    [EVM_OP_MUL] = R_ANAL_OP_TYPE_MUL,
    [EVM_OP_SUB] = R_ANAL_OP_TYPE_SUB,
    [EVM_OP_DIV] = R_ANAL_OP_TYPE_DIV,
    [EVM_OP_SDIV] = R_ANAL_OP_TYPE_DIV,
    [EVM_OP_MOD] = R_ANAL_OP_TYPE_MOD,
    [EVM_OP_SMOD] = R_ANAL_OP_TYPE_MOD,
    [EVM_OP_ADDMOD] = R_ANAL_OP_TYPE_ADD,
    [EVM_OP_MULMOD] = R_ANAL_OP_TYPE_MUL,
    [EVM_OP_EXP] = R_ANAL_OP_TYPE_MUL,
    [EVM_OP_SIGNEXTEND] = R_ANAL_OP_TYPE_CAST,
    [EVM_OP_LT] = R_ANAL_OP_TYPE_COND,
    [EVM_OP_GT] = R_ANAL_OP_TYPE_COND,
    [EVM_OP_SLT] = R_ANAL_OP_TYPE_COND,
    [EVM_OP_SGT] = R_ANAL_OP_TYPE_COND,

    [EVM_OP_EQ] = R_ANAL_OP_TYPE_CMP,
    [EVM_OP_ISZERO] = R_ANAL_OP_TYPE_CMP,
    [EVM_OP_AND] = R_ANAL_OP_TYPE_AND,
    [EVM_OP_OR] = R_ANAL_OP_TYPE_OR,
    [EVM_OP_XOR] = R_ANAL_OP_TYPE_XOR,
    [EVM_OP_NOT] = R_ANAL_OP_TYPE_NOT,
    [EVM_OP_BYTE] = R_ANAL_OP_TYPE_MOV,
    [EVM_OP_SHA3] = R_ANAL_OP_TYPE_CRYPTO,

    [EVM_OP_ADDRESS] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_BALANCE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_ORIGIN] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CALLER] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CALLVALUE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATALOAD] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATASIZE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CALLDATACOPY] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CODESIZE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_CODECOPY] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_GASPRICE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_EXTCODESIZE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_EXTCODECOPY] = R_ANAL_OP_TYPE_CRYPTO,

    [EVM_OP_BLOCKHASH] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_COINBASE] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_TIMESTAMP] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_NUMBER] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_DIFFICULTY] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_GASLIMIT] = R_ANAL_OP_TYPE_CRYPTO,

    [EVM_OP_POP] = R_ANAL_OP_TYPE_POP,
    [EVM_OP_MLOAD] = R_ANAL_OP_TYPE_LOAD,
    [EVM_OP_MSTORE] = R_ANAL_OP_TYPE_STORE,
    [EVM_OP_MSTORE8] = R_ANAL_OP_TYPE_STORE,
    [EVM_OP_SLOAD] = R_ANAL_OP_TYPE_LOAD,
    [EVM_OP_SSTORE] = R_ANAL_OP_TYPE_STORE,
    [EVM_OP_JUMP] = R_ANAL_OP_TYPE_JMP,
    [EVM_OP_JUMPI] = R_ANAL_OP_TYPE_JMP,
    [EVM_OP_PC] = R_ANAL_OP_TYPE_MOV,
    [EVM_OP_MSIZE] = R_ANAL_OP_TYPE_MOV,
    [EVM_OP_GAS] = R_ANAL_OP_TYPE_MOV,
    [EVM_OP_JUMPDEST] = R_ANAL_OP_TYPE_NOP,

	[EVM_OP_PUSH1] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH2] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH3] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH4] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH5] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH6] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH7] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH8] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH9] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH10] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH11] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH12] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH13] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH14] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH15] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH16] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH17] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH18] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH19] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH20] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH21] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH22] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH23] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH24] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH25] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH26] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH27] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH28] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH29] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH30] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH31] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_PUSH32] = R_ANAL_OP_TYPE_PUSH,
	[EVM_OP_DUP1] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP2] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP3] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP4] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP5] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP6]  = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP7] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP8] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP9] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP10] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP11] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP12] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP13] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP14] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP15] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_DUP16] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP1] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP2] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP3] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP4] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP5] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP6] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP7] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP8] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP9] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP10] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP11] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP12] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP13] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP14] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP15] = R_ANAL_OP_TYPE_MOV,
	[EVM_OP_SWAP16] = R_ANAL_OP_TYPE_MOV,

	[EVM_OP_LOG0] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG1] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG2] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG3] = R_ANAL_OP_TYPE_TRAP,
	[EVM_OP_LOG4] = R_ANAL_OP_TYPE_TRAP,

	[EVM_OP_CREATE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALL] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_CALLCODE] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_RETURN] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_DELEGATECALL] = R_ANAL_OP_TYPE_CRYPTO,
    [EVM_OP_REVERT] = R_ANAL_OP_TYPE_CRYPTO,
	[EVM_OP_SELFDESTRUCT] = R_ANAL_OP_TYPE_CRYPTO, 
};

static int evm_oplen(ut8 opcode) {
    int ret;
	EvmOpDef *opdef = &opcodes[opcode];

	if (opdef->txt) {
		return opdef->len;
	}
	switch (opcode) {
	case EVM_OP_PUSH1:
	case EVM_OP_PUSH2:
	case EVM_OP_PUSH3:
	case EVM_OP_PUSH4:
	case EVM_OP_PUSH5:
	case EVM_OP_PUSH6:
	case EVM_OP_PUSH7:
	case EVM_OP_PUSH8:
	case EVM_OP_PUSH9:
	case EVM_OP_PUSH10:
	case EVM_OP_PUSH11:
	case EVM_OP_PUSH12:
	case EVM_OP_PUSH13:
	case EVM_OP_PUSH14:
	case EVM_OP_PUSH15:
	case EVM_OP_PUSH16:
	case EVM_OP_PUSH17:
	case EVM_OP_PUSH18:
	case EVM_OP_PUSH19:
	case EVM_OP_PUSH20:
	case EVM_OP_PUSH21:
	case EVM_OP_PUSH22:
	case EVM_OP_PUSH23:
	case EVM_OP_PUSH24:
	case EVM_OP_PUSH25:
	case EVM_OP_PUSH26:
	case EVM_OP_PUSH27:
	case EVM_OP_PUSH28:
	case EVM_OP_PUSH29:
	case EVM_OP_PUSH30:
	case EVM_OP_PUSH31:
	case EVM_OP_PUSH32:
		{
			int i, pushSize = opcode - EVM_OP_PUSH1;
            /*
			op->imm = 0;
			for (i = 0; i < pushSize + 1; i++) {
				op->imm <<= 8;
				op->imm |= buf[i + 1];
			}
			settxtf (op, "push%d 0x%x", pushSize + 1, op->imm);
            */
			ret = 2 + pushSize;
		}
		break;
	case EVM_OP_DUP1:
	case EVM_OP_DUP2:
	case EVM_OP_DUP3:
	case EVM_OP_DUP4:
	case EVM_OP_DUP5:
	case EVM_OP_DUP6:
	case EVM_OP_DUP7:
	case EVM_OP_DUP8:
	case EVM_OP_DUP9:
	case EVM_OP_DUP10:
	case EVM_OP_DUP11:
	case EVM_OP_DUP12:
	case EVM_OP_DUP13:
	case EVM_OP_DUP14:
	case EVM_OP_DUP15:
	case EVM_OP_DUP16:
		{
			int dupSize = opcode - EVM_OP_DUP1 + 1;
			//settxtf (op, "dup%d", dupSize);
			ret = dupSize + 1;
		}
		break;
	case EVM_OP_SWAP1:
	case EVM_OP_SWAP2:
	case EVM_OP_SWAP3:
	case EVM_OP_SWAP4:
	case EVM_OP_SWAP5:
	case EVM_OP_SWAP6:
	case EVM_OP_SWAP7:
	case EVM_OP_SWAP8:
	case EVM_OP_SWAP9:
	case EVM_OP_SWAP10:
	case EVM_OP_SWAP11:
	case EVM_OP_SWAP12:
	case EVM_OP_SWAP13:
	case EVM_OP_SWAP14:
	case EVM_OP_SWAP15:
	case EVM_OP_SWAP16:
		{
			int swapSize = opcode - EVM_OP_SWAP1 + 1;
			//settxtf (op, "swap%d", swapSize);
			ret = 1;
		}
		break;
	case EVM_OP_LOG0:
	case EVM_OP_LOG1:
	case EVM_OP_LOG2:
	case EVM_OP_LOG3:
	case EVM_OP_LOG4:
		{
			int logSize = opcode - EVM_OP_LOG0;
			//settxtf (op, "log%d", logSize);
			ret = 1;
		}
		break;
	default:
		//settxtf (op, "invalid");
		ret = 1;
		break;
	}

	return ret;
}

static int evm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
    static ut16 a = 0;
    int ret;
    ut8 opcode;

    opcode = buf[0];
    anal->addrmy  = op->addr;

    memset(op, 0, sizeof(RAnalOp));

    op->type = opcodes_types[opcode];
	if (!op->type) {
		op->type = R_ANAL_OP_TYPE_UNK;
	}
    op->addr = addr;
    op->jump = op->fail = -1;
    op->ptr = op->val = -1;

    r_strbuf_init (&op->esil);

    switch(opcode) {
    case EVM_OP_JUMP:
        op->fail = addr+1;
        op->jump = buf[-1];
        op->type = R_ANAL_OP_TYPE_JMP;
        break;
    case EVM_OP_JUMPI:
        op->fail = addr+1;
        op->jump = buf[-1];
        op->type = R_ANAL_OP_TYPE_JMP;
        break;
    case EVM_OP_PC:
        break;
    case EVM_OP_MSIZE:
        break;
    case EVM_OP_GAS:
        break;
    case EVM_OP_JUMPDEST:
        break;
    case EVM_OP_PUSH1:
        a = buf[1];
        break;
    case EVM_OP_PUSH2:
        a = buf[1] << 8 | buf[2];
        break;
    default:
        break;
    }

	op->size = evm_oplen(opcode);
    return evm_oplen(opcode);
}


RAnalPlugin r_anal_plugin_evm = {
    .name = "evm",
    .desc = "ETHEREUM VM code analysis plugin",
    .license = "LGPL3",
    .arch = "evm",
    .bits = 8,
    .op = evm_op,
    .esil = false,
};
