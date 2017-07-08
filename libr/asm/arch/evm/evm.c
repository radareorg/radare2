#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>


typedef enum {
	EVM_OP_STOP = 0x00,
	EVM_OP_ADD,
	EVM_OP_MUL,
	EVM_OP_SUB,
	EVM_OP_DIV,
	EVM_OP_SDIV,
	EVM_OP_MOD,
	EVM_OP_SMOD,
	EVM_OP_ADDMOD,
	EVM_OP_MULMOD,
	EVM_OP_EXP,
	EVM_OP_SIGNEXTEND,
	EVM_OP_LT,
	EVM_OP_GT,
	EVM_OP_SLT,
	EVM_OP_SGT,

	EVM_OP_EQ = 0x10,
	EVM_OP_ISZERO,
	EVM_OP_AND,
	EVM_OP_OR,
	EVM_OP_XOR,
	EVM_OP_NOT,
	EVM_OP_BYTE,
	EVM_OP_SHA3 = 0x20,

	EVM_OP_ADDRESS = 0x30,
	EVM_OP_BALANCE,
	EVM_OP_ORIGIN,
	EVM_OP_CALLER,
	EVM_OP_CALLVALUE,
	EVM_OP_CALLDATALOAD,
	EVM_OP_CALLDATASIZE,
	EVM_OP_CALLDATACOPY,
	EVM_OP_CODESIZE,
	EVM_OP_CODECOPY,
	EVM_OP_GASPRICE,
	EVM_OP_EXTCODESIZE,
	EVM_OP_EXTCODECOPY,

	EVM_OP_BLOCKHASH = 0x40,
	EVM_OP_COINBASE,
	EVM_OP_TIMESTAMP,
	EVM_OP_NUMBER,
	EVM_OP_DIFFICULTY,
	EVM_OP_GASLIMIT,

	EVM_OP_POP = 0x50,
	EVM_OP_MLOAD,
	EVM_OP_MSTORE,
	EVM_OP_MSTORE8,
	EVM_OP_SLOAD,
	EVM_OP_SSTORE,
	EVM_OP_JUMP,
	EVM_OP_JUMPI,
	EVM_OP_PC,
	EVM_OP_MSIZE,
	EVM_OP_GAS,
	EVM_OP_JUMPDEST,

	EVM_OP_PUSH1 = 0x60,
	EVM_OP_PUSH2,
	EVM_OP_PUSH3,
	EVM_OP_PUSH4,
	EVM_OP_PUSH5,
	EVM_OP_PUSH6,
	EVM_OP_PUSH7,
	EVM_OP_PUSH8,
	EVM_OP_PUSH9,
	EVM_OP_PUSH10,
	EVM_OP_PUSH11,
	EVM_OP_PUSH12,
	EVM_OP_PUSH13,
	EVM_OP_PUSH14,
	EVM_OP_PUSH15,
	EVM_OP_PUSH16,
	EVM_OP_PUSH17,
	EVM_OP_PUSH18,
	EVM_OP_PUSH19,
	EVM_OP_PUSH20,
	EVM_OP_PUSH21,
	EVM_OP_PUSH22,
	EVM_OP_PUSH23,
	EVM_OP_PUSH24,
	EVM_OP_PUSH25,
	EVM_OP_PUSH26,
	EVM_OP_PUSH27,
	EVM_OP_PUSH28,
	EVM_OP_PUSH29,
	EVM_OP_PUSH30,
	EVM_OP_PUSH31,
	EVM_OP_PUSH32,
	EVM_OP_DUP1,
	EVM_OP_DUP2,
	EVM_OP_DUP3,
	EVM_OP_DUP4,
	EVM_OP_DUP5,
	EVM_OP_DUP6,
	EVM_OP_DUP7,
	EVM_OP_DUP8,
	EVM_OP_DUP9,
	EVM_OP_DUP10,
	EVM_OP_DUP11,
	EVM_OP_DUP12,
	EVM_OP_DUP13,
	EVM_OP_DUP14,
	EVM_OP_DUP15,
	EVM_OP_DUP16,
	EVM_OP_SWAP1,
	EVM_OP_SWAP2,
	EVM_OP_SWAP3,
	EVM_OP_SWAP4,
	EVM_OP_SWAP5,
	EVM_OP_SWAP6,
	EVM_OP_SWAP7,
	EVM_OP_SWAP8,
	EVM_OP_SWAP9,
	EVM_OP_SWAP10,
	EVM_OP_SWAP11,
	EVM_OP_SWAP12,
	EVM_OP_SWAP13,
	EVM_OP_SWAP14,
	EVM_OP_SWAP15,
	EVM_OP_SWAP16,

	EVM_OP_LOG0 = 0xa0,
	EVM_OP_LOG1,
	EVM_OP_LOG2,
	EVM_OP_LOG3,
	EVM_OP_LOG4,

	EVM_OP_CREATE = 0xf0,
	EVM_OP_CALL,
	EVM_OP_CALLCODE,
	EVM_OP_RETURN,
	EVM_OP_DELEGATECALL,
	EVM_OP_SELFDESTRUCT = 0xff
} EvmOpcodes;

typedef struct EvmOp {
	EvmOpcodes op;
	int len;
	uint64_t imm;
	const char *txt;
	char txt_buf[32];
} EvmOp;

static void settxtf(EvmOp *op, const char *fmt, ...) {
	if (strchr (fmt, '%')) {
		va_list ap;
		va_start (ap, fmt);
		op->txt = op->txt_buf;
		vsnprintf (op->txt_buf, sizeof (op->txt_buf), fmt, ap);
		va_end (ap);
	} else {
		op->txt = fmt;
	}
}

int evm_dis (EvmOp *op, const unsigned char *buf, int buf_len) {
	op->len = 1;
	op->op = buf[0];
	switch (op->op) {
	case EVM_OP_STOP:
		op->txt = "stop";
		break;
	case EVM_OP_ADD:
		settxtf (op, "add");
		break;
	case EVM_OP_MUL:
		settxtf (op, "mul");
		break;
	case EVM_OP_SUB:
		settxtf (op, "sub");
		break;
	case EVM_OP_DIV:
		op->txt = "div";
		break;
	case EVM_OP_SDIV:
	case EVM_OP_MOD:
	case EVM_OP_SMOD:
	case EVM_OP_ADDMOD:
	case EVM_OP_MULMOD:
	case EVM_OP_EXP:
	case EVM_OP_SIGNEXTEND:
	case EVM_OP_LT:
		op->txt = "lt";
		break;
	case EVM_OP_GT:
		op->txt = "gt";
		break;
	case EVM_OP_SLT:
		settxtf (op, "slt");
		break;
	case EVM_OP_SGT:
		settxtf (op, "sgt");
		break;
	case EVM_OP_EQ:
		settxtf (op, "eq");
		break;
	case EVM_OP_ISZERO:
		op->txt = "iszero";
		break;
	case EVM_OP_AND:
		settxtf (op, "and");
		break;
	case EVM_OP_OR:
		settxtf (op, "or");
		break;
	case EVM_OP_XOR:
		settxtf (op, "xor");
		break;
	case EVM_OP_NOT:
		settxtf (op, "not");
		break;
	case EVM_OP_BYTE:
		settxtf (op, "byte");
		break;
	case EVM_OP_SHA3:
		settxtf (op, "sha3");
		break;
	case EVM_OP_ADDRESS:
		settxtf (op, "address");
		break;
	case EVM_OP_BALANCE:
		settxtf (op, "balance");
		break;
	case EVM_OP_ORIGIN:
		settxtf (op, "origin");
		break;
	case EVM_OP_CALLER:
		settxtf (op, "caller");
		break;
	case EVM_OP_CALLVALUE:
		settxtf (op, "callvalue");
		break;
	case EVM_OP_CALLDATALOAD:
		settxtf (op, "calldataload");
		break;
	case EVM_OP_CALLDATASIZE:
		settxtf (op, "calldatasize");
		break;
	case EVM_OP_CALLDATACOPY:
	case EVM_OP_CODESIZE:
	case EVM_OP_CODECOPY:
	case EVM_OP_GASPRICE:
	case EVM_OP_EXTCODESIZE:
	case EVM_OP_EXTCODECOPY:

	case EVM_OP_BLOCKHASH:
	case EVM_OP_COINBASE:
	case EVM_OP_TIMESTAMP:
	case EVM_OP_NUMBER:
	case EVM_OP_DIFFICULTY:
	case EVM_OP_GASLIMIT:
		op->txt = "gaslimit";
		break;
	case EVM_OP_POP:
		op->txt = "pop";
		break;
	case EVM_OP_MLOAD:
		op->txt = "mload";
		break;
	case EVM_OP_MSTORE:
		op->txt = "mstore";
		break;
	case EVM_OP_MSTORE8:
		op->txt = "mstore8";
		break;
	case EVM_OP_SLOAD:
		op->txt = "sload";
		break;
	case EVM_OP_SSTORE:
		op->txt = "sstore";
		break;
	case EVM_OP_JUMP:
		op->txt = "jump";
		break;
	case EVM_OP_JUMPI:
		op->txt = "jumpi";
		break;
	case EVM_OP_PC:
		op->txt = "pc";
		break;
	case EVM_OP_MSIZE:
		op->txt = "msize";
		break;
	case EVM_OP_GAS:
		op->txt = "gas";
		break;
	case EVM_OP_JUMPDEST:
		op->txt = "jumpdest";
		break;
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
			int i, pushSize = buf[0] - EVM_OP_PUSH1;
			op->imm = 0;
			for (i = 0; i < pushSize + 1; i++) {
				op->imm <<= 8;
				op->imm |= buf[i + 1];
			}
			settxtf (op, "push%d 0x%x", pushSize + 1, op->imm);
			op->len = 2 + pushSize;
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

	case EVM_OP_LOG0:
	case EVM_OP_LOG1:
	case EVM_OP_LOG2:
	case EVM_OP_LOG3:
	case EVM_OP_LOG4:

	case EVM_OP_CREATE:
		settxtf (op, "create");
		break;
	case EVM_OP_CALL:
		settxtf (op, "call");
		break;
	case EVM_OP_CALLCODE:
		settxtf (op, "callcode");
		break;
	case EVM_OP_RETURN:
		settxtf (op, "return");
		break;
	case EVM_OP_DELEGATECALL:
		op->txt = "delegatecall";
		break;
	case EVM_OP_SELFDESTRUCT:
		settxtf (op, "selfdestruct");
		break;
	default:
		settxtf (op, "invalid");
		op->len = 0;
		break;
	}
	return op->len;
}

typedef const unsigned char* buf_t;

int main() {
#if 0
[1] 6060    PUSH1 0x60 
[3] 6040    PUSH1 0x40 
[4] 52      MSTORE 
[5] 36      CALLDATASIZE 
[6] 15      ISZERO  // WRONG ?? should be 11
[9] PUSH2 0x00da 
[10] JUMPI 
[12] PUSH1 0xe0 
[14] PUSH1 0x02 
[15] EXP 
#endif
	int i;
	EvmOp op = {0};
	buf_t b = (buf_t)"\x60\x60\x60\x40\x52\x36\x15\x61\x00\xda\x57\x60\xe0\x60\x02";
	for (i= 0; i < sizeof (b); i++) {
		evm_dis (&op, b + i, sizeof (b) - i);
		printf ("len=%d op=0x%02x  %s\n", op.len, op.op, op.txt);
		if (op.len < 1) {
			break;
		}
		i += op.len - 1;
	}
	return 0;
}
