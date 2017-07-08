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

typedef struct {
	const char *txt;
	int len;
} EvmOpDef;


static EvmOpDef opcodes[256] = {
	[EVM_OP_STOP] = { "stop", 1 },
	[EVM_OP_ADD] = { "add", 1 },
	[EVM_OP_MUL] = { "mul", 1 },
	[EVM_OP_SUB] = { "sub", 1 },
	[EVM_OP_DIV] = { "div", 1 },
	[EVM_OP_SDIV] = { "sdiv", 1 },
	[EVM_OP_MOD] = { "mod", 1 },
	[EVM_OP_SMOD] = { "smod", 1 },
	[EVM_OP_ADDMOD] = { "addmod", 1 },
	[EVM_OP_MULMOD] = { "mulmod", 1 },
	[EVM_OP_EXP] = { "exp", 1 },
	[EVM_OP_SIGNEXTEND] = { "signextend", 1 },
	[EVM_OP_LT] = { "lt", 1 },
	[EVM_OP_GT] = { "gt", 1 },
	[EVM_OP_SLT] = { "slt", 1 },
	[EVM_OP_SGT] = { "sgt", 1 },
	[EVM_OP_EQ] = { "eq", 1 },
	[EVM_OP_ISZERO] = { "iszero", 1 },
	[EVM_OP_AND] = { "and", 1 },
	[EVM_OP_OR] = { "or" },
	[EVM_OP_XOR] = { "xor" },
	[EVM_OP_NOT] = { "not" },
	[EVM_OP_BYTE] = { "byte" },
	[EVM_OP_SHA3] = { "sha3" },
	[EVM_OP_ADDRESS] = { "address" },
	[EVM_OP_BALANCE] = { "balance" },
	[EVM_OP_ORIGIN] = { "origin" },
	[EVM_OP_CALLER] = { "caller" },
	[EVM_OP_CALLVALUE] = { "callvalue" },
	[EVM_OP_CALLDATALOAD] = { "calldataload" },
	[EVM_OP_CALLDATASIZE] = { "calldatasize" },
	[EVM_OP_CALLDATACOPY] = { "calldatacopy" },
	[EVM_OP_CODESIZE] = { "codesize" },
	[EVM_OP_CODECOPY] = { "codecopy" },
	[EVM_OP_GASPRICE] = { "gasprice" },
	[EVM_OP_EXTCODESIZE] = { "extcodesize" },
	[EVM_OP_EXTCODECOPY] = { "extcodecopy" },
	[EVM_OP_BLOCKHASH] = { "blockhash" },
	[EVM_OP_COINBASE] = { "coinbase" },
	[EVM_OP_TIMESTAMP] = { "timestamp" },
	[EVM_OP_NUMBER] = { "number" },
	[EVM_OP_DIFFICULTY] = { "difficulty" },
	[EVM_OP_GASLIMIT] = { "gaslimit", 1 },
	[EVM_OP_POP] = { "pop", 1 },
	[EVM_OP_MLOAD] = { "mload", 1 },
	[EVM_OP_MSTORE] = { "mstore" },
	[EVM_OP_MSTORE8] = { "mstore8" },
	[EVM_OP_SLOAD] = { "sload" },
	[EVM_OP_SSTORE] = { "sstore" },
	[EVM_OP_JUMP] = { "jump" },
	[EVM_OP_JUMPI] = { "jumpi" },
	[EVM_OP_PC] = { "pc" },
	[EVM_OP_MSIZE] = { "msize" },
	[EVM_OP_GAS] = { "gas" },
	[EVM_OP_JUMPDEST] = { "jumpdest" },
	// ....
	[EVM_OP_CREATE] = { "create", 1 },
	[EVM_OP_CALL] = { "call", 1 },
	[EVM_OP_CALLCODE] = { "callcode", 1 },
	[EVM_OP_RETURN] = { "return", 1 },
	[EVM_OP_DELEGATECALL] = { "delegatecall", 1 },
	[EVM_OP_SELFDESTRUCT] = { "selfdestruct", 1 },
};

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

int evm_asm (const char *str, unsigned char *buf, int buf_len) {
	int i, len = -1;
	for (i = 0; i< 0xff; i++) {
		EvmOpDef *opdef = &opcodes[i];
		if (opdef->txt) {
			if (!strcmp (opdef->txt, str)) {
				buf[0] = i;
				return 1;
			}
		}
	}
	// TODO: add support for: push, swap, dup, log
	return len;
}

int evm_dis (EvmOp *op, const unsigned char *buf, int buf_len) {
	op->len = 1;
	op->op = buf[0];
	EvmOpDef *opdef = &opcodes[buf[0]];
	if (opdef->txt) {
		op->txt = opdef->txt;
		op->len = opdef->len;
		if (op->len < 1) {
			op->len = 1;
		}
		return op->len;
	}
	switch (op->op) {
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
		{
			int dupSize = buf[0] - EVM_OP_DUP1 + 1;
			settxtf (op, "dup%d", dupSize);
			op->len = dupSize + 1;
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
			int swapSize = buf[0] - EVM_OP_SWAP1 + 1;
			settxtf (op, "swap%d", swapSize);
			op->len = swapSize + 1;
		}
		break;
	case EVM_OP_LOG0:
	case EVM_OP_LOG1:
	case EVM_OP_LOG2:
	case EVM_OP_LOG3:
	case EVM_OP_LOG4:
		{
			int logSize = buf[0] - EVM_OP_LOG0;
			settxtf (op, "log%d", logSize);
			op->len = logSize + 1;
		}
		break;
	default:
		settxtf (op, "invalid");
		op->len = 0;
		break;
	}
	return op->len;
}

typedef const unsigned char* buf_t;

#if HAS_MAIN
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
#endif
