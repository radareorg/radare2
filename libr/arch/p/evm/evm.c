#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>

#include "evm.h"

static const EvmOpDef opcodes[256] = {
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
	[EVM_OP_OR] = { "or", 1 },
	[EVM_OP_XOR] = { "xor", 1 },
	[EVM_OP_NOT] = { "not", 1 },
	[EVM_OP_BYTE] = { "byte", 1 },
	[EVM_OP_SHL] = { "shl", 1 },
	[EVM_OP_SHR] = { "shr", 1 },
	[EVM_OP_SAR] = { "sar", 1 },
	[EVM_OP_SHA3] = { "sha3", 1 },
	[EVM_OP_ADDRESS] = { "address", 1 },
	[EVM_OP_BALANCE] = { "balance", 1 },
	[EVM_OP_ORIGIN] = { "origin", 1 },
	[EVM_OP_CALLER] = { "caller", 1 },
	[EVM_OP_CALLVALUE] = { "callvalue", 1 },
	[EVM_OP_CALLDATALOAD] = { "calldataload", 1 },
	[EVM_OP_CALLDATASIZE] = { "calldatasize", 1 },
	[EVM_OP_CALLDATACOPY] = { "calldatacopy", 1 },
	[EVM_OP_CODESIZE] = { "codesize", 1 },
	[EVM_OP_CODECOPY] = { "codecopy", 1 },
	[EVM_OP_GASPRICE] = { "gasprice", 1 },
	[EVM_OP_EXTCODESIZE] = { "extcodesize", 1 },
	[EVM_OP_EXTCODECOPY] = { "extcodecopy", 1 },
	[EVM_OP_RETURNDATASIZE] = { "returndatasize", 1},
	[EVM_OP_RETURNDATACOPY] = { "returndatacopy", 1},
	[EVM_OP_EXTCODEHASH] = { "extcodehash", 1},
	[EVM_OP_BLOCKHASH] = { "blockhash", 1 },
	[EVM_OP_COINBASE] = { "coinbase", 1 },
	[EVM_OP_TIMESTAMP] = { "timestamp", 1 },
	[EVM_OP_NUMBER] = { "number", 1 },
	[EVM_OP_DIFFICULTY] = { "difficulty", 1 },
	[EVM_OP_GASLIMIT] = { "gaslimit", 1 },
	[EVM_OP_CHAINID] = { "chainid", 1 },
	[EVM_OP_SELFBALANCE] = { "selfbalance", 1 },
	[EVM_OP_BASEFEE] = { "basefee", 1 },
	[EVM_OP_BLOBHASH] = { "blobhash", 1 },
	[EVM_OP_BLOBBASEFEE] = { "blobbasefee", 1 },
	[EVM_OP_POP] = { "pop", 1 },
	[EVM_OP_MLOAD] = { "mload", 1 },
	[EVM_OP_MSTORE] = { "mstore", 1 },
	[EVM_OP_MSTORE8] = { "mstore8", 1 },
	[EVM_OP_SLOAD] = { "sload", 1 },
	[EVM_OP_SSTORE] = { "sstore", 1 },
	[EVM_OP_JUMP] = { "jump", 1 },
	[EVM_OP_JUMPI] = { "jumpi", 1 },
	[EVM_OP_PC] = { "pc", 1 },
	[EVM_OP_MSIZE] = { "msize", 1 },
	[EVM_OP_GAS] = { "gas", 1 },
	[EVM_OP_JUMPDEST] = { "jumpdest", 1 },
	[EVM_OP_TLOAD] = { "tload", 1 },
	[EVM_OP_TSTORE] = { "tstore", 1 },
	[EVM_OP_MCOPY] = { "mcopy", 1 },
	[EVM_OP_PUSH0] = { "push0", 1 },
	// ....
	[EVM_OP_CREATE] = { "create", 1 },
	[EVM_OP_CALL] = { "call", 1 },
	[EVM_OP_CALLCODE] = { "callcode", 1 },
	[EVM_OP_RETURN] = { "return", 1 },
	[EVM_OP_DELEGATECALL] = { "delegatecall", 1 },
	[EVM_OP_CREATE2] = { "create2", 1 },
	[EVM_OP_STATICCALL] = { "staticcall", 1 },
	[EVM_OP_REVERT] = { "revert", 1 },
	[EVM_OP_INVALID] = { "invalid", 1 },
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

int evm_asm(const char *str, ut8 *buf, int buf_len) {
	int i, len = -1;
	for (i = 0; i < 0xff; i++) {
		const EvmOpDef *opdef = &opcodes[i];
		if (opdef->txt) {
			if (!strcmp (opdef->txt, str)) {
				buf[0] = i;
				// r_strbuf_appendf (buf, "%d", i);
				return 1;
			}
		}
	}
	// TODO: add support for: push, swap, dup, log
	return len;
}

int evm_dis(EvmOp *op, const unsigned char *buf, int buf_len) {
	op->len = 1;
	op->op = buf[0];
	const EvmOpDef *opdef = &opcodes[buf[0]];
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
		int pushSize = buf[0] - EVM_OP_PUSH1;
		char hexbuf[64] = {0};
		int res = r_hex_bin2str (buf + 1, pushSize + 1, hexbuf);
		if (res < 1 || !*hexbuf) {
			strcpy (hexbuf, "0");
		}
		settxtf (op, "push%d 0x%s", pushSize + 1, hexbuf);
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
		op->len = 1;
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
		op->len = 1;
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
		op->len = 1;
	}
	break;
	default:
		settxtf (op, "unassigned");
		op->len = 0;
		break;
	}
	return op->len;
}

typedef const unsigned char *buf_t;

#if HAS_MAIN
int main() {
#if 0
	[1] 6060    PUSH1 0x60
	[3] 6040    PUSH1 0x40
	[4] 52      MSTORE
	[5] 36      CALLDATASIZE
	[6] 15      ISZERO// WRONG ?? should be 11
	[9] PUSH2 0x00da
	[10] JUMPI
	[12] PUSH1 0xe0
	[14] PUSH1 0x02
	[15] EXP
#endif
	int i;
	EvmOp op = {
		0
	};
	buf_t b = (buf_t) "\x60\x60\x60\x40\x52\x36\x15\x61\x00\xda\x57\x60\xe0\x60\x02";
	for (i = 0; i < sizeof (b); i++) {
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
