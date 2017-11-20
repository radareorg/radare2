#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>

#include "evm.h"

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
