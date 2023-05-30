/* radare - MIT - Copyright 2012-2023 - pancake, murphy */

// This file is based on the Z80 analyser and modified for
// the Intel 8080 disassembler by Alexander Demin, 2012.

#include <string.h>
#include <stdio.h>
#include "i8080.h"
#include "optable.h"

static void get_args (RStrBuf *sb, struct arg_t const *arg, int val) {
	switch (arg->type) {
	case 1:
		r_strbuf_appendf (sb, "0x%02x", val & 0xff);
		break;
	case 2:
		r_strbuf_appendf (sb, "0x%04x", val);
		break;
	case 3:
		r_strbuf_append (sb, arg->fmt[(val >> arg->shift) & arg->mask]);
		break;
	}
}

static bool is_branch (int type) {
	return (type == R_ANAL_OP_TYPE_CJMP ||
		type == R_ANAL_OP_TYPE_CRET ||
		type == R_ANAL_OP_TYPE_CCALL
		);
}

void i8080_disasm (RAnalOp *op, RStrBuf *sb) {
	const ut8 *buf = op->bytes;
	const int instr = buf[0];
	int data = 0;
	//const int instr = cmd & ~((opcode->arg1.mask << opcode->arg1.shift) | (opcode->arg2.mask << opcode->arg2.shift));
	struct i8080_opcode_t const *opcode = &i8080_opcodes[instr];
	op->size = opcode->size;
	op->type = opcode->type;
	switch (opcode->size) {
		case 2:
			data = buf[0];
			break;
		case 3:
			data = buf[1] | (buf[2] << 8);
			break;
	}
	if (sb) {
		r_strbuf_set (sb, opcode->name);
		if (opcode->arg1.type != 0) {
			r_strbuf_append (sb, " ");
			get_args (sb, &opcode->arg1, data);
		}
		if (opcode->arg2.type != 0) {
			r_strbuf_append (sb, ", ");
			get_args (sb, &opcode->arg2, data);
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_CCALL:
			op->jump = data;
			op->fail = op->addr + op->size;
			break;
		}
	}
}