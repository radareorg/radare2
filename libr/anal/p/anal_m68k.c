/* radare - LGPL - Copyright 2012-2014 - pancake, pof */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#define R_IPI static
#include "../../asm/arch/m68k/m68k_disasm/m68k_disasm.c"

static int instlen(const ut8 *buf, int len) {
	m68k_word bof[8] = {0};
	char opcode[256], operands[256];
	const unsigned char *buf2;
	static struct DisasmPara_68k dp;
	/* initialize DisasmPara */
	*operands = *opcode = 0;
	memcpy (bof, buf, R_MIN(len, sizeof(bof)));
	dp.opcode = opcode;
	dp.operands = operands;
	dp.iaddr = 0LL;
	dp.instr = bof;
	buf2 = (const ut8*)M68k_Disassemble (&dp);
	if (!buf2) {
		// invalid instruction
		return 2;
	}
	return (buf2-(const ut8*)bof);
}

static int m68k_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {
	int sz = 2;
	if (op == NULL)
		return sz;
	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->nopcode = 1;
	sz = instlen (b, len);
	op->size = sz;
// TODO: Use disasm string to detect type?

	switch (b[0] &0xf0) {
	case 0xB0:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0xe0:
		// TODO:
		op->type = R_ANAL_OP_TYPE_SHL;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x80:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x60: {
			   int off = 0;
			   off = b[1];
			   if (off==0)
				   off = (b[2]<<8) | b[3] ;
			   else if (off==0xff)
				   off = (b[2]<<24) | (b[3]<<16) | (b[4]<<8) | b[5];
			   op->type = R_ANAL_OP_TYPE_CJMP;
			   op->jump = addr + 2 + off;
			   op->fail = addr + op->size;
			   op->eob = 1;
		   } break;
	case 0x30:
		  op->type = R_ANAL_OP_TYPE_MOV;
		  break;
	}

	switch(b[0]) {
	case 0x4e:
		if (b[1]==0x75){
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = 1;
			break;
		}
		if (b[1]==0x71){
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
		if (b[1]==0xF8 || b[1]==0xF9 || b[1]==0xB8 || b[1]==0xB9){
			op->type = R_ANAL_OP_TYPE_JMP;
			//op->type = R_ANAL_OP_TYPE_CALL;

			int off = 0;
			if (op->size == 4)
				off = (b[2]<<8) | b[3] ;
			if (op->size == 6)
				off = (b[2]<<24) | (b[3]<<16) | (b[4]<<8) | b[5];

			op->jump += off;
			op->fail = addr + op->size;
			op->eob = 1;
			break;
		}
		break;
	case 0x04:
	case 0x53:
	case 0x90:
	case 0x93:
	case 0x9D:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x06:
	case 0x50:
	case 0x52:
	case 0x54:
	case 0x58:
	case 0xD1:
	case 0xD3:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x0c:
	case 0xB0:
	case 0xB8:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x41:
	case 0x43:
	case 0x45:
	case 0x47:
	case 0x4D:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case 0x02:
	case 0xC0:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x03:
	case 0x10:
	case 0x12:
	case 0x15:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1B:
	case 0x1D:
	case 0x20:
	case 0x22:
	case 0x26:
	case 0x28:
	case 0x2B:
	case 0x2D:
	case 0x30:
	case 0x35:
	case 0x38:
	case 0x3B:
	case 0x3C:
	case 0x3D:
	case 0x70:
	case 0x72:
	case 0x74:
	case 0x7C:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_m68k = {
	.name = "m68k",
	.desc = "Motorola 68000",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_M68K,
	.bits = 16|32,
	.init = NULL,
	.fini = NULL,
	.op = &m68k_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m68k
};
#endif
