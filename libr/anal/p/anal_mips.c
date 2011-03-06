/* radare - LGPL - Copyright 2010 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int mips_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *bytes, int len) {
	unsigned long opcode;
	char buf[10];
	int reg; 
	int oplen = (anal->bits==16)?2:4;

        if (op == NULL)
		return oplen;

        memset (op, 0, sizeof (RAnalOp));
        op->type = R_ANAL_OP_TYPE_UNK;
	op->length = oplen;

	r_mem_copyendian ((ut8*)&opcode, bytes, 4, anal->big_endian);
	op->type = R_ANAL_OP_TYPE_UNK;

	switch (opcode & 0x3f) {
	// J-Type
	case 2: // j
		break;
		// branch to register
		//XXX TODO
		//eprintf("UJUMP\n");
		//op->type = R_ANAL_OP_TYPE_UJMP;
		break;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	// R-Type
	case 1: // bltz
		// 04100001        bltzal        zero,0x2aaa8cb4
	case 4: // beq // bal
	case 5: // bne
	case 6: // blez
	case 7: // bgtz
	case 16: //beqz
	case 20: //bnel
		op->type = R_ANAL_OP_TYPE_CJMP;
		reg = (((opcode&0x00ff0000)>>16) + ((opcode&0xff000000)>>24));
		op->jump = addr+(reg<<2) + 4;
		op->fail = addr+8;
		// calculate jump
		break;
	case 3: // jalr
	//case 9: // jalr
		reg = opcode>>24;
		if (reg<10) {
			op->type = R_ANAL_OP_TYPE_UCALL;
			snprintf (buf, sizeof (buf), "t%d", reg); // XXX must be rN...!regs* should be synced here
			op->jump = 1234;//flag_get_addr(buf);
			op->fail = addr+8;
		}
		break;
	case 8: // jr
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 12:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 13:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		switch(opcode) {
		case 32: // add
		case 33: // addu
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 34: // sub
		case 35: // subu
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0x03e00008:
		case 0x0800e003: // jr ra
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 0x0000000d: // case 26:
		case 0x0d000000: // break
			op->type = R_ANAL_OP_TYPE_TRAP; 
			break;
		case 0:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		default:
			//switch((opcode<<24)&0xff) { //bytes[3]) { // TODO handle endian ?
			switch((bytes[3])) {
			case 0xc:
				op->type = R_ANAL_OP_TYPE_SWI;
				break;
			case 0x9:
			case 0x8:
				op->type = R_ANAL_OP_TYPE_UJMP;
				break;
			case 0x21:
				op->type = R_ANAL_OP_TYPE_PUSH; // XXX move 
				break;
			}
		}
	}
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_mips = {
	.name = "mips",
	.desc = "MIPS code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.op = &mips_op,
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
        .data = &r_anal_plugin_mips
};
#endif
