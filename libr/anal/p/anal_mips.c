/* radare - LGPL - Copyright 2010 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *bytes, int len) {
	unsigned long op;
	char buf[10];
	int reg; 
	int oplen = (anal->bits==16)?2:4;

        if (aop == NULL)
		return oplen;

        memset (aop, 0, sizeof (RAnalOp));
        aop->type = R_ANAL_OP_TYPE_UNK;
	aop->length = oplen;

	r_mem_copyendian ((ut8*)&op, bytes, 4, anal->big_endian);
	aop->type = R_ANAL_OP_TYPE_UNK;

	switch (op & 0x3f) {
	// J-Type
	case 2: // j
		break;
		// branch to register
		//XXX TODO
		//eprintf("UJUMP\n");
		//aop->type = R_ANAL_OP_TYPE_UJMP;
		break;
		aop->type = R_ANAL_OP_TYPE_CJMP;
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
		aop->type = R_ANAL_OP_TYPE_CJMP;
		reg = (((op&0x00ff0000)>>16) + ((op&0xff000000)>>24));
		aop->jump = addr+(reg<<2) + 4;
		aop->fail = addr+8;
		// calculate jump
		break;
	case 3: // jalr
	//case 9: // jalr
		reg = op>>24;
		if (reg<10) {
			aop->type = R_ANAL_OP_TYPE_RCALL;
			snprintf (buf, sizeof (buf), "t%d", reg); // XXX must be rN...!regs* should be synced here
			aop->jump = 1234;//flag_get_addr(buf);
			aop->fail = addr+8;
		}
		break;
	case 8: // jr
		aop->type = R_ANAL_OP_TYPE_RET;
		break;
	case 12:
		aop->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 13:
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		switch(op) {
		case 32: // add
		case 33: // addu
			aop->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 34: // sub
		case 35: // subu
			aop->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0x03e00008:
		case 0x0800e003: // jr ra
			aop->type = R_ANAL_OP_TYPE_RET;
			break;
		case 0x0000000d: // case 26:
		case 0x0d000000: // break
			aop->type = R_ANAL_OP_TYPE_TRAP; 
			break;
		case 0:
			aop->type = R_ANAL_OP_TYPE_NOP;
			break;
		default:
			//switch((op<<24)&0xff) { //bytes[3]) { // TODO handle endian ?
			switch((bytes[3])) {
			case 0xc:
				aop->type = R_ANAL_OP_TYPE_SWI;
				break;
			case 0x9:
			case 0x8:
				aop->type = R_ANAL_OP_TYPE_UJMP;
				break;
			case 0x21:
				aop->type = R_ANAL_OP_TYPE_PUSH; // XXX move 
				break;
			}
		}
	}
	return aop->length;
}

struct r_anal_plugin_t r_anal_plugin_mips = {
        .name = "mips",
        .desc = "MIPS code analysis plugin",
        .init = NULL,
        .fini = NULL,
        .aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
        .type = R_LIB_TYPE_ANAL,
        .data = &r_anal_plugin_mips
};
#endif
