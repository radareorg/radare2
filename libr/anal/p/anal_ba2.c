/* radare - LGPL - Copyright 2013-2019 - pancake, dkreuter, astuder  */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../asm/arch/ba2/ba2_disas.c"


static int ba2_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	struct op_cmd cmd = {
		.instr = "",
		.operands = ""
	};

	op->cycles = 0;
	op->failcycles = 0;
	op->nopcode = 1;
//	op->size = ;
//	op->type = ;
	op->family = R_ANAL_OP_FAMILY_CPU; // maybe also FAMILY_IO...
//	op->id = ;

	int ret = ba2_decode_opcode (addr, buf, len, &cmd, &op->esil, op);
	if((len < ret) || (!ret && len<6)){ 
		op->size = 0; 
		return 0;
	}
	if (ret > 0) {
	}else{
		return -1;
	}
	return op->size = ret;
}

static bool set_reg_profile(RAnal *anal) {
	const char *p = 
            "=PC pc\n"
            "=SP r1\n"
            "=BP r2\n"
            "=A0 r0\n"
            "=A1 r1\n"
            "=A2 r2\n"
            "=A3 r3\n"
            "=A4 r4\n"
            "=A5 r5\n"
            "=A6 r6\n"
            "=A7 r7\n"
            "=A8 r8\n"
            "=SN r8\n"	///! TODO: ??? Which register ???
            "gpr r0  .32     0   0\n"
            "gpr r1  .32     4   0\n"
            "gpr r2  .32     8   0\n"
            "gpr r3  .32     12  0\n"
            "gpr r4  .32     16  0\n"
            "gpr r5  .32     20  0\n"
            "gpr r6  .32     24  0\n"
            "gpr r7  .32     28  0\n"
            "gpr r8  .32     32  0\n"
            "gpr r9  .32     36  0\n"
            "gpr r10 .32     40  0\n"
            "gpr r11 .32     44  0\n"
            "gpr r12 .32     48  0\n"
            "gpr r13 .32     52  0\n"
            "gpr r14 .32     56  0\n"
            "gpr r15 .32     60  0\n"
            "gpr r16 .32     64  0\n"
            "gpr r17 .32     68  0\n"
            "gpr r18 .32     72  0\n"
            "gpr r19 .32     76  0\n"
            "gpr r20 .32     80  0\n"
            "gpr r21 .32     84  0\n"
            "gpr r22 .32     88  0\n"
            "gpr r23 .32     92  0\n"
            "gpr r24 .32     96  0\n"
            "gpr r25 .32     100 0\n"
            "gpr r26 .32     104 0\n"
            "gpr r27 .32     108 0\n"
            "gpr r28 .32     112 0\n"
            "gpr r29 .32     116 0\n"
            "gpr r30 .32     120 0\n"
            "gpr r31 .32     124 0\n"
            "gpr sp  .32     4   0\n"
            "gpr fp  .32     8   0\n"
            "gpr lr  .32     36  0\n"
            "gpr pc  .32     128 0\n"
            "gpr fl  .1      132 0\n"
            "gpr mac .64     136 0\n";

	int retval = r_reg_set_profile_string (anal->reg, p);

	return retval;
}

static int archinfo(RAnal *anal, int q) {
//	fprintf(stderr, "archinfo:%d\r\n", q);
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		return 0;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 6;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		return 2;
	}
//	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
//		return 0;
//	}
	return 0; // XXX
}

RAnalPlugin r_anal_plugin_ba2 = {
	.name = "ba2",
	.arch = "ba2",
	.esil = true,
	.bits = 32,
	.desc = "Beyond Architecture 2 CPU code analysis plugin",
	.license = "LGPL3",
	.archinfo = archinfo,
	.op = &ba2_op,
	.set_reg_profile = &set_reg_profile,
//	.esil_init = esil_ba2_init,
//	.esil_fini = esil_ba2_fini
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ba2,
	.version = R2_VERSION
};
#endif

