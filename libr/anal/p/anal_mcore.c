/* radare - LGPL3 - Copyright 2018 - deroad */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int mcore_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	mcore_handle handle = {0};
    mcore_t* instr = NULL;
	char tmp[256];
    if (mcore_init (&handle, buf, len)) {
    	eprintf ("[!] mcore: bad data.\n");
        return -1;
    }

	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 2;
    if ((instr = mcore_next (&handle))) {
        op->type = instr->type;
        switch (instr->type) {
        case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_CJMP:
			op->fail = addr + op->size;
        case R_ANAL_OP_TYPE_UJMP:
			op->jump = addr + instr->args[0];
	    	eprintf ("[!] mcore: jump %llx.\n", op->jump);
			break;
		case R_ANAL_OP_TYPE_RET:
        case R_ANAL_OP_TYPE_UNK:
			op->eob = true;
	    	eprintf ("[!] mcore: jump %llx.\n", op->jump);
			break;
		default:
			break;
        }
        mcore_free (instr);
    }
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = 
			"=PC	pc\n"
			"=SP	r1\n"
			"=SR	sr\n"
			"=A0	r3\n"
			"=A1	r4\n"
			"=A2	r5\n"
			"=A3	r6\n"
			"=A4	r7\n"
			"=A5	r8\n"
			"=A6	r6\n"
			"gpr	r0   .32 0   0\n"
			"gpr	r1   .32 4   0\n"
			"gpr	r2   .32 8   0\n"
			"gpr	r3   .32 12  0\n"
			"gpr	r4   .32 16  0\n"
			"gpr	r5   .32 20  0\n"
			"gpr	r6   .32 24  0\n"
			"gpr	r7   .32 28  0\n"
			"gpr	r8   .32 32  0\n"
			"gpr	r9   .32 36  0\n"
			"gpr	r10  .32 40  0\n"
			"gpr	r11  .32 44  0\n"
			"gpr	r12 .32 48  0\n"
			"gpr	r13 .32 52  0\n"
			"gpr	r14 .32 56  0\n"
			"gpr	r15 .32 60  0\n"

			"gpr	psr .32 64  0\n"
			"gpr	vbr .32 68  0\n"
			"gpr	epsr .32 72  0\n"
			"gpr	fpsr .32 76  0\n"
			"gpr	epc .32 80  0\n"
			"gpr	fpc .32 84  0\n"
			"gpr	ss0 .32 88  0\n"
			"gpr	ss1 .32 92  0\n"
			"gpr	ss2 .32 96  0\n"
			"gpr	ss3 .32 100 0\n"
			"gpr	ss4 .32 104 0\n"
			"gpr	gcr .32 108 0\n"
			"gpr	gsr .32 112 0\n"
			"gpr	cpidr .32 116 0\n"
			"gpr	dcsr .32 120 0\n"
			"gpr	cwr .32 124 0\n"
			"gpr	cr16 .32 128 0\n"
			"gpr	cfr .32 132 0\n"
			"gpr	ccr   .32 136 0\n"
			"gpr	capr .32 140 0\n"
			"gpr	pacr .32 144 0\n"
			"gpr	prsr   .32 148 0\n"
			"gpr	cr22  .64 152 0\n"
			"gpr	cr23 .8  152 0\n"
			"gpr	cr24 .8  153 0\n"
			"gpr	cr25 .8  154 0\n"
			"gpr	cr26 .8  155 0\n"
			"gpr	cr27 .8  156 0\n"
			"gpr	cr28 .8  157 0\n"
			"gpr	cr29 .8  158 0\n"
			"gpr	cr30 .8  159 0\n"
			"gpr	cr31 .32 160 0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	return 2;
}

RAnalPlugin r_anal_plugin_mcore = {
	.name = "mcore",
	.desc = "MCore analysis plugin",
	.arch = "mcore",
	.license = "LGPL3",
	.bits = 32,
	.op = &mcore_anal,
	.archinfo = archinfo,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mcore,
	.version = R2_VERSION
};
#endif
