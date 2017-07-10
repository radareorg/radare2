/* radare2 - LGPL - Copyright 2017 - wargio */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/ppc/libvle/vle.h"

static vle_handle handle = {0};

static int vle_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	memset (op, 0, sizeof (RAnalOp));
	vle_t* instr = NULL;
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = 2;
	if(len > 1 && !vle_init (&handle, buf, len) && !vle_option(&handle, VLE_INTERNAL_PPC) && (instr = vle_next (&handle))) {
		
		op->size = instr->size;
		op->type = instr->anal_op;
		//op->id = instr->type;

		switch (op->type) {
		case R_ANAL_OP_TYPE_ADD:
			break;
		case R_ANAL_OP_TYPE_AND:
			break;
		case R_ANAL_OP_TYPE_CALL:
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CCALL:
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			op->cond = instr->cond;//R_ANAL_COND_NE;
			op->eob = true;
			op->jump = addr + instr->fields[instr->n - 1].value;
			op->fail = addr + op->size;
			break;
		case R_ANAL_OP_TYPE_CMP:
			break;
		case R_ANAL_OP_TYPE_JMP:
			op->jump = addr + instr->fields[instr->n - 1].value;
			break;
		case R_ANAL_OP_TYPE_LOAD:
			break;
		case R_ANAL_OP_TYPE_MOV:
			break;
		case R_ANAL_OP_TYPE_MUL:
			break;
		case R_ANAL_OP_TYPE_NOT:
			break;
		case R_ANAL_OP_TYPE_OR:
			break;
		case R_ANAL_OP_TYPE_RCALL:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RET:
			op->eob = true;
			break;
		case R_ANAL_OP_TYPE_RJMP:
			break;
		case R_ANAL_OP_TYPE_SHL:
			break;
		case R_ANAL_OP_TYPE_SHR:
			break;
		case R_ANAL_OP_TYPE_STORE:
			break;
		case R_ANAL_OP_TYPE_SUB:
			break;
		case R_ANAL_OP_TYPE_SWI:
			break;
		case R_ANAL_OP_TYPE_SYNC:
			break;
		case R_ANAL_OP_TYPE_TRAP:
			break;
		case R_ANAL_OP_TYPE_XOR:
			break;
		default:
			eprintf("Missing R_ANAL_OP_TYPE (0x%X == 0x%X)\n", op->type, R_ANAL_OP_TYPE_CJMP);
			break;
		}
		vle_free(instr);
	} else {
		return -1;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
    const char * p =
		"=PC	pc\n"
		"=SP	r1\n"
		"=SR	srr1\n" // status register ??
		"=A0	r3\n" // also for ret
		"=A1	r4\n"
		"=A2	r5\n"
		"=A3	r6\n"
		"=A4	r7\n"
		"=A5	r8\n"
		"=A6	r6\n"
		"gpr	srr0   .64 0   0\n"
		"gpr	srr1   .64 8   0\n"
		"gpr	r0   .64 16  0\n"
		"gpr	r1   .64 24  0\n"
		"gpr	r2   .64 32  0\n"
		"gpr	r3   .64 40  0\n"
		"gpr	r4   .64 48  0\n"
		"gpr	r5   .64 56  0\n"
		"gpr	r6   .64 64  0\n"
		"gpr	r7   .64 72  0\n"
		"gpr	r8   .64 80  0\n"
		"gpr	r9   .64 88  0\n"
		"gpr	r10 .64 96  0\n"
		"gpr	r11 .64 104 0\n"
		"gpr	r12 .64 112 0\n"
		"gpr	r13 .64 120 0\n"
		"gpr	r14 .64 128 0\n"
		"gpr	r15 .64 136 0\n"
		"gpr	r16 .64 144 0\n"
		"gpr	r17 .64 152 0\n"
		"gpr	r18 .64 160 0\n"
		"gpr	r19 .64 168 0\n"
		"gpr	r20 .64 176 0\n"
		"gpr	r21 .64 184 0\n"
		"gpr	r22 .64 192 0\n"
		"gpr	r23 .64 200 0\n"
		"gpr	r24 .64 208 0\n"
		"gpr	r25 .64 216 0\n"
		"gpr	r26 .64 224 0\n"
		"gpr	r27 .64 232 0\n"
		"gpr	r28 .64 240 0\n"
		"gpr	r29 .64 248 0\n"
		"gpr	r30 .64 256 0\n"
		"gpr	r31 .64 264 0\n"
		"gpr	lr   .64 272 0\n"
		"gpr	ctr .64 280 0\n"
		"gpr	msr .64 288 0\n"
		"gpr	pc   .64 296 0\n"
		"gpr	cr  .64 304 0\n"
		"gpr	cr0 .8  304 0\n"
		"gpr	cr1 .8  305 0\n"
		"gpr	cr2 .8  306 0\n"
		"gpr	cr3 .8  307 0\n"
		"gpr	cr4 .8  308 0\n"
		"gpr	cr5 .8  309 0\n"
		"gpr	cr6 .8  310 0\n"
		"gpr	cr7 .8  311 0\n"
		"gpr	xer .64 312 0\n"
		"gpr	mq   .64 320 0\n"
		"gpr	fpscr  .64 328 0\n"
		"gpr	vrsave .64 336 0\n"
		"gpr	pvr .64 344 0\n"
		"gpr	dccr   .32 352 0\n"
		"gpr	iccr   .32 356 0\n"
		"gpr	dear   .32 360 0\n"
		"gpr	hid0   .64 364 0\n"
		"gpr	hid1   .64 372 0\n"
		"gpr	hid2   .64 380 0\n"
		"gpr	hid3   .64 388 0\n"
		"gpr	hid4   .64 396 0\n"
		"gpr	hid5   .64 404 0\n"
		"gpr	hid6   .64 412 0\n"
		"gpr	ibat0  .64 420 0\n"
		"gpr	ibat1  .64 428 0\n"
		"gpr	ibat2  .64 436 0\n"
		"gpr	ibat3  .64 444 0\n"
		"gpr	ibat0l .32 420 0\n"
		"gpr	ibat1l .32 428 0\n"
		"gpr	ibat2l .32 436 0\n"
		"gpr	ibat3l .32 444 0\n"
		"gpr	ibat0u .32 424 0\n"
		"gpr	ibat1u .32 432 0\n"
		"gpr	ibat2u .32 440 0\n"
		"gpr	ibat3u .32 448 0\n"
		"gpr	dbat0  .64 456 0\n"
		"gpr	dbat1  .64 464 0\n"
		"gpr	dbat2  .64 472 0\n"
		"gpr	dbat3  .64 480 0\n"
		"gpr	dbat0l .32 456 0\n"
		"gpr	dbat1l .32 464 0\n"
		"gpr	dbat2l .32 472 0\n"
		"gpr	dbat3l .32 480 0\n"
		"gpr	dbat0u .32 460 0\n"
		"gpr	dbat1u .32 468 0\n"
		"gpr	dbat2u .32 476 0\n"
		"gpr	dbat3u .32 484 0\n"
		"gpr	mask   .64 488 0\n"; //not a real register used on complex functions
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_ppc_vle = {
	.desc = "PowerPC VLE analysis plugin",
	.license = "LGPL3",
	.name = "ppc.vle",
	.arch = "ppc",
	.bits = 32,
	.op = &vle_anop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_ppc_vle,
	.version = R2_VERSION
};
#endif
