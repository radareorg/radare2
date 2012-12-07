/* radare - LGPL - Copyright 2007-2012 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

/* DEPRECATE ?? */
#include "arm/arm.h"
#include "../asm/arch/arm/arm.h"
#include "../asm/arch/arm/winedbg/be_arm.h"

static unsigned int disarm_branch_offset (unsigned int pc, unsigned int insoff) {
	unsigned int add = insoff << 2;
	/* zero extend if higher is 1 (0x02000000) */
	if ((add & 0x02000000) == 0x02000000)
		add |= 0xFC000000;
	return add + pc + 8;
}

#define IS_BRANCH(x)  ((x&ARM_BRANCH_I_MASK) == ARM_BRANCH_I)
#define IS_BRANCHL(x) (IS_BRANCH(x) && (x&ARM_BRANCH_LINK) == ARM_BRANCH_LINK)
#define IS_RETURN(x)  ((x&(ARM_DTM_I_MASK|ARM_DTM_LOAD|(1<<15))) == (ARM_DTM_I|ARM_DTM_LOAD|(1<<15)))
//if ( (inst & ( ARM_DTX_I_MASK | ARM_DTX_LOAD  | ( ARM_DTX_RD_MASK ) ) ) == ( ARM_DTX_LOAD | ARM_DTX_I | ( ARM_PC << 12 ) ) )
#define IS_UNKJMP(x)  (( (( ARM_DTX_RD_MASK ) ) ) == ( ARM_DTX_LOAD | ARM_DTX_I | ( ARM_PC << 12 ) ))
#define IS_LOAD(x)    ((x&ARM_DTX_LOAD) == (ARM_DTX_LOAD))
#define IS_CONDAL(x)  ((x&ARM_COND_MASK)==ARM_COND_AL)
#define IS_EXITPOINT(x) (IS_BRANCH (x) || IS_RETURN (x) || IS_UNKJMP (x))

#define API static

static int op_thumb(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int op_code;
	ut16 *_ins = (ut16*)data;
	ut16 ins = *_ins;

	struct arm_insn *arminsn = arm_new();
	arm_set_thumb(arminsn, R_TRUE);
	arm_set_input_buffer(arminsn, data);
	arm_set_pc(arminsn, addr);
	op->length = arm_disasm_one_insn(arminsn);

	// TODO: handle 32bit instructions (branches are not correctly decoded //

	/* CMP */
	if (((ins & _(B1110,0,0,0)) == _(B0010,0,0,0) )
                && (1 == (ins & _(1,B1000,0,0)) >> 11)) { // dp3
		op->type = R_ANAL_OP_TYPE_CMP;
		return op->length;
	}
        if ( (ins & _(B1111,B1100,0,0)) == _(B0100,0,0,0) ) {
                op_code = (ins & _(0,B0011,B1100,0)) >> 6;
                if (op_code == 8 || op_code == 10) { // dp5
			op->type = R_ANAL_OP_TYPE_CMP;
			return op->length;
		}
	}
        if ( (ins & _(B1111,B1100,0,0)) == _(B0100,B0100,0,0) ) {
                op_code = (ins & _(0,B0011,0,0)) >> 8; // dp8
		if (op_code== 1) {
			op->type = R_ANAL_OP_TYPE_CMP;
			return op->length;
		}
	}
	if (ins == 0xbf) {
		// TODO: add support for more NOP instructions
		op->type = R_ANAL_OP_TYPE_NOP;
        } else if (((op_code = ((ins & _(B1111,B1000,0,0)) >> 11)) >= 12 && op_code <= 17 )) {
		if (op_code%2)
			op->type = R_ANAL_OP_TYPE_LOAD;
		else op->type = R_ANAL_OP_TYPE_STORE;
        } else if ( (ins & _(B1111,0,0,0)) == _(B0101,0,0,0) ) {
                op_code = (ins & _(0,B1110,0,0)) >> 9;
		if (op_code%2)
			op->type = R_ANAL_OP_TYPE_LOAD;
		else op->type = R_ANAL_OP_TYPE_STORE;
	} else if ( (ins & _(B1111,0,0,0)) == _(B1101,0,0,0) ) {
		// BNE..
		int delta = (ins & _(0,0,B1111,B1111));
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr+4+(delta<<1);
		op->fail = addr+4;
        } else if ( (ins & _(B1110,B1000,0,0)) == _(B1110,0,0,0) ) {
		// B
		int delta = (ins & _(0,0,B1111,B1111));
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr+4+(delta<<1);
		op->fail = addr+4;
		op->eob = 1;
        } else if ( (ins & _(B1111,B1111,0,0)) == _(B0100,B0111,0,0) ) {
		// BLX
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->jump = addr+4+(ut32)((ins & _(0,0,B0111,B1000)) >> 3);
		op->fail = addr+4;
        } else if ( (ins & _(B1111,B1111,0,0)) == _(B1011,B1110,0,0) ) {
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->value = (ut64)(ins>>8);
        } else if ( (ins & _(B1111,B1111,0,0)) == _(B1101,B1111,0,0)) {
		op->type = R_ANAL_OP_TYPE_SWI;
		op->value = (ut64)(ins>>8);
	}
	op->jump = arminsn->jmp;
	op->fail = arminsn->fail;
	arm_free(arminsn);
	return op->length;
}

#if 0
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
#endif
static int iconds[] = {
	R_ANAL_COND_EQ,
	R_ANAL_COND_NE,
	0, // cs
	0, // cc
	0, // mi
	0, // pl
	0, // vs
	0, // vc

	0, // hi
	0, // ls
	R_ANAL_COND_GE,
	R_ANAL_COND_LT,
	R_ANAL_COND_GT,
	R_ANAL_COND_LE,
	R_ANAL_COND_AL,
	R_ANAL_COND_NV,
};

static int op_cond (const ut8 *data) {
	ut8 b = data[3] >>4;
	if (b==0xf) return 0;
	return iconds[b];
}

static int arm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	const ut8 *b = (ut8 *)data;
	ut8 ndata[4];
	ut32 branch_dst_addr, i = 0;
	ut32* code = (ut32 *)data;
	struct arm_insn *arminsn;

	if (data == NULL)
		return 0;
	memset (op, '\0', sizeof (RAnalOp));
	arminsn = arm_new();
	arm_set_thumb (arminsn, R_FALSE);
	arm_set_input_buffer (arminsn, data);
	arm_set_pc (arminsn, addr);
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (anal->big_endian) {
		b = data = ndata;
		ndata[0]=data[3];
		ndata[1]=data[2];
		ndata[2]=data[1];
		ndata[3]=data[0];
	}
#if 0
	op->jump = op->fail = -1;
	op->ref = op->value = -1;
#endif
	if (anal->bits==16)
		return op_thumb (anal, op, addr, data, len);
	op->length = 4;
#if 0
	fprintf(stderr, "CODE %02x %02x %02x %02x\n",
		codeA[0], codeA[1], codeA[2], codeA[3]);
#endif
	op->cond = op_cond (data);
	if (b[2]==0x8f && b[3]==0xe2) {
		op->type = R_ANAL_OP_TYPE_ADD;
		op->ref = addr+b[0]+((b[1]&0xf)<<8);
	} else
	if (b[2]>=0x9c && b[2]<= 0x9f) { // load instruction
		char ch = b[3]&0xf;
		switch (ch) {
			case 5:
				if ((b[3]&0xf) == 5) {
					op->ref = 12+addr+b[0]+((b[1]&0xf)<<8);
					op->refptr = R_TRUE;
				}
			case 4:
			case 6:
			case 7:
			case 8:
			case 9:
				op->type = R_ANAL_OP_TYPE_LOAD;
		}
	} else
    	// 0x000037b8  00:0000   0             800000ef  svc 0x00000080
	if (b[2]==0xa0 && b[3]==0xe1) {
		int n = (b[0]<<16) + b[1];
		op->type = R_ANAL_OP_TYPE_MOV;
		switch (n) {
		case 0:
		case 0x0110: case 0x0220: case 0x0330: case 0x0440:
		case 0x0550: case 0x0660: case 0x0770: case 0x0880:
		case 0x0990: case 0x0aa0: case 0x0bb0: case 0x0cc0:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
	} else
	if (b[3]==0xef) {
		op->type = R_ANAL_OP_TYPE_SWI;
		op->value = (b[0] | (b[1]<<8) | (b[2]<<2));
	} else
#if 0
          0x00000000      a4a09fa4         ldrge sl, [pc], 0xa4
          0x00000000      a4a09fa5         ldrge sl, [pc, 0xa4]
          0x00000000      a4a09fa6         ldrge sl, [pc], r4, lsr 1
          0x00000000      a4a09fa7         ldrge sl, [pc, r4, lsr 1]
          0x00000000      a4a09fe8         ldm pc, {r2, r5, r7, sp, pc}; <UNPREDICT
#endif
	if ((b[3]&0xf)==5) { // [reg,0xa4]
		if ((b[1]&0xf0) == 0xf0) {
			//ldr pc, [pc, #1] ; 
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->type = R_ANAL_OP_TYPE_RET; // FAKE FOR FUN
			//op->stackop = R_ANAL_STACK_SET;
			op->jump = 1234;
			//op->ref = 4+addr+b[0]; // sure? :)
			//op->refptr = R_TRUE;
		}
	} else
//eprintf("0x%08x\n", code[i] & ARM_DTX_LOAD);
	// 0x0001B4D8,           1eff2fe1        bx    lr
	if (b[3]==0xe2 && b[2]==0x8d && b[1]==0xd0) {
		// ADD SP, SP, ...
		op->type = R_ANAL_OP_TYPE_ADD;
		op->stackop = R_ANAL_STACK_INCSTACK;
		op->value = -b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4d && b[1]==0xd0) {
		// SUB SP, SP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INCSTACK;
		op->value = b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4c && b[1]==0xb0) {
		// SUB SP, FP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INCSTACK;
		op->value = -b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4b && b[1]==0xd0) {
		// SUB SP, IP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INCSTACK;
		op->value = -b[0];
	} else
	if ( (code[i] == 0x1eff2fe1) ||(code[i] == 0xe12fff1e)) { // bx lr
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = 1;
	} else
	if ((code[i] & ARM_DTX_LOAD)) { //IS_LOAD(code[i])) {
		ut32 ptr = 0;
		op->type = R_ANAL_OP_TYPE_MOV;
		if (b[2]==0x1b) {
			/* XXX pretty incomplete */
			op->stackop = R_ANAL_STACK_GET;
			op->ref = b[0];
			//var_add_access(addr, -b[0], 1, 0); // TODO: set/get (the last 0)
		} else {
			//ut32 oaddr = addr+8+b[0];
			//XXX TODO ret = radare_read_at(oaddr, (ut8*)&ptr, 4);
			if (anal->bits == 32) {
				b = (ut8*)&ptr;
				op->ref = b[0] + (b[1]<<8) + (b[2]<<16) + (b[3]<<24);
				//XXX data_xrefs_add(oaddr, op->ref, 1);
				//TODO change data type to pointer
			} else op->ref = 0;
		}
	}

	if (IS_EXITPOINT (code[i])) {
		b=data;
		branch_dst_addr = disarm_branch_offset (addr, b[0] | (b[1]<<8) | (b[2]<<16)); //code[i]&0x00FFFFFF);
		op->ref = 0;
		if (IS_BRANCHL (code[i])) {
			if (IS_BRANCH (code[i])) {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = branch_dst_addr;
				op->fail = addr + 4 ;
				op->eob  = 1;
			} else {
				op->type = R_ANAL_OP_TYPE_RET;
				op->eob = 1;
			}
		} else if (IS_BRANCH (code[i])) {
			if (IS_CONDAL (code[i])) {
				op->type = R_ANAL_OP_TYPE_JMP;
		//op->type = R_ANAL_OP_TYPE_NOP;
				op->jump = branch_dst_addr;
				op->fail = UT64_MAX;
				op->eob = 1;
			} else {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = branch_dst_addr;
				op->fail = addr + 4;
				op->eob  = 1;
			}
		} else {
			//unknown jump o return
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->eob = 1;
		}
	}
	//op->jump = arminsn->jmp;
	//op->fail = arminsn->fail;
	arm_free(arminsn);
	return op->length;
}

static int set_reg_profile(RAnal *anal) {
	/* XXX Dupped Profiles */
	return r_reg_set_profile_string (anal->reg,
			"=pc	r15\n"
			"=sp	r14\n" // XXX
			"=bp	r14\n" // XXX
			"=a0	r0\n"
			"=a1	r1\n"
			"=a2	r2\n"
			"=a3	r3\n"
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15

			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n");
}

struct r_anal_plugin_t r_anal_plugin_arm = {
	.name = "arm",
	.arch = R_SYS_ARCH_ARM,
	.bits = 32,
	.desc = "ARM code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.op = &arm_op,
	.set_reg_profile = set_reg_profile,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm
};
#endif
