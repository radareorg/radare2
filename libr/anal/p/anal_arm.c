/* radare - LGPL - Copyright 2007-2010 */
/*   pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

/* DEPRECATE ?? */
#include "arm/arm.h"

// XXX: must be configured somewhere with anal.bits
static int arm_mode = 32;

static unsigned int disarm_branch_offset ( unsigned int pc, unsigned int insoff ) {
	unsigned int add = insoff << 2;
	/* zero extend if higher is 1 (0x02000000) */
	if ( (add & 0x02000000) == 0x02000000 )
		add = add | 0xFC000000 ;
	return add + pc + 8;
}

#define IS_BRANCH(x) \
	((x&ARM_BRANCH_I_MASK) == ARM_BRANCH_I)

#define IS_BRANCHL(x) \
	(IS_BRANCH(x) && (x&ARM_BRANCH_LINK) == ARM_BRANCH_LINK)

#define IS_RETURN(x) \
	((x&(ARM_DTM_I_MASK|ARM_DTM_LOAD|(1<<15))) == (ARM_DTM_I|ARM_DTM_LOAD|(1<<15)))

	//if ( (inst & ( ARM_DTX_I_MASK | ARM_DTX_LOAD  | ( ARM_DTX_RD_MASK ) ) ) == ( ARM_DTX_LOAD | ARM_DTX_I | ( ARM_PC << 12 ) ) )
#define IS_UNKJMP(x) \
	(( (( ARM_DTX_RD_MASK ) ) ) == ( ARM_DTX_LOAD | ARM_DTX_I | ( ARM_PC << 12 ) ))

#define IS_LOAD(x) \
	((x&ARM_DTX_LOAD) == (ARM_DTX_LOAD))

#define IS_CONDAL(x) \
	((x&ARM_COND_MASK)==ARM_COND_AL)

#define IS_EXITPOINT(x) \
	(IS_BRANCH (x) || IS_RETURN (x) || IS_UNKJMP (x))

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *data, int len) {
	unsigned int i = 0;
	unsigned int* code = (unsigned int *)data;
	unsigned int branch_dst_addr;
	const ut8 *b = (ut8 *)data;

	if (data == NULL)
		return 0;

	memset (aop, '\0', sizeof (RAnalOp));
	aop->addr = addr;
	aop->type = R_ANAL_OP_TYPE_UNK;


	if (aop == NULL)
		return (arm_mode==16)?2:4;

	memset (aop, '\0', sizeof (RAnalOp));
	aop->type = R_ANAL_OP_TYPE_UNK;
#if 0
	fprintf(stderr, "CODE %02x %02x %02x %02x\n",
		codeA[0], codeA[1], codeA[2], codeA[3]);
#endif

	if (b[3]==0xe5 && b[2]==0x9f) {
		/* STORE */
		aop->type = R_ANAL_OP_TYPE_STORE;
		aop->stackop = R_ANAL_STACK_SET;
		aop->ref = 4+addr+b[0];
		aop->refptr = R_TRUE;
	} else
//eprintf("0x%08x\n", code[i] & ARM_DTX_LOAD);
	// 0x0001B4D8,           1eff2fe1        bx    lr
	if (b[3]==0xe2 && b[2]==0x8d && b[1]==0xd0) {
		// ADD SP, SP, ...
		aop->type = R_ANAL_OP_TYPE_ADD;
		aop->stackop = R_ANAL_STACK_INCSTACK;
		aop->value = -b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4d && b[1]==0xd0) {
		// SUB SP, SP, ..
		aop->type = R_ANAL_OP_TYPE_SUB;
		aop->stackop = R_ANAL_STACK_INCSTACK;
		aop->value = b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4c && b[1]==0xb0) {
		// SUB SP, FP, ..
		aop->type = R_ANAL_OP_TYPE_SUB;
		aop->stackop = R_ANAL_STACK_INCSTACK;
		aop->value = -b[0];
	} else
	if (b[3]==0xe2 && b[2]==0x4b && b[1]==0xd0) {
		// SUB SP, IP, ..
		aop->type = R_ANAL_OP_TYPE_SUB;
		aop->stackop = R_ANAL_STACK_INCSTACK;
		aop->value = -b[0];
	} else
	if( (code[i] == 0x1eff2fe1) ||(code[i] == 0xe12fff1e)) { // bx lr
		aop->type = R_ANAL_OP_TYPE_RET;
		aop->eob = 1;
	} else
	if ((code[i] & ARM_DTX_LOAD)) { //IS_LOAD(code[i])) {
		int ret = arm_mode/8;
		ut32 ptr = 0;
		aop->type = R_ANAL_OP_TYPE_MOV;
		if (b[2]==0x1b) {
			/* XXX pretty incomplete */
			aop->stackop = R_ANAL_STACK_GET;
			aop->ref = b[0];
			//var_add_access(addr, -b[0], 1, 0); // TODO: set/get (the last 0)
		} else {
			//ut32 oaddr = addr+8+b[0];
			//XXX TODO ret = radare_read_at(oaddr, (ut8*)&ptr, 4);
			if (ret == 4) {
				b = (ut8*)&ptr;
				aop->ref = b[0] + (b[1]<<8) + (b[2]<<16) + (b[3]<<24);
				//XXX data_xrefs_add(oaddr, aop->ref, 1);
				//TODO change data type to pointer
			} else {
				aop->ref = 0;
			}
		}
	}

	if (IS_EXITPOINT (code[i])) {
		branch_dst_addr = disarm_branch_offset (addr, code[i]&0x00FFFFFF);
		aop->ref = 0;
		if (IS_BRANCHL (code[i])) {
			if (IS_BRANCH (code[i])) {
				aop->type = R_ANAL_OP_TYPE_CALL;
				aop->jump = branch_dst_addr;
				aop->fail = addr + 4 ;
				aop->eob  = 1;
			} else {
				aop->type = R_ANAL_OP_TYPE_RET;
				aop->eob = 1;
			}
		} else if (IS_BRANCH (code[i])) {
			if (IS_CONDAL (code[i])) {
				aop->type = R_ANAL_OP_TYPE_JMP;
				aop->jump = branch_dst_addr;
				aop->eob = 1;
			} else {
				aop->type = R_ANAL_OP_TYPE_CJMP;
				aop->jump = branch_dst_addr;
				aop->fail = addr + 4;
				aop->eob  = 1;
			}
		} else {
			//unknown jump o return
			aop->type = R_ANAL_OP_TYPE_UJMP;
			aop->eob = 1;
		}
	}

	return (arm_mode==16)?2:4;
}

struct r_anal_plugin_t r_anal_plugin_arm = {
	.name = "arm",
	.desc = "ARM code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm
};
#endif
