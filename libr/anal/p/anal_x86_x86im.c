/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "x86/x86im/x86im.h"

static int aop(RAnal *anal, RAnalAop *aop, ut64 addr, const ut8 *data, int len) {
	x86im_instr_object io;

	if (data == NULL)
		return 0;

	memset (aop, '\0', sizeof (RAnalAop));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->addr = addr;
	aop->jump = -1;
	aop->fail = -1;

	if ((x86im_dec (&io,
					anal->bits == 32 ? X86IM_IO_MODE_32BIT : X86IM_IO_MODE_64BIT,
					(unsigned char*)data)) == X86IM_STATUS_SUCCESS) {
		io.imm = r_hex_bin_truncate (io.imm, io.imm_size);
		io.disp = r_hex_bin_truncate (io.disp, io.disp_size);
		// XXX: Fix arg/local vars sign
		if (X86IM_IO_IS_GPI_JMP (&io)) { /* jump */
			if (io.id == X86IM_IO_ID_JMP_N_AI_RG) {
				aop->type = R_ANAL_OP_TYPE_UJMP;
				aop->eob = R_TRUE;
			} else {
				aop->type = R_ANAL_OP_TYPE_JMP;
				aop->jump = aop->fail + io.imm;
				aop->eob = R_TRUE;
			}
		} else
		if (X86IM_IO_IS_GPI_JCC (&io)) { /* conditional jump*/
			aop->type = R_ANAL_OP_TYPE_CJMP;
			aop->fail = aop->addr + io.len;
			aop->jump = aop->fail + io.imm;
			aop->eob = R_TRUE;
		} else
		if (X86IM_IO_IS_GPI_CALL (&io)) { /* call */
			if (io.id == X86IM_IO_ID_CALL_N_AI_RG) {
				aop->type = R_ANAL_OP_TYPE_RCALL;
				aop->eob = R_TRUE;
			} else {
				aop->type = R_ANAL_OP_TYPE_CALL;
				aop->fail = aop->addr + io.len;
				aop->jump = aop->fail + io.imm;
			}
		} else
		if (X86IM_IO_IS_GPI_RET (&io)) { /* ret*/
			aop->type = R_ANAL_OP_TYPE_RET;
			aop->eob = R_TRUE;
		} else
		if (X86IM_IO_IS_GPI_MOV (&io)) { /* mov */
			aop->type = R_ANAL_OP_TYPE_MOV;
			if (io.id == X86IM_IO_ID_MOV_RG_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_ARG_GET;
				aop->ref = io.disp;
			} else
			if (io.id == X86IM_IO_ID_MOV_MM_RG &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_ARG_SET;
				aop->ref = io.disp;
			}
		} else
		if (X86IM_IO_IS_GPI_CMP (&io)) { /* cmp */
			aop->type = R_ANAL_OP_TYPE_CMP;
		} else
		if (X86IM_IO_IS_GPI_PUSH (&io)) { /* push */
			if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_16) ||
				(io.rop[0] & X86IM_IO_ROP_SGR_GPR_32) ||
				(io.rop[0] & X86IM_IO_ROP_SGR_GPR_64))
				aop->type = R_ANAL_OP_TYPE_UPUSH;
			else {
				aop->type = R_ANAL_OP_TYPE_PUSH;
				aop->ref = io.imm;
			}
			if (io.id == X86IM_IO_ID_PUSH_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_ARG_GET;
			}
		} else
		if (X86IM_IO_IS_GPI_POP (&io)) { /* pop */
			aop->type = R_ANAL_OP_TYPE_POP;
		} else
		if (X86IM_IO_IS_GPI_ADD (&io)) { /* add */
			aop->type = R_ANAL_OP_TYPE_ADD;
			if (io.id == X86IM_IO_ID_ADD_RG_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_LOCAL_GET;
				aop->ref = io.disp;
			} else
			if (io.id == X86IM_IO_ID_ADD_MM_RG &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_LOCAL_SET;
				aop->ref = io.disp;
			} else
			if (io.id == X86IM_IO_ID_ADD_RG_IM &&
				(io.rop[0] & X86IM_IO_ROP_ID_ESP)) {
				aop->stackop = R_ANAL_STACK_INCSTACK;
				aop->value = io.imm;
			}
		} else
		if (X86IM_IO_IS_GPI_SUB (&io)) { /* sub */
			if (io.id == X86IM_IO_ID_SUB_RG_IM &&
				(io.rop[0] & X86IM_IO_ROP_ID_ESP)) {
				aop->stackop = R_ANAL_STACK_INCSTACK;
				aop->value = io.imm;
			}
			aop->type = R_ANAL_OP_TYPE_SUB;
		} else
		if (X86IM_IO_IS_GPI_MUL (&io)) { /* mul */
			aop->type = R_ANAL_OP_TYPE_MUL;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_DIV (&io)) { /* div */
			aop->type = R_ANAL_OP_TYPE_DIV;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_SHR (&io)) { /* shr */
			aop->type = R_ANAL_OP_TYPE_SHR;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_SHL (&io)) { /* shl */
			aop->type = R_ANAL_OP_TYPE_SHL;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_OR (&io)) { /* or */
			aop->type = R_ANAL_OP_TYPE_OR;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_AND (&io)) { /* and */
			aop->type = R_ANAL_OP_TYPE_AND;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_XOR (&io)) { /* xor */
			aop->type = R_ANAL_OP_TYPE_XOR;
			aop->value = io.imm;
		} else
		if (X86IM_IO_IS_GPI_NOT (&io)) { /* not */
			aop->type = R_ANAL_OP_TYPE_NOT;
			aop->value = io.imm;
		}
		aop->length = io.len;
	}

	return aop->length;
}

struct r_anal_handle_t r_anal_plugin_x86_x86im = {
	.name = "x86_x86im",
	.desc = "X86 x86im analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_x86im
};
#endif
