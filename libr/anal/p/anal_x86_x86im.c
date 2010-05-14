/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>

#include "x86/x86im/x86im.h"

static int aop(RAnal *anal, RAnalAop *aop, ut64 addr, const ut8 *data, int len) {
	x86im_instr_object io;
	st64 imm, disp;

	if (data == NULL)
		return 0;

	memset (aop, '\0', sizeof (RAnalAop));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->addr = addr;
	aop->jump = aop->fail = -1;

	if ((x86im_dec (&io,
					anal->bits == 32 ? X86IM_IO_MODE_32BIT : X86IM_IO_MODE_64BIT,
					(unsigned char*)data)) == X86IM_STATUS_SUCCESS) {
		imm = r_hex_bin_truncate (io.imm, io.imm_size);
		disp = r_hex_bin_truncate (io.disp, io.disp_size);
		if (X86IM_IO_IS_GPI_JMP (&io)) { /* jump */
			if (io.id == X86IM_IO_ID_JMP_N_AI_RG) {
				aop->type = R_ANAL_OP_TYPE_UJMP;
				aop->eob = R_TRUE;
			} else {
				aop->type = R_ANAL_OP_TYPE_JMP;
				aop->jump = aop->addr + io.len + imm;
				aop->eob = R_TRUE;
			}
		} else
		if (X86IM_IO_IS_GPI_JCC (&io)) { /* conditional jump*/
			aop->type = R_ANAL_OP_TYPE_CJMP;
			aop->fail = aop->addr + io.len;
			aop->jump = aop->addr + io.len + imm;
			aop->eob = R_TRUE;
		} else
		if (X86IM_IO_IS_GPI_CALL (&io)) { /* call */
			if (io.id == X86IM_IO_ID_CALL_N_AI_RG) {
				aop->type = R_ANAL_OP_TYPE_RCALL;
			} else {
				aop->type = R_ANAL_OP_TYPE_CALL;
				aop->jump = aop->addr + io.len + imm;
			}
			aop->fail = aop->addr + io.len;
		} else
		if (X86IM_IO_IS_GPI_RET (&io)) { /* ret */
			aop->type = R_ANAL_OP_TYPE_RET;
			aop->eob = R_TRUE;
		} else
		if (io.id == X86IM_IO_ID_HLT) { /* htl */
			aop->type = R_ANAL_OP_TYPE_RET;
			aop->eob = R_TRUE;
		} else
		if (X86IM_IO_IS_GPI_MOV (&io)) { /* mov */
			aop->type = R_ANAL_OP_TYPE_MOV;
			if (io.id == X86IM_IO_ID_MOV_RG_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_GET;
				aop->ref = disp;
			} else
			if ((io.id == X86IM_IO_ID_MOV_MM_RG ||
				 io.id == X86IM_IO_ID_MOV_MM_IM) &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_SET;
				aop->ref = disp;
			}
		} else
		if (X86IM_IO_IS_GPI_CMP (&io)) { /* cmp */
			aop->type = R_ANAL_OP_TYPE_CMP;
			if (io.id == X86IM_IO_ID_CMP_MM_IM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_GET;
				aop->ref = disp;
			}
		} else
		if (X86IM_IO_IS_GPI_PUSH (&io)) { /* push */
			if ((io.rop[0] & X86IM_IO_ROP_SGR_GPR_16) ||
				(io.rop[0] & X86IM_IO_ROP_SGR_GPR_32) ||
				(io.rop[0] & X86IM_IO_ROP_SGR_GPR_64))
				aop->type = R_ANAL_OP_TYPE_UPUSH;
			else {
				aop->type = R_ANAL_OP_TYPE_PUSH;
				aop->ref = imm;
			}
			if (io.id == X86IM_IO_ID_PUSH_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_GET;
			}
		} else
		if (X86IM_IO_IS_GPI_POP (&io)) { /* pop */
			aop->type = R_ANAL_OP_TYPE_POP;
		} else
		if (X86IM_IO_IS_GPI_ADD (&io)) { /* add */
			aop->type = R_ANAL_OP_TYPE_ADD;
			if (io.id == X86IM_IO_ID_ADD_RG_MM &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_GET;
				aop->ref = disp;
			} else
			if (io.id == X86IM_IO_ID_ADD_MM_RG &&
				(io.mem_base & X86IM_IO_ROP_ID_EBP)) {
				aop->stackop = R_ANAL_STACK_SET;
				aop->ref = disp;
			} else
			if (io.id == X86IM_IO_ID_ADD_RG_IM &&
				(io.rop[0] & X86IM_IO_ROP_ID_ESP)) {
				aop->stackop = R_ANAL_STACK_INCSTACK;
				aop->value = imm;
			}
		} else
		if (X86IM_IO_IS_GPI_SUB (&io)) { /* sub */
			if (io.id == X86IM_IO_ID_SUB_RG_IM &&
				(io.rop[0] & X86IM_IO_ROP_ID_ESP)) {
				aop->stackop = R_ANAL_STACK_INCSTACK;
				aop->value = imm;
			}
			aop->type = R_ANAL_OP_TYPE_SUB;
		} else
		if (X86IM_IO_IS_GPI_MUL (&io)) { /* mul */
			aop->type = R_ANAL_OP_TYPE_MUL;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_DIV (&io)) { /* div */
			aop->type = R_ANAL_OP_TYPE_DIV;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHR (&io)) { /* shr */
			aop->type = R_ANAL_OP_TYPE_SHR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_SHL (&io)) { /* shl */
			aop->type = R_ANAL_OP_TYPE_SHL;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_OR (&io)) { /* or */
			aop->type = R_ANAL_OP_TYPE_OR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_AND (&io)) { /* and */
			aop->type = R_ANAL_OP_TYPE_AND;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_XOR (&io)) { /* xor */
			aop->type = R_ANAL_OP_TYPE_XOR;
			aop->value = imm;
		} else
		if (X86IM_IO_IS_GPI_NOT (&io)) { /* not */
			aop->type = R_ANAL_OP_TYPE_NOT;
			aop->value = imm;
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
