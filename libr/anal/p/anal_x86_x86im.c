/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "x86/x86im/x86im.h"

static int aop(RAnal *anal, RAnalAop *aop, ut64 addr, const ut8 *data, int len) {
	x86im_instr_object io;

	if (data == NULL)
		return 0;

	memset (aop, '\0', sizeof (RAnalAop));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->addr = addr;

	if ((x86im_dec (&io,
					anal->bits == 32 ? X86IM_IO_MODE_32BIT : X86IM_IO_MODE_64BIT,
					(unsigned char*)data)) == X86IM_STATUS_SUCCESS) {
		if (X86IM_IO_IS_GPI_JMP (&io)) {
			aop->type = R_ANAL_OP_TYPE_JMP;
			aop->jump = aop->fail + io.imm;
			aop->eob = R_TRUE;
		}
		if (X86IM_IO_IS_GPI_JCC (&io)) {
			aop->type = R_ANAL_OP_TYPE_CJMP;
			aop->fail = aop->addr + io.len;
			aop->jump = aop->fail + io.imm;
			aop->eob = R_TRUE;
		}
		if (X86IM_IO_IS_GPI_CALL (&io)) {
			aop->type = R_ANAL_OP_TYPE_CALL;
			aop->fail = aop->addr + io.len;
			aop->jump = aop->fail + io.imm;

		}
		if (X86IM_IO_IS_GPI_RET (&io)) {
			aop->type = R_ANAL_OP_TYPE_RET;
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
