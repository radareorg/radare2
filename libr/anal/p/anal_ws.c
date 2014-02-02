/* radare - LGPL - Copyright 2014 Condret */

#include <string.h>
#include <r_types.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>
#define WS_API static
#include "../../asm/arch/whitespace/wsdis.c"


static int ws_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len)
{
	memset(op, '\0', sizeof(RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	RAsmOp *aop;
	aop = R_NEW0(RAsmOp);
	op->size = wsdis(aop, data, len);
	if(op->size) {
		switch(aop->buf_asm[0]) {
			case 'n':
				op->type = R_ANAL_OP_TYPE_NOP;
				break;
			case 'e':
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			case 'd':
				if(aop->buf_asm[1] == 'u')
					op->type = R_ANAL_OP_TYPE_UPUSH;
				else
					op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case 'i':
				op->type = R_ANAL_OP_TYPE_ILL;
				break;
			case 'a':
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			case 'm':
				if(aop->buf_asm[1] == 'o')
					op->type = R_ANAL_OP_TYPE_MOD;
				else
					op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case 'r':
				op->type = R_ANAL_OP_TYPE_RET;
				break;
			case 'l':
				op->type = R_ANAL_OP_TYPE_LOAD;
				break;
			case 'c':
				if(aop->buf_asm[1] == 'a')
					op->type = R_ANAL_OP_TYPE_CALL;
				else
					op->type = R_ANAL_OP_TYPE_UPUSH;
				break;
			case 'j':
				if(aop->buf_asm[1] == 'm')
					op->type = R_ANAL_OP_TYPE_JMP;
				else
					op->type = R_ANAL_OP_TYPE_CJMP;
				break;
			case 'g':
				op->type = R_ANAL_OP_TYPE_IO;
				break;
			case 'p':
				if(aop->buf_asm[1] == 'o') {
					op->type = R_ANAL_OP_TYPE_POP;
				} else {
					if(aop->buf_asm[2] == 's')
						op->type = R_ANAL_OP_TYPE_PUSH;
					else
						op->type = R_ANAL_OP_TYPE_IO;
				}
				break;
			case 's':
				switch (aop->buf_asm[1]) {
					case 'u':
						op->type = R_ANAL_OP_TYPE_SUB;
						break;
					case 't':
						op->type = R_ANAL_OP_TYPE_STORE;
						break;
					case 'l':
						op->type = R_ANAL_OP_TYPE_LOAD;			// XXX
						break;
					case 'w':
						op->type = R_ANAL_OP_TYPE_ROR;
				}
				break;
		}
	}
	r_asm_op_free(aop);
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_ws = {
	.name = "ws",
	.desc = "Space, tab and linefeed analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_BF,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &ws_anal,
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
	.data = &r_anal_plugin_ws
};
#endif
