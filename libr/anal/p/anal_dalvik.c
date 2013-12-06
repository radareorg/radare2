/* radare - LGPL - Copyright 2010 */

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../asm/arch/dalvik/opcode.h"

static int dalvik_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int sz = 1;

	sz = dalvik_opcodes[data[0]].len;
	if (op == NULL)
		return sz;

	memset (op, '\0', sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = sz;
	op->nopcode = 1; // Necesary??

	switch(data[0]) {
	case 0x0e: // return-void
	case 0x0f: // return
	case 0x10: // return-wide
	case 0x11: // return-object
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob  = 1;
		break;
	case 0x28: // goto
		op->jump = addr + ((char)data[1])*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob  = 1;
		break;
	case 0x29: // goto/16
		op->jump = addr + (short)(data[2]|data[3]<<8)*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob  = 1;
		break;
	case 0x2a: // goto/32
		op->jump = addr + (int)(data[2]|(data[3]<<8)|(data[4]<<16)|(data[5]<<24))*2;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->eob  = 1;
		break;
	case 0x2d: // cmpl-float
	case 0x2e: // cmpg-float
	case 0x2f: // cmpl-double
	case 0x30: // cmlg-double
	case 0x31: // cmp-long
	case 0x32: // if-eq
	case 0x33: // if-ne
	case 0x34: // if-lt
	case 0x35: // if-ge
	case 0x36: // if-gt
	case 0x37: // if-le
	case 0x38: // if-eqz
	case 0x39: // if-nez
	case 0x3a: // if-ltz
	case 0x3b: // if-gez
	case 0x3c: // if-gtz
	case 0x3d: // if-lez
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + (short)(data[2]|data[3]<<8)*2;
		op->fail = addr + sz;
		op->eob = 1;
		break;
	case 0xec: // breakpoint
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
/* JAVA
	case 0xa8: // jsr
	case 0xc9: // jsr_w
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = 0x0; // TODO
		op->fail = addr + sz;
		op->eob = 1;
		break;
	case 0xb9: // invokeinterface
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb6: // invokevirtual
	case 0xbb: // new
	case 0xbc: // newarray
	case 0xc5: // multi new array
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
*/
	case 0x27: // throw
	case 0xed: // throw-verification-error
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0x00: // nop
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
/* JAVA
	case 0xba:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case 0x57: // pop
	case 0x58: // pop2
		op->type = R_ANAL_OP_TYPE_POP;
		break;
	case 0x10: // bipush
	case 0x11: // sipush
	case 0x59: // dup
	case 0x5a: // dup_x1
	case 0x5b: // dup_x2
	case 0x5c: // dup2
	case 0x5d: // dup2_x1
	case 0x5e: // dup2_x2
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
*/
	case 0x90: // add-int
	case 0x9b: // add-long
	case 0xa6: // add-float
	case 0xac: // add-double
	case 0xb0: // add-int/2addr
	case 0xbb: // add-long/2addr
	case 0xc6: // add-float/2addr
	case 0xcb: // add-double/2addr
	case 0xd0: // add-int/lit16
	case 0xd8: // add-int/lit8
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
/* TODO JAVA
	case 0x64: // isub
	case 0x65: // lsub
	case 0x66: // fsub
	case 0x67: // dsub
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
*/
	case 0x7b: // neg-int
	case 0x7d: // neg-long
	case 0x7f: // neg-float
	case 0x80: // neg-double
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
/* TODO JAVA
	case 0x78: //ishl
	case 0x79: //lshl
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case 0x7a: //ishr
	case 0x7b: //lshr
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x80: // ior
	case 0x81: // lor
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x82: // ixor
	case 0x83: // lxor
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x7e: // iand
	case 0x7f: // land
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x68: // imul
	case 0x69: // lmul
	case 0x6a: // fmul
	case 0x6b: // dmul
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case 0x6c: // idiv
	case 0x6d: // ldiv
	case 0x6e: // fdiv
	case 0x6f: // ddiv
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
*/
	}

	return sz;
}

struct r_anal_plugin_t r_anal_plugin_dalvik = {
	.name = "dalvik",
	.arch = R_SYS_ARCH_DALVIK,
	.license = "LGPL3",
	.bits = 32,
	.desc = "Dalvik (Android VM) bytecode analysis plugin",
	.init = NULL,
	.fini = NULL,
	.op = &dalvik_op,
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
	.data = &r_anal_plugin_dalvik
};
#endif
