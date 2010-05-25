/* radare - LGPL - Copyright 2010 */
/*   pancake<nopcode.org> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "../../asm/arch/java/javasm/javasm.h"

/* code analysis functions */

/* arch_aop for java */
// CMP ARG1
// 837d0801        cmp dword [ebp+0x8], 0x1
// SET VAR_41c
// 8985e4fbffff    mov [ebp-41C],eax 
// GET VAR_41c
// 8b85e4fbffff    mov eax,[ebp-41C]
// 8b450c          mov eax,[ebp+C] 
// 8d85e8fbffff    lea eax,[ebp-418]
// c68405e7fbffff. mov byte ptr [ebp+eax-419],0x0

// NOTE: buf should be at least 16 bytes!
// XXX addr should be off_t for 64 love
static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *data, int len) {
	unsigned int i;
	int sz = 1;

	/* get opcode size */
	for(i = 0;java_ops[i].name != NULL;i++)
		if (data[0] == java_ops[i].byte)
			sz = java_ops[i].size;

	if (aop == NULL)
		return sz;

	memset (aop, '\0', sizeof (RAnalOp));
	aop->type = R_ANAL_OP_TYPE_UNK;
	aop->length = sz;

	switch(data[0]) {
	case 0xa9: // ret
	case 0xb1: // return
	case 0xb0: // areturn
	case 0xaf: // dreturn
	case 0xae: // freturn
	case 0xac: // ireturn
	case 0xad: // lreturn
		aop->type = R_ANAL_OP_TYPE_RET;
		aop->eob  = 1;
		break;
	case 0xa7: // goto
	case 0xc8: // goto_w
		aop->type = R_ANAL_OP_TYPE_JMP;
		aop->jump = 0; // TODO
		aop->eob  = 1;
		break;
	case 0xa5: // acmpeq
	case 0xa6: // acmpne
	case 0x9f: // icmpeq
	case 0xa0: // icmpne
	case 0xa1: // icmplt
	case 0xa2: // icmpge
	case 0xa3: // icmpgt
	case 0xa4: // icmple
	case 0x99: // ifeq
	case 0x9a: // ifne
	case 0x9b: // iflt
	case 0x9c: // ifge
	case 0x9d: // ifgt
	case 0x9e: // ifle
	case 0xc7: // ifnonnull
	case 0xc6: // ifnull
		aop->type = R_ANAL_OP_TYPE_CJMP;
		aop->jump = 0x0; // TODO
		aop->fail = addr + sz;
		aop->eob = 1;
		break;
	case 0xa8: // jsr
	case 0xc9: // jsr_w
		aop->type = R_ANAL_OP_TYPE_CALL;
		aop->jump = 0x0; // TODO
		aop->fail = addr + sz;
		aop->eob = 1;
		break;
	case 0xb9: // invokeinterface
	case 0xb7: // invokespecial
	case 0xb8: // invokestatic
	case 0xb6: // invokevirtual
	case 0xbb: // new
	case 0xbc: // newarray
	case 0xc5: // multi new array
		aop->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 0xca: // breakpoint
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case 0xbf: // athrow
		aop->type = R_ANAL_OP_TYPE_TRAP;
		break;
	case 0x00: // nop
		aop->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0xba:
		aop->type = R_ANAL_OP_TYPE_ILL;
		break;
	case 0x57: // pop
	case 0x58: // pop2
		aop->type = R_ANAL_OP_TYPE_POP;
		break;
	case 0x10: // bipush
	case 0x11: // sipush
	case 0x59: // dup
	case 0x5a: // dup_x1
	case 0x5b: // dup_x2
	case 0x5c: // dup2
	case 0x5d: // dup2_x1
	case 0x5e: // dup2_x2
		aop->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case 0x60: // iadd
	case 0x61: // ladd
	case 0x62: // fadd
	case 0x63: // dadd
		aop->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x64: // isub
	case 0x65: // lsub
	case 0x66: // fsub
	case 0x67: // dsub
		aop->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x76: // neg
		aop->type = R_ANAL_OP_TYPE_NOT;
		break;
	case 0x78: //ishl
	case 0x79: //lshl
		aop->type = R_ANAL_OP_TYPE_SHL;
		break;
	case 0x7a: //ishr
	case 0x7b: //lshr
		aop->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x80: // ior
	case 0x81: // lor
		aop->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x82: // ixor
	case 0x83: // lxor
		aop->type = R_ANAL_OP_TYPE_XOR;
		break;
	case 0x7e: // iand
	case 0x7f: // land
		aop->type = R_ANAL_OP_TYPE_AND;
		break;
	case 0x68: // imul
	case 0x69: // lmul
	case 0x6a: // fmul
	case 0x6b: // dmul
		aop->type = R_ANAL_OP_TYPE_MUL;
		break;
	case 0x6c: // idiv
	case 0x6d: // ldiv
	case 0x6e: // fdiv
	case 0x6f: // ddiv
		aop->type = R_ANAL_OP_TYPE_DIV;
		break;
	}

	return sz;
}

struct r_anal_plugin_t r_anal_plugin_java = {
	.name = "java",
	.desc = "Java bytecode analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_java
};
#endif
