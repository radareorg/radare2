/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "udis86/types.h"
#include "udis86/extern.h"

// TODO : split into get/set... we need a way to create binary masks from asm buffers
// -- move this shit into r_anal.. ??
// -- delta, size, mode.. mode is for a->pc-5, register handling and things like this
static int modify(RAsm *a, ut8 *buf, int field, ut64 val) {
	ut32 val32 = (ut32)val;
	switch (buf[0]) {
	case 0x68: // push dword 
		if (field == R_ASM_MOD_RAWVALUE || field == R_ASM_MOD_VALUE) {
			memcpy (buf+1, &val, sizeof (val32));
		}
		return 5;
	case 0xe8: // call
		if (field == R_ASM_MOD_RAWVALUE) {
			memcpy (buf+1, &val32, sizeof (val32));
		} else
		if (field == R_ASM_MOD_VALUE) {
			val32 = (ut32)(val-a->pc-5);
			memcpy (buf+1, &val32, sizeof (val32));
		}
		return 5;
	case 0xeb: // jmp short
	case 0x73: // jnz
		if (field == R_ASM_MOD_RAWVALUE) {
			buf[1] = (char)val;
		} else
		if (field == R_ASM_MOD_VALUE) {
			buf[1] = (char)(val-a->pc);
		}
		return 2;
	}
	return 0;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int opsize;
	static ud_t d = {0};
	static int osyntax = 0;
	if (!d.dis_mode)
		ud_init (&d);
	if (osyntax != a->syntax) {
		ud_set_syntax (&d, (a->syntax==R_ASM_SYNTAX_ATT)?
				UD_SYN_ATT: UD_SYN_INTEL);
		osyntax = a->syntax;
	}
	ud_set_input_buffer (&d, (uint8_t*) buf, len);
	ud_set_pc (&d, a->pc);
	ud_set_mode (&d, a->bits);
	opsize = ud_disassemble (&d);
	strncpy (op->buf_asm, ud_insn_asm (&d), R_ASM_BUFSIZE-1);
	op->buf_asm[R_ASM_BUFSIZE-1] = 0;
	if (opsize<1 || strstr (op->buf_asm, "invalid"))
		opsize = 0;
	op->size = opsize;
	if (a->syntax == R_ASM_SYNTAX_JZ) {
		if (!strncmp (op->buf_asm, "je ", 3)) {
			memcpy (op->buf_asm, "jz", 2);
		} else if (!strncmp (op->buf_asm, "jne ", 4)) {
			memcpy (op->buf_asm, "jnz", 3);
		}
	}
	return opsize;
}

RAsmPlugin r_asm_plugin_x86_udis = {
	.name = "x86.udis",
	.desc = "udis86 x86-16,32,64",
	.arch = "x86",
	.license = "BSD",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.modify = &modify,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_udis,
	.version = R2_VERSION
};
#endif
