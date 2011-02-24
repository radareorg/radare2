/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "x86/udis86/types.h"
#include "x86/udis86/extern.h"

// TODO : split into get/set... we need a way to create binary masks from asm buffers
// -- move this shit into r_anal.. ??
// -- delta, size, mode.. mode is for a->pc-5, register handling and things like this
static int modify(RAsm *a, ut8 *buf, int field, ut64 val) {
	ut32 val32 = (ut32)val;
	int ret = R_FALSE;
	
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
	return ret;
}

static int disassemble(RAsm *a, RAsmOp *op, ut8 *buf, ut64 len) {
	static ud_t disasm_obj;

	ud_init (&disasm_obj);
	if (a->syntax == R_ASM_SYNTAX_ATT)
		ud_set_syntax (&disasm_obj, UD_SYN_ATT);
	else ud_set_syntax (&disasm_obj, UD_SYN_INTEL);
	ud_set_mode (&disasm_obj, a->bits);
	ud_set_pc (&disasm_obj, a->pc);
	ud_set_input_buffer (&disasm_obj, buf, len);
	ud_disassemble (&disasm_obj);
	op->inst_len = ud_insn_len (&disasm_obj);
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", ud_insn_asm (&disasm_obj));

	return op->inst_len;
}

RAsmPlugin r_asm_plugin_x86 = {
	.name = "x86",
	.desc = "udis86 disassembly plugin",
	.arch = "x86",
	.bits = (int[]){ 16, 32, 64, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = &modify,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86
};
#endif
