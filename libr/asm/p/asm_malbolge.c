#include <r_asm.h>
#include <r_types.h>
#include <r_lib.h>
#include <string.h>

static int mal_dis(RAsmOp *op, ut64 c, const ut8 *buf, ut64 len) {
	if(len) {
		switch ((buf[0]+c)%94) {
			case 4:
				sprintf(op->buf_asm, "jmp [d]");
				break;
			case 5:
				sprintf(op->buf_asm, "out a");
				break;
			case 23:
				sprintf(op->buf_asm, "in a");
				break;
			case 39:
				sprintf(op->buf_asm, "rotr [d], mov a, [d]");
				break;
			case 40:
				sprintf(op->buf_asm, "mov d, [d]");
				break;
			case 62:
				sprintf(op->buf_asm, "crz [d], a, mov a, [d]");
				break;
			case 81:
				sprintf(op->buf_asm, "end");
				break;
			default:
				sprintf(op->buf_asm, "nop");
		}
		return R_TRUE;
	}
	return R_FALSE;
}

static int __disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = mal_dis(op, a->pc, buf, len);
}

RAsmPlugin r_asm_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge Ternary VM",
	.arch = "malbolge",
	.license = "LGPL3",
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.disassemble = &__disassemble,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_malbolge
};
#endif
