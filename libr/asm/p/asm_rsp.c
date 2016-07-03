/* radare - LGPL - Copyright 2016 - bobby.smiles32@gmail.com */
// TODO: add assembler

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>

#include <stdarg.h>
#include <stdio.h>

#include "rsp_idec.h"


static void snappendf(char** dst, size_t* size, const char* format, ...) {
	size_t n;
	va_list va;

	va_start (va, format);
	n = vsnprintf (*dst, *size, format, va);

	*dst += n;
	*size -= n;

	va_end (va);
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut32 iw;
	rsp_instruction r_instr;
	int i;
	char* buffer;
	size_t size;

	/* all instructions are 32bit words */
	if (len < 4) {
		op->size = 0;
		return 0;
	}
	op->size = 4;

	iw = r_read_ble32 (buf, a->big_endian);
	r_instr = rsp_instruction_decode (a->pc, iw);

	buffer = op->buf_asm;
	size = sizeof (op->buf_asm);

	snappendf (&buffer, &size, r_instr.mnemonic);
	for (i = 0; i < r_instr.noperands; ++i) {
		snappendf (&buffer, &size, "%s", (i == 0) ? " " : ", ");

		switch (r_instr.operands[i].type) {
		case RSP_OPND_GP_REG:
			snappendf (&buffer, &size, "%s", rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_OFFSET:
		case RSP_OPND_TARGET:
			snappendf (&buffer, &size, "0x%08x", r_instr.operands[i].u);
			break;
		case RSP_OPND_ZIMM:
			snappendf (&buffer, &size, "0x%04x", r_instr.operands[i].u >> ((r_instr.operands[i].u & ~0xffff) ? 16 : 0));
			break;
		case RSP_OPND_SIMM:
			snappendf (&buffer, &size, "%s0x%04x",
			(r_instr.operands[i].s<0)?"-":"",
			(r_instr.operands[i].s<0)?-r_instr.operands[i].s:r_instr.operands[i].s);
			break;
		case RSP_OPND_SHIFT_AMOUNT:
			snappendf (&buffer, &size, "%u", r_instr.operands[i].u);
			break;
		case RSP_OPND_BASE_OFFSET:
			snappendf (&buffer, &size, "%s0x%04x(%s)",
			(r_instr.operands[i].s<0)?"-":"",
			(r_instr.operands[i].s<0)?-r_instr.operands[i].s:r_instr.operands[i].s,
			rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C0_REG:
			snappendf (&buffer, &size, "%s", rsp_c0_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_CREG:
			snappendf (&buffer, &size, "%s", rsp_c2_creg_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_ACCU:
			snappendf (&buffer, &size, "%s", rsp_c2_accu_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG:
			snappendf (&buffer, &size, "%s", rsp_c2_vreg_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG_BYTE:
		case RSP_OPND_C2_VREG_SCALAR:
			snappendf (&buffer, &size, "%s[%u]", rsp_c2_vreg_names[r_instr.operands[i].u], r_instr.operands[i].s);
			break;
		case RSP_OPND_C2_VREG_ELEMENT:
			snappendf (&buffer, &size, "%s%s", rsp_c2_vreg_names[r_instr.operands[i].u], rsp_c2_vreg_element_names[r_instr.operands[i].s]);
			break;
		default: /* should not happend */
			snappendf (&buffer, &size, "???");
			break;
		}
	}

	return op->size;
}

RAsmPlugin r_asm_plugin_rsp = {
	.name = "rsp",
	.desc = "Reality Signal Processor",
	.arch = "rsp",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BI, /* For conveniance, we don't force BIG endian but allow both to be used */
	.license = "LGPL3",
	.disassemble = &disassemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_rsp,
	.version = R2_VERSION
};
#endif
