/* radare - LGPL - Copyright 2016 - bobby.smiles32@gmail.com */
// TODO: add assembler

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>

#include <stdarg.h>
#include <stdio.h>

#include "rsp_idec.h"


static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	rsp_instruction r_instr;
	int i;

	/* all instructions are 32bit words */
	if (len < 4) {
		op->size = 0;
		return 0;
	}
	op->size = 4;

	ut32 iw = r_read_ble32 (buf, a->config->big_endian);
	r_instr = rsp_instruction_decode (a->pc, iw);

	r_strbuf_append (&op->buf_asm, r_instr.mnemonic);
	for (i = 0; i < r_instr.noperands; i++) {
		r_strbuf_append (&op->buf_asm, (i == 0) ? " " : ", ");

		switch (r_instr.operands[i].type) {
		case RSP_OPND_GP_REG:
			r_strbuf_append (&op->buf_asm, rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_OFFSET:
		case RSP_OPND_TARGET:
			r_strbuf_appendf (&op->buf_asm, "0x%08"PFMT64x, r_instr.operands[i].u);
			break;
		case RSP_OPND_ZIMM:
			{
			int shift = (r_instr.operands[i].u & ~0xffff) ? 16 : 0;
			r_strbuf_appendf (&op->buf_asm, "0x%04"PFMT64x,
				r_instr.operands[i].u >> shift);
			}
			break;
		case RSP_OPND_SIMM:
			r_strbuf_appendf (&op->buf_asm, "%s0x%04"PFMT64x,
			(r_instr.operands[i].s<0)?"-":"",
			(r_instr.operands[i].s<0)?-r_instr.operands[i].s:r_instr.operands[i].s);
			break;
		case RSP_OPND_SHIFT_AMOUNT:
			r_strbuf_appendf (&op->buf_asm, "%"PFMT64u, r_instr.operands[i].u);
			break;
		case RSP_OPND_BASE_OFFSET:
			r_strbuf_appendf (&op->buf_asm, "%s0x%04x(%s)",
			(r_instr.operands[i].s<0)?"-":"",
			(ut32)((r_instr.operands[i].s<0)?-r_instr.operands[i].s:r_instr.operands[i].s),
			rsp_gp_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C0_REG:
			r_strbuf_append (&op->buf_asm, rsp_c0_reg_soft_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_CREG:
			r_strbuf_append (&op->buf_asm, rsp_c2_creg_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_ACCU:
			r_strbuf_append (&op->buf_asm, rsp_c2_accu_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG:
			r_strbuf_append (&op->buf_asm, rsp_c2_vreg_names[r_instr.operands[i].u]);
			break;
		case RSP_OPND_C2_VREG_BYTE:
		case RSP_OPND_C2_VREG_SCALAR:
			r_strbuf_appendf (&op->buf_asm, "%s[%u]", rsp_c2_vreg_names[r_instr.operands[i].u],
				(ut32)r_instr.operands[i].s);
			break;
		case RSP_OPND_C2_VREG_ELEMENT:
			r_strbuf_appendf (&op->buf_asm, "%s%s", rsp_c2_vreg_names[r_instr.operands[i].u], rsp_c2_vreg_element_names[r_instr.operands[i].s]);
			break;
		default: /* should not happend */
			r_strbuf_append (&op->buf_asm, "???");
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_rsp,
	.version = R2_VERSION
};
#endif
