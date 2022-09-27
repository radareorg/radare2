/* radare2 - LGPL - Copyright 2014-2022 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "disas-asm.h"
#if 0

Documentation
-------------
http://developer.axis.com/old/documentation/hw/etraxfs/des_ref/des_ref.pdf
http://developer.axis.com/old/documentation/hw/etraxfs/iop_howto/iop_howto.pdf

#endif

static int cris_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 8) {
		return -1;
	}
	const ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

bfd_boolean cris_parse_disassembler_options(disassemble_info *info, int distype);

// TODO: refactor the gnu code to have a getter instead of exposing so many disasm entrypoints
int print_insn_crisv10_v32_with_register_prefix(bfd_vma vma, disassemble_info *info);
int print_insn_crisv10_v32_without_register_prefix(bfd_vma vma, disassemble_info *info);
int print_insn_cris_with_register_prefix(bfd_vma vma, disassemble_info *info);
int print_insn_cris_without_register_prefix(bfd_vma vma, disassemble_info *info);
int print_insn_crisv32_with_register_prefix(bfd_vma vma, disassemble_info *info);
int print_insn_crisv32_without_register_prefix(bfd_vma vma, disassemble_info *info);

static char *disassemble(RAnal *a, RAnalOp *op, const ut8 *buf, int len) {
	ut8 bytes[8] = { 0 };
	struct disassemble_info disasm_obj;
	int mode = 2;
	if (len < 4) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	const ut64 addr = op->addr;
	memcpy (bytes, buf, R_MIN (len, 8)); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = (a->config->bits == 64)?"64":"";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &cris_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	disasm_obj.buffer_vma = op->addr;

	const char *cpu = a->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		// enum cris_disass_family { cris_dis_v0_v10, cris_dis_common_v10_v32, cris_dis_v32 };
		// 0: v0-v10
		// 1: v10-v32
		// 2: v32
		mode = 0;
		if (strstr (cpu,  "v10")) {
			mode = 1;
		}
		if (strstr (cpu,  "v32")) {
			mode = 2;
		}
	} else {
		mode = 2;
	}
	(void)cris_parse_disassembler_options (&disasm_obj, mode);
	if (a->config->syntax == R_ARCH_SYNTAX_ATT) {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_with_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_with_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		default:
			op->size = print_insn_crisv32_with_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		}
	} else {
		switch (mode) {
		case 0:
			op->size = print_insn_cris_without_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		case 1:
			op->size = print_insn_crisv10_v32_without_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		default:
			op->size = print_insn_crisv32_without_register_prefix ((bfd_vma)addr, &disasm_obj);
			break;
		}
	}
	if (op->size == -1) {
		r_strbuf_set (sb, "(data)");
	}
	return r_strbuf_drain (sb);
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int opsize = -1;
	op->type = -1;
	opsize = 2;
	if (len < 1) {
		return -1;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->addr = addr;
		op->mnemonic = disassemble (a, op, buf, len);
		if (!op->mnemonic) {
			op->mnemonic = strdup ("invalid");
		}
	}
	switch (buf[0]) {
	case 0x3f:
	case 0x4f:
		op->type = R_ANAL_OP_TYPE_MOV;
		opsize = 4;
		break;
	case 0x6f:
		op->type = R_ANAL_OP_TYPE_MOV;
		opsize = 6;
		break;
	case 0x7f:
		op->type = R_ANAL_OP_TYPE_LEA;
		if (len > 5) {
			op->ptr = buf[2];
			op->ptr |= buf[3] << 8;
			op->ptr |= buf[4] << 16;
			op->ptr |= ((ut32)(0xff & buf[5])) << 24;
			op->ptr += addr;
			opsize = 6;
		} else {
			// error
			op->ptr = UT64_MAX;
		}
		break;
	case 0xbf: // bsr
		op->type = R_ANAL_OP_TYPE_CALL;
		if (len > 5) {
			st32 delta = buf[2];
			delta |= buf[3] << 8;
			delta |= buf[4] << 16;
			delta |= buf[5] << 24;
			op->jump = addr + delta;
		} else {
			op->jump = UT64_MAX;
		}
		op->fail = addr + 6;
		opsize = 6;
		break;
	case 0x00:
		if (len < 2) {
			break;
		}
		if (buf[1] == 0x00) {
			op->type = R_ANAL_OP_TYPE_TRAP;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			{
				st8 delta = buf[0];
				op->jump = addr + delta;
			}
		}
		break;
	case 0xf0:
		if (len < 2) {
			break;
		}
		if (buf[1] == 0xb9) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
		break;
	default:
		if (len < 2) {
			break;
		}
		switch (buf[1]) {
		case 0x00:
			op->type = R_ANAL_OP_TYPE_CJMP; // BCC
			break;
		case 0xf3:
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case 0x96: // move.d r, r
			if (buf[0] >= 0xc0) {
				op->type = R_ANAL_OP_TYPE_CMP;
			} else {
				op->type = R_ANAL_OP_TYPE_MOV;
			}
			break;
		case 0xf2:
		case 0x0b:
		case 0x72:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 0x05:
			if (buf[0] == 0xb0) {
				op->type = R_ANAL_OP_TYPE_NOP;
			}
			break;
		case 0x01:
		case 0x02:
		case 0xc2:
		case 0xf5:
		case 0x91:
		case 0x41:
		case 0x61:
		case 0x65:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x12:
		case 0xf6:
		case 0xe2:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0x82: // moveq i, r
		case 0xba: // move.d [r], r
		case 0xeb: // move.d r, [r]
		case 0xc6: // move.d r, r
		case 0x92: // moveq i, r
		case 0x9b: // move.d i, r
		case 0xbe: // move [sp+], srp
		case 0x06:
		case 0x26:
		case 0xfb:
		case 0x9a:
		case 0xb2:
		case 0xda:
		case 0x2b:
		case 0x6f:
		case 0xa2:
		case 0x2f:
		case 0x8b:
		case 0x1b:
		case 0xaa:
		case 0xa6:
		case 0xb6:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 0xe0:
			op->type = R_ANAL_OP_TYPE_JMP;
			{
				st8 delta = buf[0];
				op->jump = addr + delta;
			}
			break;
		case 0x10:
		case 0x30:
		case 0x20:
		case 0x2d:
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + buf[0];
			op->fail = addr + 2; // delay slot here?
			break;
		case 0xbf:
			op->type = R_ANAL_OP_TYPE_CALL; // bsr
			break;
		case 0xb9:
			op->type = R_ANAL_OP_TYPE_UJMP; // jsr reg
			break;
		}
	}
#if 0
	switch (*buf) {
	case 0x3f: // adds.w N, R
		opsize = 4;
	case 0x01:
	case 0x53: // addi, acr.w, r3, acr
	case 0x04:
	case 0x61:
	case 0x62:
	case 0x63:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x88:
	case 0x84:
	case 0x81:
	case 0x8c:
	case 0xad:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x7f: // lapc <addr>, <reg>
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
	case 0xcf:
	case 0xbe:
	case 0x60:
	case 0x6f:
	case 0x6a: // move.d reg, reg
	case 0x7e:
	case 0xfe:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x00:
		op->type = R_ANAL_OP_TYPE_JMP;
		// jsr acr
		break;
	case 0xff:
		opsize = 6;
	case 0x14:
	case 0x0e:
	case 0x1a:
	case 0x9c:
	case 0x6d: // bne
		op->type = R_ANAL_OP_TYPE_CJMP;
		// jsr acr
		break;
	case 0xbf:
		opsize = 6;
	case 0xb1:
	case 0xb2:
	case 0xb3:
	case 0xb4:
	case 0xb5:
	case 0xb6:
	case 0xb7:
	case 0xb8:
	case 0xb9:
		op->type = R_ANAL_OP_TYPE_UJMP;
		// jsr acr
		break;
	case 0x8f: // test.b [acr]
	case 0xc0:
	case 0xe1:
	case 0xaa:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	default:
		switch (*w) {
		case 0xb0b9: //// jsr r0
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 0xb005:
		case 0x05b0:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 0xf0b9:
		case 0xb9f0:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		}
	}
#endif
	op->size = opsize;
	//op->delay = 1;
	return opsize;
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pc\n"
		"=SP	r14\n" // XXX
		"=BP	srp\n" // XXX
		"=SN	r0\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"gpr	sp	.32	56	0\n" // r14
		"gpr	acr	.32	60	0\n" // r15
		"gpr	pc	.32	64	0\n" // r16 // out of context
		"gpr	srp	.32	68	0\n" // like rbp on x86 // out of context
		// GPR
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"

		// STACK POINTER
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
		// ADD P REGISTERS
		;
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_cris = {
	.name = "cris",
	.desc = "Axis Communications 32-bit embedded processor",
	.license = "LGPL3",
	.esil = false,
	.arch = "cris",
	.set_reg_profile = set_reg_profile,
	.bits = 32,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_cris,
	.version = R2_VERSION
};
#endif
