/* radare2 - LGPL - Copyright 2014-2022 - pancake */

#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "disas-asm.h"

int print_insn_big_nios2(bfd_vma address, disassemble_info *info);
int print_insn_little_nios2(bfd_vma address, disassemble_info *info);

static int nios2_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
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

static int disassemble(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = "";
	disasm_obj.buffer = buf;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &nios2_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !a->config->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;

	if (disasm_obj.endian == BFD_ENDIAN_BIG) {
		op->size = print_insn_big_nios2 ((bfd_vma)addr, &disasm_obj);
	} else {
		op->size = print_insn_little_nios2 ((bfd_vma)addr, &disasm_obj);
	}
	if (op->size == -1) {
		op->mnemonic = strdup ("(data)");
		r_strbuf_free (sb);
	} else {
		op->mnemonic = r_strbuf_drain (sb);
	}
	return op->size;
}

static int nios2_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len, RAnalOpMask mask) {
	if (!op) {
		return 1;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		disassemble (anal, op, addr, b, len);
	}
	op->size = 4;

	if ((b[0] & 0xff) == 0x3a) {
		// XXX
		op->type = R_ANAL_OP_TYPE_RET;
	} else if ((b[0] & 0xf) == 0xa) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else if ((b[0] & 0xf) == 4) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else if ((b[0] & 0xf) == 5) {
		op->type = R_ANAL_OP_TYPE_STORE;
	} else if ((b[0] & 0xf) == 6) {
		// blt, r19, r5, 0x8023480
		op->type = R_ANAL_OP_TYPE_CJMP;
		// TODO: address
	} else if ((b[0] & 0xf) == 7) {
		// blt, r19, r5, 0x8023480
		op->type = R_ANAL_OP_TYPE_LOAD;
		// TODO: address
	} else {
		switch (b[0]) {
		case 0x3a:
			if (b[1] >= 0xa0 && b[1] <= 0xaf && b[3] == 0x3d) {
				op->type = R_ANAL_OP_TYPE_TRAP;
			} else if ((b[1] >= 0xe0 && b[1] <= 0xe7) && b[2] == 0x3e && !b[3]) {
				// nextpc ra
				op->type = R_ANAL_OP_TYPE_RET;
			}
			break;
		case 0x01:
			// jmpi
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case 0x00:
		case 0x20:
		case 0x40:
		case 0x80:
		case 0xc0:
			//
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case 0x26:
			// beq
			break;
		case 0x07:
		case 0x47:
		case 0x87:
		case 0xc7:
			// ldb
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x0d:
		case 0x2d:
		case 0x4d:
		case 0x8d:
		case 0xcd:
			// sth && sthio
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x06:
		case 0x46:
		case 0x86:
		case 0xc6:
			// br
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		}
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_nios2 = {
	.name = "nios2",
	.desc = "NIOS II code analysis plugin",
	.license = "LGPL3",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.arch = "nios2",
	.esil = false,
	.bits = 32,
	.op = &nios2_op,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_nios2,
	.version = R2_VERSION
};
#endif
