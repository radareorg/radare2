/* radare2 - LGPL - Copyright 2014-2024 - pancake */

#include <r_asm.h>
#include <r_anal.h>
#include "../../include/disas-asm.h"

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

static int disassemble(RArchSession *session, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut8 bytes[8] = {0};
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	memcpy (bytes, buf, R_MIN (len, sizeof (bytes)));

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = "";
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &nios2_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (session->config);
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

static bool decode(RArchSession *session, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *b = op->bytes;
	const size_t len = op->size;

	if (op->size < 4) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			free (op->mnemonic);
			op->mnemonic = strdup ("truncated");
		}
		op->type = R_ANAL_OP_TYPE_ILL;
		return false;
	}
	disassemble (session, op, addr, b, len);
	op->size = 4;
	if (op->mnemonic && r_str_startswith (op->mnemonic, "0x")) {
		op->type = R_ANAL_OP_TYPE_ILL;
		free (op->mnemonic);
		op->mnemonic = strdup ("invalid");
		return false;
	}

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
	return true;
}

static char *regs(RArchSession *as) {
	 const char *const p = \
	       // XXX aliases not verified
		 "=PC	r31\n"
		 "=A0	r0\n"
		 "=A1	r1\n"
		 "=A2	r2\n"
		 "=A3	r3\n"
		 "=A4	r4\n"
		 "=A5	r5\n"
		 "=A6	r6\n"
		 "=A7	r7\n"
		 "=R0	r0\n"
		 "=R1	r1\n"
		 "=SP	r30\n"
		 "=LR	r29\n"
		 "=BP	r28\n"
		 "=SN	a0\n"
		 "gpr	pc	.32	0	0\n"
		 "gpr	r0	.32	4	0\n"
		 "gpr	r1	.32	8	0\n"
		 "gpr	r2	.32	12	0\n"
		 "gpr	r3	.32	16	0\n"
		 "gpr	r4	.32	20	0\n"
		 "gpr	r5	.32	24	0\n"
		 "gpr	r6	.32	28	0\n"
		 "gpr	r7	.32	32	0\n"
		 "gpr	r8	.32	36	0\n"
		 "gpr	r9	.32	40	0\n"
		 "gpr	r10	.32	44	0\n"
		 "gpr	r11	.32	48	0\n"
		 "gpr	r12	.32	52	0\n"
		 "gpr	r13	.32	56	0\n"
		 "gpr	r14	.32	60	0\n"
		 "gpr	r15	.32	64	0\n"
		 "gpr	r16	.32	68	0\n"
		 "gpr	r17	.32	72	0\n"
		 "gpr	r18	.32	76	0\n"
		 "gpr	r19	.32	80	0\n"
		 "gpr	r20	.32	84	0\n"
		 "gpr	r21	.32	88	0\n"
		 "gpr	r22	.32	92	0\n"
		 "gpr	r23	.32	96	0\n"
		 "gpr	r24	.32	100	0\n"
		 "gpr	r25	.32	104	0\n"
		 "gpr	r26	.32	108	0\n"
		 "gpr	r27	.32	112	0\n"
		 "gpr	r28	.32	116	0\n"
		 "gpr	r29	.32	120	0\n"
		 "gpr	r30	.32	124	0\n"
		 "gpr	r31	.32	128	0\n"
		 ;
	 return strdup (p);
}

static int info(RArchSession *s, ut32 q) {
	return 4;
}

const RArchPlugin r_arch_plugin_nios2 = {
	.meta = {
		.name = "nios2",
		.desc = "Intel Altera NIOS II FPGA",
		.license = "LGPL-3.0-only",
	},
	.arch = "nios2",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.info = info,
	.regs = regs,
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_nios2,
	.version = R2_VERSION
};
#endif
