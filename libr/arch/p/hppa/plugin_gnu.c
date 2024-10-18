/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_asm.h>
#include "../../include/disas-asm.h"

static int hppa_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	ut8 *bytes = info->buffer;
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

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
// static int hppa_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	const ut8 *buf = op->bytes;
	const int len = op->size;
	ut8 bytes[8] = {0};
	struct disassemble_info disasm_obj = {0};
	RStrBuf *sb = NULL;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}
	memcpy (bytes, buf, R_MIN (sizeof (bytes), len)); // TODO handle thumb

	/* prepare disassembler */
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = op->addr;
	disasm_obj.read_memory_func = &hppa_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_hppa ((bfd_vma)op->addr, &disasm_obj);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
		sb = NULL;
		r_str_replace_ch (op->mnemonic, '\t', ' ', true);
		switch (*op->mnemonic) {
		case 'a':
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 'b':
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 'c':
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 'l':
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 's':
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case '#':
			op->type = R_ANAL_OP_TYPE_ILL;
			free (op->mnemonic);
			op->mnemonic = strdup ("invalid");
			break;
		}
	} else {
		r_strbuf_free (sb);
	}
	return op->size;
}

static char *regs(RArchSession *s) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	ep\n"
		"=SN	r1\n"
		"=ZF	z\n"
		"=A0	r1\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	r0	.32	?   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	tp	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	psw .32 132 0\n" // program status word
		"gpr	npi  .1 132.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 132.17 0\n" // exception processing interrupt
		"gpr	id   .1 132.18 0\n" // :? should be id
		"gpr	sat  .1 132.19 0\n" // saturation detection
		"flg	cy  .1 132.28 0 carry\n" // carry or borrow
		"flg	ov  .1 132.29 0 overflow\n" // overflow
		"flg	s   .1 132.30 0 sign\n" // signed result
		"flg	z   .1 132.31 0 zero\n" // zero result
		;
	return strdup (p);
}

static int info(RArchSession *as, ut32 q) {
	return 4; /* :D */
}

const RArchPlugin r_arch_plugin_hppa_gnu = {
	.meta = {
		.name = "hppa",
		.author = "pancake",
		.license = "GPL-3.0-only",
		.desc = "HP PA-RISC",
	},
	.arch = "hppa",
	.bits = R_SYS_BITS_PACK1 (16),
	.endian = R_SYS_ENDIAN_BIG,
	.info = info,
	.regs = regs,
	.decode = &decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_hppa_gnu,
	.version = R2_VERSION
};
#endif
