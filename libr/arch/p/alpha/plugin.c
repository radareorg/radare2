/* radare - LGPL - Copyright 2015-2024 - pancake */

#include <r_asm.h>

#define BUFSZ 8
#include "../../include/disas-asm.h"
#include "opcode-alpha.h"

static int alpha_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	ut8 *bytes = info->buffer;
	int nlen = R_MIN (length, BUFSZ - delta);
	if (nlen > 0) {
		memcpy (myaddr, bytes + delta, nlen);
	}
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

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	ut8 bytes[BUFSZ] = {0};
	RStrBuf *sb = NULL;
	struct disassemble_info disasm_obj = {0};
	if (op->size < 4) {
		op->mnemonic = strdup ("truncated");
		return false;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		sb = r_strbuf_new (NULL);
	}
	memcpy (bytes, op->bytes, R_MIN (op->size, BUFSZ));
	/* prepare disassembler */
	disasm_obj.buffer = (ut8*)bytes;
	disasm_obj.buffer_vma = op->addr;
	disasm_obj.read_memory_func = &alpha_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = print_insn_alpha ((bfd_vma)op->addr, &disasm_obj);

	char *instr = sb? r_strbuf_drain (sb): NULL;
	if (instr && *instr == '.') {
		R_FREE (instr);
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 4;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		free (instr);
		return false;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->size > 0) {
			op->mnemonic = instr? instr: strdup ("");
			r_str_replace_char (op->mnemonic, '\t', ' ');
		} else {
			free (instr);
			op->mnemonic = strdup ("(data)");
		}
	} else {
		free (instr);
	}
	return true;
}

static char *regs(RArchSession *as) {
	const char *const p =
		"=PC    pc\n"
		"=SP    r30\n"
		"=BP    r28\n"
		"=RA    r28\n"
		"=GP    r29\n"
		"=A0    r15\n"
		"=A1    r16\n"
		"=A2    r17\n"
		"=A3    r18\n"
		"=SN    r15\n"
		"=R0    r0\n"
		"=R1    r1\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r1	.64	8	0\n"
		"gpr	r2	.64	16	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	r4	.64	32	0\n"
		"gpr	r5	.64	40	0\n"
		"gpr	r6	.64	48	0\n"
		"gpr	r7	.64	56	0\n"
		"gpr	r8	.64	64	0\n"
		"gpr	r9	.64	72	0\n"
		"gpr	r10 	.64	80	0\n"
		"gpr	r11 	.64	88	0\n"
		"gpr	r12 	.64	96	0\n"
		"gpr	r13 	.64	104	0\n"
		"gpr	r14 	.64	112	0\n"
		"gpr	r15 	.64	120	0\n"
		"gpr	r16	.64	128	0\n"
		"gpr	r17	.64	136	0\n"
		"gpr	r18	.64	144	0\n"
		"gpr	r19	.64	152	0\n"
		"gpr	r20 	.64	160	0\n"
		"gpr	r21 	.64	168	0\n"
		"gpr	r22 	.64	176	0\n"
		"gpr	r23	.64	184	0\n"
		"gpr	r24	.64	192	0\n"
		"gpr	r25 	.64	200	0\n"
		"gpr	r26	.64	208	0\n"
		"gpr	r27	.64	216	0\n"
		"gpr	r28	.64	224	0\n" // at
		"gpr	r29	.64	232	0\n" // gp
		"gpr	r30	.64	240	0\n" // sp
		"gpr	r31	.64	?0	0\n" // zero
		"gpr	pc	.64	256	0\n"
		"gpr	lr0	.64	264	0\n"
		"gpr	lr1	.64	272	0\n"
		"gpr	fpcr	.64	280	0\n"; // fpu control register
		// TODO: missing F0-F31 floating point registers!
	return strdup (p);
}

static int info(RArchSession *s, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_ISVM:
		return 0;
	}
	return 4;
}

const RArchPlugin r_arch_plugin_alpha = {
	.meta = {
		.name = "alpha",
		.desc = "64bit DEC ALPHA (Based on GNU binutils)",
		.license = "GPL-3.0-only",
	},
	.arch = "alpha",
	.bits = R_SYS_BITS_PACK1 (64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = info,
	.regs = regs,
	.decode = decode
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_alpha,
	.version = R2_VERSION
};
#endif
