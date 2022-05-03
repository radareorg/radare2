/* radare2 - LGPL - Copyright 2014-2022 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include "disas-asm.h"

#define INSOP(n) insn->detail->sysz.operands[n]

static R_TH_LOCAL unsigned long Offset = 0;
static R_TH_LOCAL RStrBuf *buf_global = NULL;
static R_TH_LOCAL unsigned char bytes[8];

static int s390_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > 6) {
		return -1;
	}
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	char options[64];
	struct disassemble_info disasm_obj;
	if (len < 6) {
		// r_asm_op_set_asm (op, "truncated");
		return 2;
	}
	buf_global = r_strbuf_new ("");
	Offset = addr;
	memcpy (bytes, buf, 6); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	if (!R_STR_ISEMPTY (a->config->cpu)) {
		r_str_ncpy (options, a->config->cpu, sizeof (options));
	} else {
		*options = 0;
	}
	op->size = 2;
	//r_asm_op_set_asm (op, "");
	disasm_obj.disassembler_options = options;
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &s390_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = 0; // !a->big_endian;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = stdout;
	disassemble_init_s390 (&disasm_obj);
	op->size = print_insn_s390 ((bfd_vma)Offset, &disasm_obj);
	if (op->size < 1) {
		op->mnemonic = strdup ("invalid");
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
	} else {
		op->mnemonic = r_strbuf_drain (buf_global);
		buf_global = NULL;
	}
	r_strbuf_free (buf_global);
	buf_global = NULL;
	return op->size;
}

static bool set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	r15\n"
		"=LR	r14\n"
		"=SP	r13\n"
		"=BP	r12\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=SN	r0\n"
		"gpr	sb	.32	36	0\n" // r9
		"gpr	sl	.32	40	0\n" // rl0
		"gpr	fp	.32	44	0\n" // r11
		"gpr	ip	.32	48	0\n" // r12
		"gpr	sp	.32	52	0\n" // r13
		"gpr	lr	.32	56	0\n" // r14
		"gpr	pc	.32	60	0\n" // r15

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
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
	;
	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	switch (q) {
	case R_ANAL_ARCHINFO_DATA_ALIGN:
	case R_ANAL_ARCHINFO_ALIGN:
		return 2;
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
		return 2;
	}
	return 2;
}

RAnalPlugin r_anal_plugin_s390_gnu = {
	.name = "s390.gnu",
	.desc = "SystemZ S390 from binutils",
	.esil = false,
	.license = "BSD",
	.arch = "s390",
	.cpus = "esa,zarch",
	.bits = 32 | 64, // it's actually 31
	.op = &analop,
	.archinfo = archinfo,
	.set_reg_profile = &set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_s390_gnu,
	.version = R2_VERSION
};
#endif
