/* radare - LGPL - Copyright 2025 - pancake */

#define R_LOG_ORIGIN "arch.tms320.gnu"

#include <r_arch.h>
#include "../../include/disas-asm.h"

static int tms320_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > info->buffer_length) {
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

static int disassemble(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char options[64];
	ut8 bytes[8] = { 0 };
	struct disassemble_info disasm_obj = {0};
	if (len < 4) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	*options = 0;
	int av = 5; // arch-version
	if (R_STR_ISNOTEMPTY (a->config->cpu)) {
		const char *cpu = a->config->cpu;
		if (strstr (cpu, "c3")) {
			av = 3;
		} else if (strstr (cpu, "c4")) {
			av = 4;
		} else if (strstr (cpu, "c5")) {
			av = 5;
		} else if (strstr (cpu, "c6")) {
			av = 6;
		}
	}
	disasm_obj.disassembler_options = options;
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.buffer_length = len;
	disasm_obj.read_memory_func = &tms320_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	switch (av) {
	case 3:
		op->size = print_insn_tic30 ((bfd_vma)addr, &disasm_obj);
		break;
	case 4:
		op->size = print_insn_tic4x ((bfd_vma)addr, &disasm_obj);
		break;
	case 5:
		op->size = print_insn_tic54x ((bfd_vma)addr, &disasm_obj);
		break;
	case 6:
		op->size = print_insn_tic6x ((bfd_vma)addr, &disasm_obj);
		break;
	default:
		op->size = print_insn_tic54x ((bfd_vma)addr, &disasm_obj);
		R_LOG_DEBUG ("Fallback to c54x");
		break;
	}
	if (op->size == -1) {
		op->mnemonic = strdup ("invalid");
		r_strbuf_free (sb);
	} else {
		op->mnemonic = r_strbuf_drain (sb);
		if (R_STR_ISEMPTY (op->mnemonic)) {
			free (op->mnemonic);
			op->mnemonic = strdup ("invalid");
			op->size = -1;
		}
	}
	return op->size;
}

static bool tms320_op(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	const ut8 *bytes = op->bytes;

	op->addr = addr;
	op->type = 0;
	op->size = 4;
	int res = disassemble (as, op, addr, bytes, len);
	if (res == -1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	}
	// TODO: get op info from disasm
	op->size = 4;
	return op->size;
}

static char *regs(RArchSession *as) {
	const char *const p =
	"=PC	srr0\n"
	"=SR	srr1\n" // status register
	"=BP	r31\n"
	"=A0	r0\n"
	"=A1	r1\n"
	"=A2	r2\n"
	"=A3	r3\n"
#if 0
	"=a4	r4\n"
	"=a5	r5\n"
	"=a6	r6\n"
	"=a7	r7\n"
#endif
	"gpr	srr0	.32	0	0\n"
	"gpr	srr1	.32	4	0\n"
	"gpr	r0	.32	8	0\n"
	"gpr	r1	.32	12	0\n"
	"gpr	r2	.32	16	0\n"
	"gpr	r3	.32	20	0\n"
	"gpr	r4	.32	24	0\n"
	"gpr	r5	.32	28	0\n"
	"gpr	r6	.32	32	0\n"
	"gpr	r7	.32	36	0\n"
	"gpr	r8	.32	40	0\n"
	"gpr	r9	.32	44	0\n"
	"gpr	r10	.32	48	0\n"
	"gpr	r11	.32	52	0\n"
	"gpr	r12	.32	56	0\n"
	"gpr	r13	.32	60	0\n"
	"gpr	r14	.32	64	0\n"
	"gpr	r15	.32	68	0\n"
	"gpr	r16	.32	72	0\n"
	"gpr	r17	.32	76	0\n"
	"gpr	r18	.32	80	0\n"
	"gpr	r19	.32	84	0\n"
	"gpr	r20	.32	88	0\n"
	"gpr	r21	.32	92	0\n"
	"gpr	r22	.32	96	0\n"

	"gpr	r23	.32	100	0\n"
	"gpr	r24	.32	104	0\n"
	"gpr	r25	.32	108	0\n"
	"gpr	r26	.32	112	0\n"
	"gpr	r27	.32	116	0\n"
	"gpr	r28	.32	120	0\n"
	"gpr	r29	.32	124	0\n"
	"gpr	r30	.32	128	0\n"
	"gpr	r31	.32	132	0\n"
	"gpr	cr	.32	136	0\n"
	"gpr	xer	.32	140	0\n"
	"gpr	lr	.32	144	0\n"
	"gpr	ctr	.32	148	0\n"
	"gpr	mq	.32	152	0\n"
	"gpr	vrsave	.32	156	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_DATA_ALIGN:
		return 2;
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 8;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 4;
}

const RArchPlugin r_arch_plugin_tms320_gnu = {
	.meta = {
		.name = "tms320.gnu",
		.desc = "TMS320 TIC c30/c4x/c54x/c6x",
		.license = "GPL-3.0-only",
	},
	.cpus = "c30,c4x,c54x,c6x",
	.arch = "tms320",
	.info = archinfo,
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.decode = &tms320_op,
	.regs = &regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_tms320_gnu,
	.version = R2_VERSION
};
#endif
