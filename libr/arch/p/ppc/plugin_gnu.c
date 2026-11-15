/* radare - LGPL - Copyright 2009-2024 - pancake */

#define R_LOG_ORIGIN "arch.ppc.gnu"

#include <r_arch.h>
#include "../../include/disas-asm.h"
#include "../../include/opcode/ppc.h"

static int ppc_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
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

static int disassemble(RArchSession *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char options[64];
	ut8 bytes[8] = { 0 };
	struct disassemble_info disasm_obj = {0};
	if (len < 4) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	memcpy (bytes, buf, 4);
	*options = 0;
	const int bits = a->config->bits;
	if (!R_STR_ISEMPTY (a->config->cpu)) {
		snprintf (options, sizeof (options), "%s,%s",
			(bits == 64)? "64": "", a->config->cpu);
	} else if (bits == 64) {
		r_str_ncpy (options, "64", sizeof (options));
	}
	disasm_obj.disassembler_options = options;
	disasm_obj.buffer = bytes;
	disasm_obj.buffer_vma = addr;
	disasm_obj.read_memory_func = &ppc_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.endian = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config)? BFD_ENDIAN_BIG: BFD_ENDIAN_LITTLE;
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	if (disasm_obj.endian == BFD_ENDIAN_BIG) {
		op->size = print_insn_big_powerpc ((bfd_vma)addr, &disasm_obj);
	} else {
		op->size = print_insn_little_powerpc ((bfd_vma)addr, &disasm_obj);
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

static bool ppc_op(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	if (len < 4) {
		return false;
	}
	const ut32 insn = r_read_ble32 (op->bytes, R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
	const ut32 opcode = PPC_OP (insn);
	const st16 bd = (st16) (insn & 0xfffc);
	const bool aa = insn & 2;
	const bool lk = insn & 1;
	const ut32 bo = (insn >> 21) & 0x1f;
	// BO 20 is the only valid branch-always encoding; anything else keeps the fall-through edge
	const bool cond = bo != 20;

	op->type = R_ANAL_OP_TYPE_NULL;
	if ((mask & R_ARCH_OP_MASK_DISASM) && disassemble (as, op, addr, op->bytes, len) == -1) {
		// don't let the switch type reserved-field garbage as a real op
		op->type = R_ANAL_OP_TYPE_ILL;
	} else switch (opcode) {
	case 10: // cmpli
	case 11: // cmpi
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 16: // bc
		op->jump = aa? bd: addr + bd;
		if (cond) {
			op->type = lk? R_ANAL_OP_TYPE_CCALL: R_ANAL_OP_TYPE_CJMP;
			op->fail = addr + 4;
		} else if (lk && (aa || op->jump != addr + 4)) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->fail = addr + 4;
		} else {
			// branch-always; bcl 20,31,$+4 only exists for the LR write (ppc32 pic idiom), not a call
			op->type = R_ANAL_OP_TYPE_JMP;
		}
		op->eob = !lk;
		break;
	case 17: // sc
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case 18: { // b/ba/bl/bla
		st32 li = insn & 0x03fffffc;
		if (li & 0x02000000) {
			li -= 0x04000000;
		}
		op->type = lk? R_ANAL_OP_TYPE_CALL: R_ANAL_OP_TYPE_JMP;
		op->jump = aa? li: addr + li;
		if (lk) {
			op->fail = addr + 4;
		}
		op->eob = !lk;
		break;
	}
	case 19: { // bclr/bcctr/rfi/cr ops
		const ut32 xo = (insn >> 1) & 0x3ff;
		if (xo == 16 || xo == 528) { // bclr/bcctr
			if (lk) {
				op->type = cond? R_ANAL_OP_TYPE_UCCALL: R_ANAL_OP_TYPE_UCALL;
			} else if (xo == 16) {
				// CTR-decrement forms (bdnzlr/bdzlr) are loop branches, not returns
				op->type = (bo & 4)? (cond? R_ANAL_OP_TYPE_CRET: R_ANAL_OP_TYPE_RET): R_ANAL_OP_TYPE_CJMP;
			} else {
				op->type = cond? R_ANAL_OP_TYPE_UCJMP: R_ANAL_OP_TYPE_UJMP;
			}
			if (cond || lk) {
				op->fail = addr + 4;
			}
			op->eob = true;
		} else if (xo == 18 || xo == 50 || xo == 51) { // rfid/rfi/rfci
			op->type = R_ANAL_OP_TYPE_RET;
			op->eob = true;
		}
		break;
	}
	}
	op->size = 4;
	return true;
}

static char *regs(RArchSession *as) {
	const char *const p =
	"=PC	srr0\n"
	"=SR	srr1\n" // status register
	"=BP	r31\n"
	"=LR	lr\n"
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
	if (q == R_ARCH_INFO_WODST) {
		return 1;
	}
	return 4; /* :D */
}

const RArchPlugin r_arch_plugin_ppc_gnu = {
	.meta = {
		.name = "ppc.gnu",
		.desc = "PowerPC analysis plugin",
		.license = "GPL-3.0-only",
	},
	.cpus = "booke,e300,e500,e500x2,e500mc,e440,e464,efs,ppcps,power4,power5,power6,power7,vsx",
	.arch = "ppc",
	.info = archinfo,
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.decode = &ppc_op,
	.regs = &regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ppc_gnu,
	.version = R2_VERSION
};
#endif
