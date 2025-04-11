/* radare - LGPL - Copyright 2009-2024 - pancake */

#define R_LOG_ORIGIN "arch.ppc.gnu"

#include <r_arch.h>
#include "../../include/disas-asm.h"

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
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
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
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	if (disasm_obj.endian) {
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

static bool ppc_op(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const int len = op->size;
	const ut8 *bytes = op->bytes;
	// XXX hack
	int opcode = (bytes[0] & 0xf8) >> 3; // bytes 0-5
	short baddr = (((ut32) bytes[2] << 8) | (bytes[3] & 0xfc));// 16-29
	int aa = bytes[3]&0x2;
	int lk = bytes[3]&0x1;
	//if (baddr>0x7fff)
	//      baddr = -baddr;

	op->addr = addr;
	op->type = 0;
	op->size = 4;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		int res = disassemble (as, op, addr, bytes, len);
		if (res == -1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
	}
//	R_LOG_DEBUG ("OPCODE IS %08x : %02x (opcode=%d) baddr = %d", addr, bytes[0], opcode, baddr);

	switch (opcode) {
//	case 0: // bl op->type = R_ANAL_OP_TYPE_NOP; break;
	case 11: // cmpi
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 9: // pure branch
		if (bytes[0] == 0x4e) {
			// bctr
		} else {
			op->jump = aa? baddr: addr + baddr;
			if (lk) {
				op->fail = addr + 4;
			}
		}
		op->eob = 1;
		break;
	case 6: // bc // conditional jump
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = aa? baddr: addr + baddr + 4;
		op->eob = 1;
		break;
#if 0
	case 7: // sc/svc
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
#endif
#if 0
	case 15: // bl
		// OK
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (aa)?(baddr):(addr+baddr);
		op->fail = addr+4;
		op->eob = 1;
		break;
#endif
	case 8: // bne i tal
		// OK
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (aa)?(baddr):(addr+baddr+4);
		op->fail = addr+4;
		op->eob = 1;
		break;
	case 19: // bclr/bcr/bcctr/bcc
		op->type = R_ANAL_OP_TYPE_RET; // jump to LR
		if (lk) {
			op->jump = UT32_MAX; // LR ?!?
			op->fail = addr+4;
		}
		op->eob = 1;
		break;
	}
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

#if 0
NOTES:
======
	 10000
	 AA = absolute address
	 LK = link bit
	 BD = bits 16-19
	   address
	 if (AA) {
	   address = (int32) BD << 2
	 } else {
	   address += (int32) BD << 2
	 }
	AA LK
	30 31
	 0  0  bc
	 1  0  bca
	 0  1  bcl
	 1  1  bcla

	 10011
	 BCCTR
	 LK = 31

	 bclr or bcr (Branch Conditional Link Register) Instruction
	 10011

	 6-29 -> LL (addr) ?
	 B  10010 -> branch
	 30 31
	 0  0   b
	 1  0   ba
	 0  1   bl
	 1  1   bla
	 SC SYSCALL 5 first bytes 10001
	 SVC SUPERVISORCALL
	 30 31
	 0  0  svc
	 0  1  svcl
	 1  0  svca
	 1  1  svcla
#endif
