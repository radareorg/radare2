/* radare - LGPL - Copyright 2007-2024 - pancake */

#include <r_arch.h>
#include <r_anal.h>

// R2R db/anal/arm.gnu_16 db/tools/rasm2 db/anal/arm

/* DEPRECATE ?? */
#include "../../include/wine-arm.h"
#include "../../include/disas-asm.h"
#include "asm-arm.h"
#include "winedbg/be_arm.h"
#include "anal_arm_hacks.inc.c"
#include "gnu/opcode-arm.h"

typedef struct plugin_data_t {
	char *oldcpu;
	int oldcpucode;
} PluginData;

static ut32 disarm_branch_offset(ut32 pc, ut32 insoff) {
	ut32 add = insoff << 2;
	/* zero extend if higher is 1 (0x02000000) */
	if ((add & 0x02000000) == 0x02000000) {
		add |= 0xFC000000;
	}
	return add + pc + 8;
}

#define IS_BRANCH(x)  (((x) & ARM_BRANCH_I_MASK) == ARM_BRANCH_I)
#define IS_BRANCHL(x) (IS_BRANCH (x) && ((x) & ARM_BRANCH_LINK) == ARM_BRANCH_LINK)
#define IS_RETURN(x)  (((x) & (ARM_DTM_I_MASK | ARM_DTM_LOAD | (1 << 15))) == (ARM_DTM_I | ARM_DTM_LOAD | (1 << 15)))
// if ((inst & ( ARM_DTX_I_MASK | ARM_DTX_LOAD  | ( ARM_DTX_RD_MASK ) ) ) == ( ARM_DTX_LOAD | ARM_DTX_I | ( ARM_PC << 12 ) ) )
#define IS_UNKJMP(x)  ((((ARM_DTX_RD_MASK))) == (ARM_DTX_LOAD | ARM_DTX_I | (ARM_PC << 12)))
#define IS_LOAD(x)    (((x) & ARM_DTX_LOAD) == (ARM_DTX_LOAD))
#define IS_CONDAL(x)  (((x) & ARM_COND_MASK) == ARM_COND_AL)
#define IS_EXITPOINT(x) (IS_BRANCH (x) || IS_RETURN (x) || IS_UNKJMP (x))

#define API static

static int op_thumb(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *data, int len, ut32 mask) {
	int op_code;
	if (len < 2) {
		return 0;
	}
	ut16 *_ins = (ut16 *) data;
	ut16 ins = *_ins;
	ut32 ins32 = 0;
	if (len > 3) {
		ut32 *_ins32 = (ut32 *) data;
		ins32 = *_ins32;
	}

	struct winedbg_arm_insn *arminsn = arm_new ();
	arm_set_thumb (arminsn, true);
	arm_set_input_buffer (arminsn, data);
	arm_set_pc (arminsn, addr);
	op->delay = 0;
	op->size = arm_disasm_one_insn (arminsn);
	op->jump = arminsn->jmp;
	op->fail = arminsn->fail;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		const char *cpu = r_str_get_fail (as->config->cpu, "");
		if (!strcmp (cpu, "wd")) {
			const char *asmstr = winedbg_arm_insn_asm (arminsn);
			if (asmstr) {
				op->mnemonic = strdup (asmstr);
			} else {
				op->mnemonic = strdup ("invalid");
			}
		}
	}
	arm_free (arminsn);

	// TODO: handle 32bit instructions (branches are not correctly decoded //

	/* CMP */
	if (((ins & B4 (B1110, 0, 0, 0)) == B4 (B0010, 0, 0, 0))
	    && (1 == (ins & B4 (1, B1000, 0, 0)) >> 11)) { // dp3
		op->type = R_ANAL_OP_TYPE_CMP;
		return op->size;
	}
	if ((ins & B4 (B1111, B1100, 0, 0)) == B4 (B0100, 0, 0, 0)) {
		op_code = (ins & B4 (0, B0011, B1100, 0)) >> 6;
		if (op_code == 8 || op_code == 10) {  // dp5
			op->type = R_ANAL_OP_TYPE_CMP;
			return op->size;
		}
	}
	if ((ins & B4 (B1111, B1100, 0, 0)) == B4 (B0100, B0100, 0, 0)) {
		op_code = (ins & B4 (0, B0011, 0, 0)) >> 8;  // dp8
		if (op_code == 1) {
			op->type = R_ANAL_OP_TYPE_CMP;
			return op->size;
		}
	}
	if (ins == 0xbf) {
		// TODO: add support for more NOP instructions
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (((op_code = ((ins & B4 (B1111, B1000, 0, 0)) >> 11)) >= 12 && op_code <= 17)) {
		if (op_code % 2) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else {
			op->type = R_ANAL_OP_TYPE_STORE;
		}
	} else if ((ins & B4 (B1111, 0, 0, 0)) == B4 (B0101, 0, 0, 0)) {
		op_code = (ins & B4 (0, B1110, 0, 0)) >> 9;
		if (op_code % 2) {
			op->type = R_ANAL_OP_TYPE_LOAD;
		} else {
			op->type = R_ANAL_OP_TYPE_STORE;
		}
	} else if ((ins & B4 (B1111, 0, 0, 0)) == B4 (B1101, 0, 0, 0)) {
		// BNE..
		int delta = (ins & B4 (0, 0, B1111, B1111));
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + 4 + (delta << 1);
		op->fail = addr + 4;
	} else if ((ins & B4 (B1111, B1000, 0, 0)) == B4 (B1110, 0, 0, 0)) {
		// B
		int delta = (ins & B4 (0, 0, B1111, B1111));
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + 4 + (delta << 1);
		op->fail = addr + 4;
	} else if ((ins & B4 (B1111, B1111, B1000, 0)) == B4 (B0100, B0111, B1000, 0)) {
		// BLX
		op->type = R_ANAL_OP_TYPE_UCALL;
		op->fail = addr + 4;
	} else if ((ins & B4 (B1111, B1111, B1000, 0)) == B4 (B0100, B0111, 0, 0)) {
		// BX
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->fail = addr + 4;
	} else if ((ins & B4 (B1111, B1000, 0, 0)) == B4 (B1111, 0, 0, 0)) {
		// BL The long branch with link, it's in 2 instructions:
		// prefix: 11110[offset]
		// suffix: 11111[offset] (11101[offset] for blx)
		ut16 nextins = (ins32 & 0xFFFF0000) >> 16;
		ut32 high = (ins & B4 (0, B0111, B1111, B1111)) << 12;
		if (ins & B4 (0, B0100, 0, 0)) {
			high |= B4 (B1111, B1000, 0, 0) << 16;
		}
		int delta = high + ((nextins & B4 (0, B0111, B1111, B1111)) * 2);
		op->jump = (int) (addr + 4 + (delta));
		op->type = R_ANAL_OP_TYPE_CALL;
		op->fail = addr + 4;
	} else if ((ins & B4 (B1111, B1111, 0, 0)) == B4 (B1011, B1110, 0, 0)) {
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->val = (ut64) (ins >> 8);
	} else if ((ins & B4 (B1111, B1111, 0, 0)) == B4 (B1101, B1111, 0, 0)) {
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = (ut64) (ins >> 8);
	}
	return op->size;
}

#if 0
"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
"hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
#endif
static const int iconds[] = {
	R_ANAL_CONDTYPE_EQ,
	R_ANAL_CONDTYPE_NE,
	0, // cs
	0, // cc
	0, // mi
	0, // pl
	0, // vs
	0, // vc
	0, // hi
	0, // ls
	R_ANAL_CONDTYPE_GE,
	R_ANAL_CONDTYPE_LT,
	R_ANAL_CONDTYPE_GT,
	R_ANAL_CONDTYPE_LE,
	R_ANAL_CONDTYPE_AL,
	R_ANAL_CONDTYPE_NV,
};

static int op_cond(const ut8 *data) {
	ut8 b = data[3] >> 4;
	if (b == 0xf) {
		return 0;
	}
	return iconds[b];
}

static int arm_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
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
	// --
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS()

static const struct {
	const char *name;
	int cpucode;
} arm_cpus[] = {
	{ "v2", bfd_mach_arm_2 },
	{ "v2a", bfd_mach_arm_2a },
	{ "v3M", bfd_mach_arm_3M },
	{ "v4", bfd_mach_arm_4 },
	{ "v4t", bfd_mach_arm_4T },
	{ "v5", bfd_mach_arm_5 },
	{ "v5t", bfd_mach_arm_5T },
	{ "v5te", bfd_mach_arm_5TE },
	{ "v5j", bfd_mach_arm_5TE },
	{ "XScale", bfd_mach_arm_XScale },
	{ "ep9312", bfd_mach_arm_ep9312 },
	{ "iWMMXt", bfd_mach_arm_iWMMXt },
	{ "iWMMXt2", bfd_mach_arm_iWMMXt2 },
};

static int disassemble(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	const int bits = as->config->bits;
	ut8 bytes[4] = {0};
	struct disassemble_info obj;
	int opsize;

	if (len < 2) {
		return -1;
	}
	memset (bytes, 0, sizeof (bytes));
	memcpy (bytes, buf, R_MIN (len, 4));
	if (bits < 64 && len < (bits / 8)) {
		return -1;
	}
	RStrBuf *insn_buffer = r_strbuf_new ("");

	/* prepare disassembler */
	memset (&obj, '\0', sizeof (struct disassemble_info));

	/* select cpu */
	// XXX oldcpu leaks
	char *cpu = as->config->cpu;
	PluginData *pd = as->data;
	if (pd->oldcpu != cpu) {
		int cpucode = 0;
		if (cpu) {
 			int i;
			cpucode = atoi (cpu);
			for (i = 0; i < (sizeof (arm_cpus) / sizeof (arm_cpus[0])); i++) {
				if (!strcmp (arm_cpus[i].name, cpu)) {
					cpucode = arm_cpus[i].cpucode;
					break;
				}
			}
		}
		pd->oldcpu = cpu;
		pd->oldcpucode = cpucode;
	}

	obj.arch = 0;
	obj.mach = pd->oldcpucode;
	if (obj.mach) {
		obj.flags |= USER_SPECIFIED_MACHINE_TYPE;
	}

	obj.buffer = bytes;
	obj.buffer_vma = addr;
	obj.read_memory_func = arm_buffer_read_memory;
	obj.symbol_at_address_func = &symbol_at_address;
	obj.memory_error_func = &memory_error_func;
	obj.print_address_func = &generic_print_address_func;
	obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	obj.fprintf_func = &generic_fprintf_func;
	obj.stream = insn_buffer;
	obj.bytes_per_chunk = obj.bytes_per_line = (bits / 8);

	if (bits == 64) {
		obj.disassembler_options = NULL;
		memcpy (bytes, buf, 4);
		op->size = print_insn_aarch64 ((bfd_vma) addr, &obj);
	} else {
		const char *options = (bits == 16)? "force-thumb": "no-force-thumb";
		obj.disassembler_options = (char *)options;
		op->size = (obj.endian == BFD_ENDIAN_LITTLE)
			? print_insn_little_arm ((bfd_vma) addr, &obj)
			: print_insn_big_arm ((bfd_vma) addr, &obj);
	}
	opsize = op->size;
	op->mnemonic = NULL;
	if (op->size == -1) {
		op->mnemonic = strdup ("(data)");
		op->size = 4;
	} else if (strstr (r_strbuf_get (insn_buffer), "UNDEF")) {
		op->mnemonic = strdup ("undefined");
		op->size = 2;
		opsize = 2;
	}
	if (op->mnemonic) {
		r_strbuf_free (insn_buffer);
	} else {
		op->mnemonic = r_strbuf_drain (insn_buffer);
	}
	return opsize;
}


static int arm_op32(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *data, int len, ut32 mask) {
	const ut8 *b = (ut8 *) data;
	ut8 ndata[4] = {0};
	ut32 branch_dst_addr, i = 0;
	ut32 *code = (ut32 *) data;

	if (!data) {
		return 0;
	}
	struct winedbg_arm_insn *arminsn = arm_new ();
	arm_set_thumb (arminsn, false);

	arm_set_input_buffer (arminsn, data);
	arm_set_pc (arminsn, addr);
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;

	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)) {
		b = data = ndata;
		ut8 tmp = data[3];
		ndata[0] = data[3];
		ndata[1] = data[2];
		ndata[2] = data[1];
		ndata[3] = tmp;
	}
	if (as->config->bits == 16) {
		arm_free (arminsn);
		return op_thumb (as, op, addr, data, len, mask);
	}
	op->size = arm_disasm_one_insn (arminsn);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		const char *cpu = r_str_get_fail (as->config->cpu, "");
		if (!strcmp (cpu, "wd")) {
			const char *asmstr = winedbg_arm_insn_asm (arminsn);
			if (asmstr) {
				op->mnemonic = strdup (asmstr);
			} else {
				op->mnemonic = strdup ("invalid");
			}
		}
	}
	op->cond = op_cond (data);
	if (b[2] == 0x8f && b[3] == 0xe2) {
		op->type = R_ANAL_OP_TYPE_ADD;
#define ROR(x, y) ((int) ((x) >> (y)) | (((x) << (32 - (y)))))
		op->ptr = addr + ROR (b[0], (b[1] & 0xf) << 1) + 8;
	} else if (b[2] >= 0x9c && b[2] <= 0x9f) {  // load instruction
		char ch = b[3] & 0xf;
		switch (ch) {
		case 5:
			if ((b[3] & 0xf) == 5) {
				op->ptr = 8 + addr + b[0] + ((b[1] & 0xf) << 8);
				// XXX: if set it breaks the visual disasm wtf
				op->refptr = 4;
			}
		case 4:
		case 6:
		case 7:
		case 8:
		case 9: op->type = R_ANAL_OP_TYPE_LOAD; break;
		}
	} else // 0x000037b8  00:0000   0             800000ef  svc 0x00000080
	if (b[2] == 0xa0 && b[3] == 0xe1) {
		int n = (b[0] << 16) + b[1];
		op->type = R_ANAL_OP_TYPE_MOV;
		switch (n) {
		case 0:
		case 0x0110: case 0x0220: case 0x0330: case 0x0440:
		case 0x0550: case 0x0660: case 0x0770: case 0x0880:
		case 0x0990: case 0x0aa0: case 0x0bb0: case 0x0cc0:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		}
	} else if (b[3] == 0xef) {
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = (b[0] | (b[1] << 8) | (b[2] << 2));
	} else if ((b[3] & 0xf) == 5) {  // [reg,0xa4]
#if 0
		0x00000000      a4a09fa4 ldrge sl, [pc], 0xa4
		0x00000000      a4a09fa5 ldrge sl, [pc, 0xa4]
		0x00000000      a4a09fa6 ldrge sl, [pc], r4, lsr 1
		0x00000000      a4a09fa7 ldrge sl, [pc, r4, lsr 1]
		0x00000000      a4a09fe8 ldm pc, {
			r2, r5, r7, sp, pc
		}; < UNPREDICT
#endif
		if ((b[1] & 0xf0) == 0xf0) {
			// ldr pc, [pc, #1] ;
			// op->type = R_ANAL_OP_TYPE_UJMP;
			op->type = R_ANAL_OP_TYPE_RET; // FAKE FOR FUN
			// op->stackop = R_ANAL_STACK_SET;
			op->jump = 1234;
			// op->ptr = 4+addr+b[0]; // sure? :)
			// op->ptrptr = true;
		}
		// eprintf("0x%08x\n", code[i] & ARM_DTX_LOAD);
		// 0x0001B4D8,           1eff2fe1        bx    lr
	} else if (b[3] == 0xe2 && b[2] == 0x8d && b[1] == 0xd0) {
		// ADD SP, SP, ...
		op->type = R_ANAL_OP_TYPE_ADD;
		op->stackop = R_ANAL_STACK_INC;
		op->val = -b[0];
	} else if (b[3] == 0xe2 && b[2] == 0x4d && b[1] == 0xd0) {
		// SUB SP, SP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INC;
		op->val = b[0];
	} else if (b[3] == 0xe2 && b[2] == 0x4c && b[1] == 0xb0) {
		// SUB SP, FP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INC;
		op->val = -b[0];
	} else if (b[3] == 0xe2 && b[2] == 0x4b && b[1] == 0xd0) {
		// SUB SP, IP, ..
		op->type = R_ANAL_OP_TYPE_SUB;
		op->stackop = R_ANAL_STACK_INC;
		op->val = -b[0];
	} else if (code[i] == 0x1eff2fe1 || code[i] == 0xe12fff1e) {  // bx lr
		op->type = R_ANAL_OP_TYPE_RET;
	} else if (code[i] & ARM_DTX_LOAD) {  // IS_LOAD(code[i])) {
		ut32 ptr = 0;
		op->type = R_ANAL_OP_TYPE_MOV;
		if (b[2] == 0x1b) {
			/* XXX pretty incomplete */
			op->stackop = R_ANAL_STACK_GET;
			op->ptr = b[0];
			// var_add_access(addr, -b[0], 1, 0); // TODO: set/get (the last 0)
		} else {
			// ut32 oaddr = addr+8+b[0];
			// XXX TODO ret = radare_read_at(oaddr, (ut8*)&ptr, 4);
			if (as->config->bits == 32) {
				b = (ut8 *) &ptr;
				op->ptr = b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);
				// XXX data_xrefs_add(oaddr, op->ptr, 1);
				// TODO change data type to pointer
			} else {
				op->ptr = 0;
			}
		}
	}

	if (IS_LOAD (code[i])) {
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->refptr = 4;
	}
	if (((((code[i] & 0xff) >= 0x10 && (code[i] & 0xff) < 0x20)) &&
	     ((code[i] & 0xffffff00) == 0xe12fff00)) ||
	    IS_EXITPOINT (code[i])) {
		// if (IS_EXITPOINT (code[i])) {
		b = data;
		branch_dst_addr = disarm_branch_offset (
			addr, b[0] | (b[1] << 8) |
			(b[2] << 16));                // code[i]&0x00FFFFFF);
		op->ptr = 0;
		if ((((code[i] & 0xff) >= 0x10 && (code[i] & 0xff) < 0x20)) &&
		    ((code[i] & 0xffffff00) == 0xe12fff00)) {
			op->type = R_ANAL_OP_TYPE_UJMP;
		} else if (IS_BRANCHL (code[i])) {
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = branch_dst_addr;
			op->fail = addr + 4;
		} else if (IS_BRANCH (code[i])) {
			if (IS_CONDAL (code[i])) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = branch_dst_addr;
				op->fail = UT64_MAX;
			} else {
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = branch_dst_addr;
				op->fail = addr + 4;
			}
		} else {
			// unknown jump o return
			// op->type = R_ANAL_OP_TYPE_UJMP;
			// op->type = R_ANAL_OP_TYPE_NOP;
		}
	}
	// op->jump = arminsn->jmp;
	// op->fail = arminsn->fail;
	arm_free (arminsn);
	return op->size;
}

static ut64 getaddr(ut64 addr, const ut8 *d) {
	if (d[2] >> 7) {
		/// st32 n = (d[0] + (d[1] << 8) + (d[2] << 16) + (0xff << 24));
		st32 n = (d[0] + (d[1] << 8) + (d[2] << 16) + ((ut64)(0xff) << 24)); // * 16777216));
		n = -n;
		return addr - (n * 4);
	}
	return addr + (4 * (d[0] + (d[1] << 8) + (d[2] << 16)));
}

static int arm_op64(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *d, int len) {
	if (d[3] == 0) {
		return -1; // invalid
	}
	int haa = hacky_arm_anal (as, op, d, len);
	if (haa > 0) {
		return haa;
	}
	op->size = 4;
	op->type = R_ANAL_OP_TYPE_NULL;
	if (d[0] == 0xc0 && d[3] == 0xd6) {
		// defaults to x30 reg. but can be different
		op->type = R_ANAL_OP_TYPE_RET;
	}
	switch (d[3]) {
	case 0x71:
	case 0xeb:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0xb8:
	case 0xb9:
	case 0xf8:
	case 0xa9: // ldp/stp
	case 0xf9: // ldr/str
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x91: // mov
	case 0x52: // mov
	case 0x94: // bl A
	case 0x97: // bl A
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = getaddr (addr, d);
		op->fail = addr + 4;
		break;
	case 0x54: // beq A
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + (4 * ((d[0] >> 4) | (d[1] << 8) | (d[2] << 16)));
		op->fail = addr + 4;
		break;
	case 0x17: // b A
	case 0x14: // b A
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = getaddr (addr, d);
		op->fail = addr + 4;
		break;
	}
	return op->size;
}

static bool arm_op(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
// }ut64 addr, const ut8 *data, int len, RAnalOpMask mask)
// static int arm_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask)
	const ut64 addr = op->addr;
	const ut8 *data = op->bytes;
	const int len = op->size;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		const char *cpu = r_str_get_fail (as->config->cpu, "");
		if (strcmp (cpu, "wd")) {
			disassemble (as, op, addr, data, len);
		}
	}
	if (as->config->bits == 64) {
		return arm_op64 (as, op, addr, data, len);
	}
	return arm_op32 (as, op, addr, data, len, mask);
}

static char *set_reg_profile(RArchSession *as) {
	// TODO: support 64bit profile
	const char p32[] =
		"=PC	r15\n"
		"=SP	r13\n"
		"=BP	r14\n" // XXX
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
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
		"gpr	r16	.32	64	0\n"
		"gpr	r17	.32	68	0\n"
		"gpr	cpsr	.32	72	0\n";
	return strdup (p32);
}

static int archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_CODE_ALIGN) {
		return (as && as->config->bits == 16)? 2: 4;
	}
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 4;
	}
	if (q == R_ARCH_INFO_MINOP_SIZE) {
		return (as && as->config->bits == 16)? 2: 4;
	}
	return 4; // XXX
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	return !!as->data;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	R_FREE (as->data);
	return true;
}
#include "preludes.inc.c"

const RArchPlugin r_arch_plugin_arm_gnu = {
	.meta = {
		.name = "arm.gnu",
		.license = "GPL-3.0-only",
		.desc = "ARM code analysis plugin (asm.cpu=wd for winedbg disassembler)",
	},
	.arch = "arm",
	.cpus = "v2,v2a,v3M,v4,v5,v5t,v5te,v5j,XScale,ep9312,iWMMXt,iWMMXt2,wd",
#if 0
	// arm32 and arm64
	"crypto,databarrier,divide,fparmv8,multpro,neon,t2extractpack,"
	"thumb2dsp,trustzone,v4t,v5t,v5te,v6,v6t2,v7,v8,vfp2,vfp3,vfp4,"
	"arm,mclass,notmclass,thumb,thumb1only,thumb2,prev8,fpvmlx,"
	"mulops,crc,dpvfp,v6m"
#endif
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.info = archinfo,
	.decode = arm_op,
	.preludes = anal_preludes,
	.regs = set_reg_profile,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_arm_gnu,
	.version = R2_VERSION
};
#endif
