/* Copyright (C) 2008-2025 - pancake, unlogic, emvivre */

#include <r_arch.h>

#define ENCODING_SHIFT 0
#define OPTYPE_SHIFT   6
#define REGMASK_SHIFT  16
#define OPSIZE_SHIFT   24

// How to encode the operand?
#define OT_REGMEM      (1 << (ENCODING_SHIFT + 0))
#define OT_SPECIAL     (1 << (ENCODING_SHIFT + 1))
#define OT_IMMEDIATE   (1 << (ENCODING_SHIFT + 2))
#define OT_JMPADDRESS  (1 << (ENCODING_SHIFT + 3))

// Register indices - by default, we allow all registers
#define OT_REGALL   (0xff << REGMASK_SHIFT)

// Memory or register operands: how is the operand written in assembly code?
#define OT_MEMORY      (1 << (OPTYPE_SHIFT + 0))
#define OT_CONSTANT    (1 << (OPTYPE_SHIFT + 1))
#define OT_GPREG      ((1 << (OPTYPE_SHIFT + 2)) | OT_REGALL)
#define OT_SEGMENTREG ((1 << (OPTYPE_SHIFT + 3)) | OT_REGALL)
#define OT_FPUREG     ((1 << (OPTYPE_SHIFT + 4)) | OT_REGALL)
#define OT_MMXREG     ((1 << (OPTYPE_SHIFT + 5)) | OT_REGALL)
#define OT_XMMREG     ((1 << (OPTYPE_SHIFT + 6)) | OT_REGALL)
#define OT_CONTROLREG ((1 << (OPTYPE_SHIFT + 7)) | OT_REGALL)
#define OT_DEBUGREG   ((1 << (OPTYPE_SHIFT + 8)) | OT_REGALL)
#define OT_SREG       ((1 << (OPTYPE_SHIFT + 9)) | OT_REGALL)
// more?

#define OT_REGTYPE    ((OT_GPREG | OT_SEGMENTREG | OT_FPUREG | OT_MMXREG | OT_XMMREG | OT_CONTROLREG | OT_DEBUGREG) & ~OT_REGALL)

// Register mask
#define OT_REG(num)  ((1 << (REGMASK_SHIFT + (num))) | OT_REGTYPE)

#define OT_UNKNOWN    (0 << OPSIZE_SHIFT)
#define OT_BYTE       (1 << OPSIZE_SHIFT)
#define OT_WORD       (2 << OPSIZE_SHIFT)
#define OT_DWORD      (4 << OPSIZE_SHIFT)
#define OT_QWORD      (8 << OPSIZE_SHIFT)
#define OT_OWORD     (16 << OPSIZE_SHIFT)
#define OT_TBYTE     (32 << OPSIZE_SHIFT)

#define ALL_SIZE     (OT_BYTE | OT_WORD | OT_DWORD | OT_QWORD | OT_OWORD)

// For register operands, we mostly don't care about the size.
// So let's just set all relevant flags.
#define OT_FPUSIZE  (OT_DWORD | OT_QWORD | OT_TBYTE)
#define OT_XMMSIZE  (OT_DWORD | OT_QWORD | OT_OWORD)

// Macros for encoding
#define OT_REGMEMOP(type)  (OT_##type##REG | OT_MEMORY | OT_REGMEM)
#define OT_REGONLYOP(type) (OT_##type##REG | OT_REGMEM)
#define OT_MEMONLYOP       (OT_MEMORY | OT_REGMEM)
#define OT_MEMIMMOP        (OT_MEMORY | OT_IMMEDIATE)
#define OT_REGSPECOP(type) (OT_##type##REG | OT_SPECIAL)
#define OT_IMMOP           (OT_CONSTANT | OT_IMMEDIATE)
#define OT_MEMADDROP       (OT_MEMORY | OT_IMMEDIATE)

// Some operations are encoded via opcode + spec field
#define SPECIAL_SPEC 0x00010000
#define SPECIAL_MASK 0x00000007

#define MAX_OPERANDS 3
#define MAX_REPOP_LENGTH 20

#define is_valid_registers(op)\
	if (is_debug_or_control (op->operands[0]) || is_debug_or_control (op->operands[1])) {\
		return -1; \
	}

const ut8 SEG_REG_PREFIXES[] = { 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65 };

typedef enum tokentype_t {
	TT_EOF,
	TT_WORD,
	TT_NUMBER,
	TT_SPECIAL
} x86newTokenType;

typedef enum register_t {
	X86R_UNDEFINED = -1,
	X86R_EAX = 0, X86R_ECX, X86R_EDX, X86R_EBX, X86R_ESP, X86R_EBP, X86R_ESI, X86R_EDI, X86R_EIP,
	X86R_AX = 0, X86R_CX, X86R_DX, X86R_BX, X86R_SP, X86R_BP, X86R_SI, X86R_DI,
	X86R_AL = 0, X86R_CL, X86R_DL, X86R_BL, X86R_AH, X86R_CH, X86R_DH, X86R_BH,
	// r8 with any REX prefix, 0->3 is al->dl
	X86R_SPL = 4, X86R_BPL, X86R_SIL, X86R_DIL,
	X86R_RAX = 0, X86R_RCX, X86R_RDX, X86R_RBX, X86R_RSP, X86R_RBP, X86R_RSI, X86R_RDI, X86R_RIP,
	X86R_R8 = 0, X86R_R9, X86R_R10, X86R_R11, X86R_R12, X86R_R13, X86R_R14, X86R_R15,
	X86R_CS = 0, X86R_SS, X86R_DS, X86R_ES, X86R_FS, X86R_GS,	// Is this the right order?
	X86R_CR0 = 0, X86R_CR1, X86R_CR2, X86R_CR3, X86R_CR4, X86R_CR5, X86R_CR6, X86R_CR7,
	X86R_DR0 = 0, X86R_DR1, X86R_DR2, X86R_DR3, X86R_DR4, X86R_DR5, X86R_DR6, X86R_DR7
} Register;

typedef struct operand_t {
	ut32 type;
	st8 sign;
	struct {
		Register reg;
		bool extended;
		bool rex_prefixed;
	};
	union {
		struct {
			ut64 offset;
			st8 offset_sign;
			Register regs[2];
			int scale[2];
		};
		struct {
			ut64 immediate;
			bool is_good_flag;
		};
		struct {
			char rep_op[MAX_REPOP_LENGTH];
		};
	};
	bool explicit_size;
	ut32 dest_size;
	ut32 reg_size;
} Operand;

typedef struct r_x86nz_opcode_t {
	char *mnemonic;
	ut64 addr;
	ut32 op[3];
	size_t op_len;
	bool is_short;
	ut8 opcode[3];
	int operands_count;
	Operand operands[MAX_OPERANDS];
	bool has_bnd;
} Opcode;

static bool immediate_out_of_range(int bits, ut64 immediate) {
	return bits == 32 && (immediate >> 32);
}

static inline bool is_debug_or_control(Operand op) {
	return (op.type & OT_REGTYPE) & (OT_CONTROLREG | OT_DEBUGREG);
}

static ut8 getsib(const ut8 sib) {
	if (!sib) {
		return 0;
	}
	return (sib & 0x8) ? 3 : getsib ((sib << 1) | 1) - 1;
}

static int is_al_reg(const Operand *op) {
	if (op->type & OT_MEMORY) {
		return 0;
	}
	if (op->reg == X86R_AL && op->type & OT_BYTE && !op->extended) {
		return 1;
	}
	return 0;
}

static int oprep(RArchSession *a, ut8 *data, const Opcode *op);

// Minimal VEX.3 prefix emission for selected BMI2 GPR ops (SHLX/SHRX/SARX)
// Encodes: VEX.NDS.LZ.0F38.Wx with computed R', X', B', vvvv'
static int emit_vex3_prefix_bmi2(ut8 *data, int w, int pp, int vreg, const Operand *dst, const Operand *src) {
	int l = 0;
	// VEX 3-byte: C4, RXBmmmmm, WvvvvLpp
	data[l++] = 0xC4;
	// m-mmmm = 0x02 -> 0F 38 map
	const int mmmmm = 0x02;
	// R' X' B' are inverted bits
	int R = (dst && (dst->extended)) ? 1 : 0;
	int B = 0;
	int X = 0;
	// Determine B and X from src (r/m side) when it's a GP reg
	if (src) {
		if ((src->type & OT_GPREG) && !(src->type & OT_MEMORY)) {
			B = src->extended ? 1 : 0;
		} else {
			// For memory addressing, this assembler doesn't track per-base/index extension flags
			// Use 0 (no extension) which is fine for low regs; extended bases won't be supported here.
			B = 0;
			X = 0;
		}
	}
	ut8 vex2 = ((R ? 0 : 1) << 7) | ((X ? 0 : 1) << 6) | ((B ? 0 : 1) << 5) | (mmmmm & 0x1f);
	data[l++] = vex2;
	// vvvv is first source (count register), encode 1's complement in bits 6..3
	int vvvv = vreg & 0x0f; // include high bit via extended flag in caller
	ut8 vex3 = ((w & 1) << 7) | (((~vvvv) & 0x0f) << 3) | (0 << 2) | (pp & 3);
	data[l++] = vex3;
	return l;
}

// Encode SHLX/SHRX/SARX (BMI2):
//   SHLX r32a, r/m32, r32b  => VEX.NDS.LZ.0F38.W0 F7 /r
//   SHRX r32a, r/m32, r32b  => VEX.NDS.LZ.0F38.W0 F7 /r (pp distinguishes)
//   SARX r32a, r/m32, r32b  => VEX.NDS.LZ.0F38.W0 F7 /r (pp distinguishes)
// Same for r64 with W1. We use VEX.pp to distinguish the variants:
//   SHLX: pp = 0 (none)
//   SARX: pp = 2 (F3)
//   SHRX: pp = 3 (F2)
static int opshiftx(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands_count != 3) {
		return -1;
	}
	// Validate operand classes
	const Operand *dst = &op->operands[0];
	const Operand *src = &op->operands[1];
	const Operand *cnt = &op->operands[2];
	if (!(dst->type & OT_GPREG) || (dst->type & OT_MEMORY)) {
		return -1;
	}
	if (!((src->type & OT_GPREG) || (src->type & OT_MEMORY))) {
		return -1;
	}
	if (!(cnt->type & OT_GPREG) || (cnt->type & OT_MEMORY)) {
		return -1;
	}

	// Size checks: only 32/64-bit are valid
	const bool is64 = (dst->type & OT_QWORD) || (src->type & OT_QWORD) || (cnt->type & OT_QWORD);
	if (!((dst->type & (OT_DWORD | OT_QWORD)) && (src->type & (OT_DWORD | OT_QWORD)) && (cnt->type & (OT_DWORD | OT_QWORD)))) {
		return -1;
	}

	int l = 0;
	int pp;
	if (!strcmp (op->mnemonic, "shlx")) {
		pp = 0; // no legacy prefix
	} else if (!strcmp (op->mnemonic, "sarx")) {
		pp = 2; // F3
	} else if (!strcmp (op->mnemonic, "shrx")) {
		pp = 3; // F2
	} else {
		return -1;
	}

	// Build VEX.3 prefix
	int vreg = (cnt->extended ? 8 : 0) | (cnt->reg & 7);
	l += emit_vex3_prefix_bmi2 (data + l, is64 ? 1 : 0, pp, vreg, dst, src);

	// Opcode bytes: 0F 38 F7
	data[l++] = 0x0f;
	data[l++] = 0x38;
	data[l++] = 0xf7;

	// ModRM/SIB for (dst, src)
	int modrm = 0;
	if (src->type & OT_MEMORY) {
		// Only simple [base + disp] addressing here
		int base = src->regs[0];
		int disp = (int)(src->offset * src->offset_sign);
		int mod = 0;
		if (base == X86R_UNDEFINED) {
			// rip-relative unsupported here for VEX; use absolute disp32
			modrm = (0 << 6) | ((dst->reg & 7) << 3) | 5;
			data[l++] = (ut8)modrm;
			data[l++] = (ut8)disp;
			data[l++] = (ut8)(disp >> 8);
			data[l++] = (ut8)(disp >> 16);
			data[l++] = (ut8)(disp >> 24);
			return l;
		}
		if (disp != 0) {
			if (disp >= -128 && disp <= 127) mod = 1; else mod = 2;
		}
		modrm = (mod << 6) | ((dst->reg & 7) << 3) | (base & 7);
		data[l++] = (ut8)modrm;
		if (base == X86R_ESP) {
			data[l++] = 0x24; // SIB for [esp]
		}
		if (mod) {
			data[l++] = (ut8)disp;
			if (mod == 2) {
				data[l++] = (ut8)(disp >> 8);
				data[l++] = (ut8)(disp >> 16);
				data[l++] = (ut8)(disp >> 24);
			}
		}
	} else {
		// register source
		modrm = 0xC0 | ((dst->reg & 7) << 3) | (src->reg & 7);
		data[l++] = (ut8)modrm;
	}
	return l;
}

static int process_16bit_group_1(RArchSession *a, ut8 *data, const Opcode *op, int op1) {
	is_valid_registers (op);
	int l = 0;
	int immediate = op->operands[1].immediate * op->operands[1].sign;

	data[l++] = 0x66;
	if (op->operands[0].extended) {
		data[l++] = 0x41;
	}
	if (op->operands[1].immediate < 128) {
		data[l++] = 0x83;
		data[l++] = op->operands[0].reg | (0xc0 + op1 + op->operands[0].reg);
	} else {
		if (op->operands[0].reg == X86R_AX) {
			data[l++] = 0x05 + op1;
		} else {
			data[l++] = 0x81;
			data[l++] = (0xc0 + op1) | op->operands[0].reg;
		}
	}
	data[l++] = immediate;
	if (op->operands[1].immediate > 127) {
		data[l++] = immediate >> 8;
	}

	return l;
}

static int process_group_1(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int offset = 0;
	int mem_ref = 0;
	st32 immediate = 0;

	if (!op->operands[1].is_good_flag) {
		return -1;
	}
	if (a->config->bits == 64 && op->operands[0].type & OT_QWORD) {
		data[l++] = (op->operands[0].extended)? 0x49: 0x48;
	}
	if (!strcmp (op->mnemonic, "adc")) {
		modrm = 2;
	} else if (!strcmp (op->mnemonic, "add")) {
		modrm = 0;
	} else if (!strcmp (op->mnemonic, "or")) {
		modrm = 1;
	} else if (!strcmp (op->mnemonic, "and")) {
		modrm = 4;
	} else if (!strcmp (op->mnemonic, "xor")) {
		modrm = 6;
	} else if (!strcmp (op->mnemonic, "sbb")) {
		modrm = 3;
	} else if (!strcmp (op->mnemonic, "sub")) {
		modrm = 5;
	} else if (!strcmp (op->mnemonic, "cmp")) {
		modrm = 7;
	}
	immediate = op->operands[1].immediate * op->operands[1].sign;

	ut32 op0type = op->operands[0].type;
	if (op0type & OT_DWORD || op0type & OT_QWORD) {
		if ((st64)op->operands[1].immediate < 128) {
			data[l++] = 0x83;
		} else if (op->operands[0].reg != X86R_EAX || op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x81;
		}
	} else if (op0type & OT_BYTE) {
		if ((st64)op->operands[1].immediate > 255) {
			R_LOG_ERROR ("Immediate exceeds bounds");
			return -1;
		}
		if (op->operands[0].rex_prefixed) {
			data[l++] = 0x40;
		} else if (op->operands[0].extended) {
			data[l++] = 0x41;
		}
		data[l++] = 0x80;
	}
	if (op->operands[0].type & OT_MEMORY) {
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (op->operands[0].offset || op->operands[0].regs[0] == X86R_EBP) {
			mod_byte = 1;
		}
		if (offset < ST8_MIN || offset > ST8_MAX) {
			mod_byte = 2;
		}
		int reg0 = op->operands[0].regs[0];
		if (reg0 == -1) {
			mem_ref = 1;
			reg0 = 5;
			mod_byte = 0;
		}
		data[l++] = mod_byte << 6 | modrm << 3 | reg0;
		if (op->operands[0].regs[0] == X86R_ESP) {
			data[l++] = 0x24;
		}
		if (mod_byte || mem_ref) {
			data[l++] = offset;
			if (mod_byte == 2 || mem_ref) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	} else {
		if (op->operands[1].immediate > 127 && op->operands[0].reg == X86R_EAX) {
			data[l++] = 5 | modrm << 3 | op->operands[0].reg;
		} else {
			mod_byte = 3;
			data[l++] = mod_byte << 6 | modrm << 3 | op->operands[0].reg;
		}

	}

	data[l++] = immediate;
	if ((immediate > 127 || immediate < -128) && (op->operands[0].type & (OT_DWORD | OT_QWORD))) {
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int process_group_2(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int reg0 = 0;

	if (a->config->bits == 64 && op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	}

	if (!strcmp (op->mnemonic, "rol")) {
		modrm = 0;
	} else if (!strcmp (op->mnemonic, "ror")) {
		modrm = 1;
	} else if (!strcmp (op->mnemonic, "rcl")) {
		modrm = 2;
	} else if (!strcmp (op->mnemonic, "rcr")) {
		modrm = 3;
	} else if (!strcmp (op->mnemonic, "shl")) {
		modrm = 4;
	} else if (!strcmp (op->mnemonic, "shr")) {
		modrm = 5;
	} else if (!strcmp (op->mnemonic, "sal")) {
		modrm = 6;
	} else if (!strcmp (op->mnemonic, "sar")) {
		modrm = 7;
	}

	st32 immediate = op->operands[1].immediate * op->operands[1].sign;
	if (immediate > 255 || immediate < -128) {
		R_LOG_ERROR ("Immediate exceeds bounds");
		return -1;
	}

	if (op->operands[0].type & (OT_DWORD | OT_QWORD)) {
		if (op->operands[1].type & (OT_GPREG | OT_BYTE)) {
			data[l++] = 0xd3;
		} else if (immediate == 1) {
			data[l++] = 0xd1;
		} else {
			data[l++] = 0xc1;
		}
	} else if (op->operands[0].type & OT_BYTE) {
		const Operand *o = &op->operands[0];
		if (o->regs[0] != -1 && o->regs[1] != -1) {
			data[l++] = 0xc0;
			data[l++] = 0x44;
			data[l++] = o->regs[0] | (o->regs[1]<<3);
			data[l++] = (ut8)((o->offset*o->offset_sign) & 0xff);
			data[l++] = immediate;
			return l;
		} else if (op->operands[1].type & (OT_GPREG | OT_WORD)) {
			data[l++] = 0xd2;
		} else if (immediate == 1) {
			data[l++] = 0xd0;
		} else {
			data[l++] = 0xc0;
		}
	}
	if (op->operands[0].type & OT_MEMORY) {
		reg0 = op->operands[0].regs[0];
		mod_byte = 0;
	} else {
		reg0 = op->operands[0].reg;
		mod_byte = 3;
	}
	data[l++] = mod_byte << 6 | modrm << 3 | reg0;
	if (immediate != 1 && !(op->operands[1].type & OT_GPREG)) {
		data[l++] = immediate;
	}
	return l;
}

static int process_1byte_op(RArchSession *a, ut8 *data, const Opcode *op, int op1) {
	is_valid_registers (op);
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	int rex = 0;
	int mem_ref = 0;
	st32 offset = 0;
	int ebp_reg = 0;

	if (!op->operands[1].is_good_flag) {
		return -1;
	}
	if (op->operands[0].rex_prefixed) {
		data[l++] = 0x40;
	}
	if (op->operands[0].reg == X86R_AL && op->operands[1].type & OT_CONSTANT) {
		data[l++] = op1 + 4;
		data[l++] = op->operands[1].immediate * op->operands[1].sign;
		return l;
	}

	const int bits = a->config->bits;
	if (bits == 64) {
		if (!(op->operands[0].type & op->operands[1].type)) {
			return -1;
		}
	}

	if (bits == 64 && ((op->operands[0].type & OT_QWORD) | (op->operands[1].type & OT_QWORD))) {
		if (op->operands[0].extended) {
				rex = 1;
		}
		if (op->operands[1].extended) {
			rex += 4;
		}
		data[l++] = 0x48 | rex;
	}

	if (op->operands[0].type & OT_MEMORY && op->operands[1].type & OT_REGALL) {
		if (bits == 64 && (op->operands[0].type & OT_DWORD)
				&& (op->operands[1].type & OT_DWORD)) {
			data[l++] = 0x67;
		}
		if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
			data[l++] = op1;
		} else if (op->operands[0].type & (OT_DWORD | OT_QWORD)
				&& op->operands[1].type & (OT_DWORD | OT_QWORD)) {
			data[l++] = op1 + 0x1;
		} else {
			R_LOG_ERROR ("mismatched operand sizes");
			return -1;
		}
		reg = op->operands[1].reg;
		rm = op->operands[0].regs[0];
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (rm == -1) {
			rm = 5;
			mem_ref = 1;
		} else {
			if (offset) {
				mod_byte = 1;
				if (offset < ST8_MIN || offset > ST8_MAX) {
					mod_byte = 2;
				}
			} else if (op->operands[0].regs[1] != X86R_UNDEFINED) {
				rm = 4;
				offset = op->operands[0].regs[1] << 3;
			}
		}
	} else if (op->operands[0].type & OT_REGALL) {
		if (op->operands[1].type & OT_MEMORY) {
			if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
				data[l++] = op1 + 0x2;
			} else if (op->operands[0].type & (OT_DWORD | OT_QWORD)
					&& op->operands[1].type & (OT_DWORD | OT_QWORD)) {
				data[l++] = op1 + 0x3;
			} else {
				R_LOG_ERROR ("mismatched operand sizes");
				return -1;
			}
			reg = op->operands[0].reg;
			rm = op->operands[1].regs[0];

			if (op->operands[1].scale[0] > 1) {
				if (op->operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[0].reg << 3 | 4;
					data[l++] = getsib (op->operands[1].scale[0]) << 6
							| op->operands[1].regs[0] << 3
							| op->operands[1].regs[1];
					return l;
				}
				data[l++] = op->operands[0].reg << 3 | 4; // 4 = SIB
				data[l++] = getsib (op->operands[1].scale[0]) << 6
						| op->operands[1].regs[0] << 3
						| 5;
				data[l++] = op->operands[1].offset * op->operands[1].offset_sign;
				data[l++] = 0;
				data[l++] = 0;
				data[l++] = 0;
				return l;
			}
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (offset) {
				mod_byte = 1;
				if (offset < ST8_MIN || offset > ST8_MAX) {
					mod_byte = 2;
				}
			}
		} else if (op->operands[1].type & OT_REGALL) {
			if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
				data[l++] = op1;
			} else if (op->operands[0].type & (OT_WORD | OT_DWORD) && op->operands[1].type & (OT_WORD | OT_DWORD)) {
				if (op->operands[0].type & OT_WORD) {
					data[l++] = 0x66;
				}
				data[l++] = op1 + 0x1;
			}
			if (bits == 64) {
				if (op->operands[0].type & OT_QWORD &&
					op->operands[1].type & OT_QWORD) {
					data[l++] = op1 + 0x1;
				}
			}
			mod_byte = 3;
			reg = op->operands[1].reg;
			rm = op->operands[0].reg;
		}
	}
	if (op->operands[0].regs[0] == X86R_EBP || op->operands[1].regs[0] == X86R_EBP) {
		//reg += 8;
		ebp_reg = 1;
	}
	data[l++] = mod_byte << 6 | reg << 3 | rm;

	if (op->operands[0].regs[0] == X86R_ESP || op->operands[1].regs[0] == X86R_ESP) {
		data[l++] = 0x24;
	}
	if (offset || mem_ref || ebp_reg) {
	// if ((mod_byte > 0 && mod_byte < 3) || mem_ref) {
		data[l++] = offset;
		if (mod_byte == 2 || mem_ref) {
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opadc(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x10);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x10);
}

static int opadd(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x00);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x00);
}

static int opand(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x20);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x20);
}

static int opcmp(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x38);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x38);
}

static int opsub(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x28);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x28);
}

static int opor(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x08);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x08);
}

static int opxadd(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int i = 0;
	if (op->operands_count < 2) {
		return -1;
	}
	if (a->config->bits == 64) {
		data[i++] = 0x48;
	};
	data[i++] = 0x0f;
	if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
		data[i++] = 0xc0;
	} else {
		data[i++] = 0xc1;
	}
	if (op->operands[0].type & OT_REGALL && op->operands[1].type & OT_REGALL) { // TODO memory modes
		data[i] |= 0xc0;
		data[i] |= (op->operands[1].reg << 3);
		data[i++] |= op->operands[0].reg;
	}
	return i;
}

static int opxor(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	if (op->operands_count < 2) {
		return -1;
	}
	if (op->operands[0].type == 0x80 && op->operands[0].reg == X86R_UNDEFINED) {
		return -1;
	}
	if (op->operands[1].type == 0x80 && op->operands[0].reg == X86R_UNDEFINED) {
		return -1;
	}
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x30);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x30);
}

static int opneg(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;

	if ((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
		} else if (op->operands[0].type & OT_QWORD)  {
			data[l++] = 0x48;
		}

		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		data[l++] = 0xd8 | op->operands[0].reg;
		return l;
	}
	return -1;
}

static int endbr64(RArchSession *a, ut8 *data, const Opcode *op) {
	memcpy (data, "\xf3\x0f\x1e\xfa", 4);
	return 4;
}

static int endbr32(RArchSession *a, ut8 *data, const Opcode *op) {
	memcpy (data, "\xf3\x0f\x1e\xfb", 4);
	return 4;
}

static int opnot(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;

	if (op->operands[0].reg == X86R_UNDEFINED)  {
		return -1;
	}

	int size = op->operands[0].type & ALL_SIZE;
	if (op->operands[0].explicit_size) {
		size = op->operands[0].dest_size;
	}
	//rex prefix
	int rex = 1 << 6;
	bool use_rex = false;
	if (size & OT_QWORD) {			//W field
		use_rex = true;
		rex |= 1 << 3;
	}
	if (op->operands[0].extended) {		//B field
		use_rex = true;
		rex |= 1;
	}

	if (use_rex) {
		data[l++] = rex;
	}
	data[l++] = 0xf7;
	data[l++] = 0xd0 | op->operands[0].reg;

	return l;
}

static int opsbb(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x18);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x18);
}

static int opbs(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (a->config->bits >= 32 && op->operands[1].type & OT_MEMORY && op->operands[1].reg_size & OT_WORD) {
		return -1;
	}
	if (!(op->operands[1].type & OT_MEMORY)
			&& !((op->operands[0].type & ALL_SIZE)
				== (op->operands[1].type & ALL_SIZE))) {
		return -1;
	}
	if (!(op->operands[0].type & OT_GPREG) || (op->operands[0].type & OT_MEMORY)) {
		return -1;
	}

	// Prefixes and operand/address size handling
	if (a->config->bits == 64) {
		if (op->operands[1].type & OT_MEMORY && (op->operands[1].reg_size & OT_DWORD)) {
			// 32-bit addressing in 64-bit mode
			data[l++] = 0x67;
		}
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_QWORD) {
			data[l++] = 0x48;
		}
	} else if (op->operands[0].type & OT_WORD) {
		data[l++] = 0x66;
	}

	// Opcode 0F BC (BSF) / 0F BD (BSR)
	data[l++] = 0x0f;
	data[l++] = (!strcmp (op->mnemonic, "bsf")) ? 0xbc : 0xbd;

	// Build ModRM/SIB depending on r/m (second operand)
	if (op->operands[1].type & OT_GPREG && !(op->operands[1].type & OT_MEMORY)) {
		// register source: mod=11, reg=dest, r/m=src
		data[l++] = 0xc0 | (op->operands[0].reg << 3) | (op->operands[1].reg & 7);
		return l;
	}

	// memory source
	int base = op->operands[1].regs[0];
	int index = op->operands[1].regs[1];
	int disp = (int)(op->operands[1].offset * op->operands[1].offset_sign);
	int mod = 0;
	int rm = 0;
	bool use_sib = false;
	ut8 sib = 0;

	if (base == X86R_UNDEFINED) {
		// disp32 only: rm = 101, mod = 00, followed by disp32
		rm = 5;
		mod = 0;
	} else {
		rm = base;
		if (disp != 0) {
			if (disp >= -128 && disp <= 127) {
				mod = 1;
			} else {
				mod = 2;
			}
		}
		if (index != X86R_UNDEFINED) {
			use_sib = true;
			int sc = getsib (op->operands[1].scale[1]);
			sib = (ut8)((sc << 6) | ((index & 7) << 3) | (rm & 7));
			rm = 4; // use SIB
		} else if (rm == X86R_ESP) {
			use_sib = true;
			sib = 0x24; // [esp] no index
			rm = 4;
		}
		// [ebp] alone is encoded as [ebp + disp8 = 0]
		if (rm == 5 && mod == 0 && !use_sib) {
			mod = 1;
			disp = 0;
		}
	}

	data[l++] = (ut8)((mod << 6) | ((op->operands[0].reg & 7) << 3) | (rm & 7));
	if (use_sib) {
		data[l++] = sib;
	}
	if (base == X86R_UNDEFINED) {
		// absolute disp32
		data[l++] = (ut8)disp;
		data[l++] = (ut8)(disp >> 8);
		data[l++] = (ut8)(disp >> 16);
		data[l++] = (ut8)(disp >> 24);
	} else if (mod == 1) {
		data[l++] = (ut8)disp;
	} else if (mod == 2) {
		data[l++] = (ut8)disp;
		data[l++] = (ut8)(disp >> 8);
		data[l++] = (ut8)(disp >> 16);
		data[l++] = (ut8)(disp >> 24);
	}

	return l;
}

static int opbswap(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[0].type & OT_REGALL) {
		is_valid_registers (op);
		if (op->operands[0].reg == X86R_UNDEFINED) {
			return -1;
		}

		if (op->operands[0].type & OT_QWORD) {
			if (op->operands[0].extended) {
				data[l++] = 0x49;
			} else {
				data[l++] = 0x48;
			}
			data[l++] = 0x0f;
			data[l++] = 0xc8 + op->operands[0].reg;
		} else if (op->operands[0].type & OT_DWORD) {
			if (op->operands[0].extended) {
				data[l++] = 0x41;
			}
			data[l++] = 0x0f;
			data[l++] = 0xc8 + op->operands[0].reg;
		} else {
			return -1;
		}
	}
	return l;
}

static int opcall(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int immediate = 0;
	int offset = 0;
	int mod = 0;

	if ((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY)) {
		if (op->operands[0].reg == X86R_UNDEFINED) {
			return -1;
		}
		if (a->config->bits == 64 && op->operands[0].extended) {
			data[l++] = 0x41;
		}
		data[l++] = 0xff;
		mod = 3;
		data[l++] = mod << 6 | 2 << 3 | op->operands[0].reg;
	} else if (op->operands[0].type & OT_MEMORY) {
		// Memory-indirect CALL: handles [reg + disp], [disp32], and RIP-relative (x86-64)
		if (a->config->bits == 64 && op->operands[0].extended) {
			data[l++] = 0x41;
		}
		data[l++] = 0xff;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset) {
			mod = 1;
			if (offset > 127 || offset < -128) {
				mod = 2;
			}
		}
		int reg0 = op->operands[0].regs[0];
		// Special case: RIP-relative in 64-bit: call [rip+disp32]
		if (reg0 == 8) { // X86R_RIP
			mod = 2;
			data[l++] = 0x15;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		}
		// Absolute disp32 (no base register): call dword [0xNNNNNNNN]
		if (reg0 == X86R_UNDEFINED) {
			// Only valid/expected in 32-bit mode; reject on 64-bit
			if (a->config->bits == 64) {
				return -1;
			}
			mod = 0;
			data[l++] = (mod << 6) | (2 << 3) | 5; // rm=101b -> disp32
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		}
		// General [reg + disp] addressing
		data[l++] = (mod << 6) | (2 << 3) | reg0;
		// SIB needed for ESP/RSP base
		if (reg0 == X86R_ESP) {
			data[l++] = 0x24;
		}
		if (mod) {
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	} else {
		ut64 instr_offset = op->addr;
		data[l++] = 0xe8;
		immediate = op->operands[0].immediate * op->operands[0].sign;
		immediate -= instr_offset + 5;
		data[l++] = immediate;
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int opcmov(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int mod_byte = 0;
	int offset = 0;

	if (op->operands[0].type & OT_MEMORY || op->operands[1].type & OT_CONSTANT) {
		return -1;
	}

	data[l++] = 0x0f;
	char *cmov = op->mnemonic + 4;
	if (!strcmp (cmov, "o")) {
		data[l++] = 0x40;
	} else if (!strcmp (cmov, "no")) {
		data [l++] = 0x41;
	} else if (!strcmp (cmov, "b")
			|| !strcmp (cmov, "c")
			|| !strcmp (cmov, "nae")) {
		data [l++] = 0x42;
	} else if (!strcmp (cmov, "ae")
			|| !strcmp (cmov, "nb")
			|| !strcmp (cmov, "nc")) {
		data [l++] = 0x43;
	} else if (!strcmp (cmov, "e")
			|| !strcmp (cmov, "z")) {
		data [l++] = 0x44;
	} else if (!strcmp (cmov, "ne")
			|| !strcmp (cmov, "nz")) {
		data [l++] = 0x45;
	} else if (!strcmp (cmov, "be")
			|| !strcmp (cmov, "na")) {
		data [l++] = 0x46;
	} else if (!strcmp (cmov, "a")
			|| !strcmp (cmov, "nbe")) {
		data [l++] = 0x47;
	} else if (!strcmp (cmov, "s")) {
		data [l++] = 0x48;
	} else if (!strcmp (cmov, "ns")) {
		data [l++] = 0x49;
	} else if (!strcmp (cmov, "p")
			|| !strcmp (cmov, "pe")) {
		data [l++] = 0x4a;
	} else if (!strcmp (cmov, "np")
			|| !strcmp (cmov, "po")) {
		data [l++] = 0x4b;
	} else if (!strcmp (cmov, "l")
			|| !strcmp (cmov, "nge")) {
		data [l++] = 0x4c;
	} else if (!strcmp (cmov, "ge")
			|| !strcmp (cmov, "nl")) {
		data [l++] = 0x4d;
	} else if (!strcmp (cmov, "le")
			|| !strcmp (cmov, "ng")) {
		data [l++] = 0x4e;
	} else if (!strcmp (cmov, "g")
			|| !strcmp (cmov, "nle")) {
		data [l++] = 0x4f;
	}

	if (op->operands[0].type & OT_REGALL) {
		if (op->operands[1].type & OT_MEMORY) {
			if (op->operands[1].scale[0] > 1) {
				if (op->operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[0].reg << 3 | 4;
					data[l++] = getsib (op->operands[1].scale[0]) << 6
							| op->operands[1].regs[0] << 3
							| op->operands[1].regs[1];
					return l;
				}
				offset = op->operands[1].offset * op->operands[1].offset_sign;

				if (op->operands[1].scale[0] == 2 && offset) {
					data[l++] = 0x40 | op->operands[0].reg << 3 | 4; // 4 = SIB
				} else {
					data[l++] = op->operands[0].reg << 3 | 4; // 4 = SIB
				}


				if (op->operands[1].scale[0] == 2) {
					data[l++] = op->operands[1].regs[0] << 3 | op->operands[1].regs[0];

				} else {
					data[l++] = getsib (op->operands[1].scale[0]) << 6
							| op->operands[1].regs[0] << 3
							| 5;
				}

				if (offset) {
					data[l++] = offset;
					if (offset < ST8_MIN || offset > ST8_MAX) {
						data[l++] = offset >> 8;
						data[l++] = offset >> 16;
						data[l++] = offset >> 24;
					}
				}
				return l;
			}
			if (op->operands[1].regs[1] != X86R_UNDEFINED) {
				data[l++] = op->operands[0].reg << 3 | 4;
				data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
				return l;
			}

			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (op->operands[1].offset || op->operands[1].regs[0] == X86R_EBP) {
				mod_byte = 1;
			}
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}

			data[l++] = mod_byte << 6 | op->operands[0].reg << 3 | op->operands[1].regs[0];

			if (mod_byte) {
				data[l++] = offset;
				if (mod_byte == 2) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		} else {
			data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
		}
	}

	return l;
}

static int opmovx(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int word = 0;
	char *movx = op->mnemonic + 3;

	if (!(op->operands[0].type & OT_REGTYPE && op->operands[1].type & OT_MEMORY)) {
		return -1;
	}
	if (op->operands[1].type & OT_WORD) {
		word = 1;
	}

	data[l++] = 0x0f;
	if (!strcmp (movx, "zx")) {
		data[l++] = 0xb6 + word;
	} else if (!strcmp (movx, "sx")) {
		data[l++] = 0xbe + word;
	}
	data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
	if (op->operands[1].regs[0] == X86R_ESP) {
		data[l++] = 0x24;
	}

	return l;
}

static int opaam(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int immediate = op->operands[0].immediate * op->operands[0].sign;
	data[l++] = 0xd4;
	if (immediate == 0) {
		data[l++] = 0x0a;
	} else if (immediate < 256 && immediate > -129) {
		data[l++] = immediate;
	}
	return l;
}

static int opdec(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type) {
		R_LOG_ERROR ("Invalid operands");
		return -1;
	}
	is_valid_registers (op);
	int l = 0;
	int size = op->operands[0].type & ALL_SIZE;
	if (op->operands[0].explicit_size) {
		size = op->operands[0].dest_size;
	}

	if (size & OT_WORD) {
		data[l++] = 0x66;
	}

	//rex prefix
	int rex = 1 << 6;
	bool use_rex = false;
	if (size & OT_QWORD) {			//W field
		use_rex = true;
		rex |= 1 << 3;
	}
	if (op->operands[0].extended) {		//B field
		use_rex = true;
		rex |= 1;
	}

	//opcode selection
	int opcode;
	if (size & OT_BYTE) {
		opcode = 0xfe;
	} else {
		opcode = 0xff;
	}

	if (!(op->operands[0].type & OT_MEMORY)) {
		if (use_rex) {
			data[l++] = rex;
		}
		if (a->config->bits > 32 || size & OT_BYTE) {
			data[l++] = opcode;
		}
		if (a->config->bits == 32 && size & (OT_DWORD | OT_WORD)) {
			data[l++] = 0x48 | op->operands[0].reg;
		} else {
			data[l++] = 0xc8 | op->operands[0].reg;
		}
		return l;
	}

	//modrm and SIB selection
	bool rip_rel = op->operands[0].regs[0] == X86R_RIP;
	int offset = op->operands[0].offset * op->operands[0].offset_sign;
	int modrm = 0;
	int mod;
	int reg = 0;
	int rm;
	bool use_sib = false;
	int sib = 0;
	//mod
	if (offset == 0) {
		mod = 0;
	} else if (offset < 128 && offset > -129) {
		mod = 1;
	} else {
		mod = 2;
	}

	if (op->operands[0].regs[0] & OT_WORD) {
		if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_SI) {
			rm = B0000;
		} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_DI) {
			rm = B0001;
		} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_SI) {
			rm = B0010;
		} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_DI) {
			rm = B0011;
		} else if (op->operands[0].regs[0] == X86R_SI && op->operands[0].regs[1] == -1) {
			rm = B0100;
		} else if (op->operands[0].regs[0] == X86R_DI && op->operands[0].regs[1] == -1) {
			rm = B0101;
		} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == -1) {
			rm = B0111;
		} else {
			//TODO allow for displacement only when parser is reworked
			return -1;
		}
		modrm = (mod << 6) | (reg << 3) | rm;
	} else {
		//rm
		if (op->operands[0].extended) {
			rm = op->operands[0].reg;
		} else {
			rm = op->operands[0].regs[0];
		}
		//[ebp] alone is illegal, so we need to fake a [ebp+0]
		if (rm == 5 && mod == 0) {
			mod = 1;
		}

		//sib
		int index = op->operands[0].regs[1];
		int scale = getsib(op->operands[0].scale[1]);
		if (index != -1) {
			use_sib = true;
			sib = (scale << 6) | (index << 3) | rm;
		} else if (rm == 4) {
			use_sib = true;
			sib = 0x24;
		}
		if (use_sib) {
			rm = B0100;
		}
		if (rip_rel) {
			modrm = (B0000 << 6) | (reg << 3) | B0101;
			sib = (scale << 6) | (B0100 << 3) | B0101;
		} else {
			modrm = (mod << 6) | (reg << 3) | rm;
		}
		modrm |= 1<<3;
	}

	if (use_rex) {
		data[l++] = rex;
	}
	data[l++] = opcode;
	data[l++] = modrm;
	if (use_sib) {
		data[l++] = sib;
	}
	//offset
	if (mod == 1) {
		data[l++] = offset;
	} else if (op->operands[0].regs[0] & OT_WORD && mod == 2) {
		data[l++] = offset;
		data[l++] = offset >> 8;
	} else if (mod == 2 || rip_rel) {
		data[l++] = offset;
		data[l++] = offset >> 8;
		data[l++] = offset >> 16;
		data[l++] = offset >> 24;
	}

	return l;
}

static int opidiv(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;

	if (op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xf8 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opdiv(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;

	if (op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xf0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opimul(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int offset = 0;
	st64 immediate = 0;

	if (op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	} else if (op->operands[0].type & OT_WORD) {
		data[l++] = 0x66;
	}
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x28 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xe8 | op->operands[0].reg;
		}
		break;
	case 2:
		if ((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY)) {
			if (op->operands[1].type & OT_CONSTANT) {
				if (op->operands[1].immediate == -1) {
					R_LOG_ERROR ("Immediate exceeds max");
					return -1;
				}
				immediate = op->operands[1].immediate * op->operands[1].sign;
				if (op->operands[0].type & OT_GPREG) {
					if (immediate >= 128) {
						data[l++] = 0x69;
					} else {
						data[l++] = 0x6b;
					}
					data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[0].reg;
					data[l++] = immediate;
					if (immediate >= 128) {
						data[l++] = immediate >> 8;
						data[l++] = immediate >> 16;
						data[l++] = immediate >> 24;
					}
					if (a->config->bits == 64 && immediate > UT32_MAX) {
						data[l++] = immediate >> 32;
						data[l++] = immediate >> 40;
						data[l++] = immediate >> 48;
						data[l++] = immediate >> 56;
					}
				}
			} else if (op->operands[1].type & OT_MEMORY) {
				data[l++] = 0x0f;
				data[l++] = 0xaf;
				if (op->operands[1].regs[0] != X86R_UNDEFINED) {
					offset = op->operands[1].offset * op->operands[1].offset_sign;
					if (offset != 0) {
						if (offset >= 128 || offset <= -128) {
							data[l] = 0x80;
						} else {
							data[l] = 0x40;
						}
						data[l++] |= op->operands[0].reg << 3 | op->operands[1].regs[0];
						data[l++] = offset;
						if (offset >= 128 || offset <= -128) {
							data[l++] = offset >> 8;
							data[l++] = offset >> 16;
							data[l++] = offset >> 24;
						}
					} else {
						if (op->operands[1].regs[1] != X86R_UNDEFINED) {
							data[l++] = 0x04 | op->operands[0].reg << 3;
							data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
						} else {
							data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
						}
					}
				} else {
					immediate = op->operands[1].immediate * op->operands[1].sign;
					data[l++] = op->operands[0].reg << 3 | 0x5;
					data[l++] = immediate;
					data[l++] = immediate >> 8;
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
			} else if (op->operands[1].type & OT_GPREG) {
				data[l++] = 0x0f;
				data[l++] = 0xaf;
				data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
			}
		}
		break;
	case 3:
		if (((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY))
				&& (op->operands[1].type & OT_GPREG || op->operands[1].type & OT_MEMORY)
				&& op->operands[2].type & OT_CONSTANT) {
			data[l++] = 0x6b;
			if (op->operands[1].type & OT_MEMORY) {
				if (op->operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = 0x04 | op->operands[0].reg << 3;
					data[l++] = op->operands[1].regs[0] |  op->operands[1].regs[1] << 3;
				} else {
					offset = op->operands[1].offset * op->operands[1].offset_sign;
					if (offset != 0) {
						if (offset >= 128 || offset <= -128) {
							data[l] = 0x80;
						} else {
							data[l] = 0x40;
						}
						data[l++] |= op->operands[0].reg << 3;
						data[l++] = offset;
						if (offset >= 128 || offset <= -128) {
							data[l++] = offset >> 8;
							data[l++] = offset >> 16;
							data[l++] = offset >> 24;
						}
					} else {
						data[l++] = 0x00 | op->operands[0].reg << 3 | op->operands[1].regs[0];
					}
				}
			} else {
				data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
			}
			immediate = op->operands[2].immediate * op->operands[2].sign;
			data[l++] = immediate;
			if (immediate >= 128 || immediate <= -128) {
				data[l++] = immediate >> 8;
				data[l++] = immediate >> 16;
				data[l++] = immediate >> 24;
			}
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opin(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	st32 immediate = 0;
	if (op->operands[1].reg == X86R_DX) {
		if (op->operands[0].reg == X86R_AL &&
			op->operands[0].type & OT_BYTE) {
			data[l++] = 0xec;
			return l;
		}
		if (op->operands[0].reg == X86R_AX &&
			op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xed;
			return l;
		}
		if (op->operands[0].reg == X86R_EAX &&
			op->operands[0].type & OT_DWORD) {
			data[l++] = 0xed;
			return l;
		}
	} else if (op->operands[1].type & OT_CONSTANT) {
		immediate = op->operands[1].immediate * op->operands[1].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op->operands[0].reg == X86R_AL && op->operands[0].type & OT_BYTE) {
			data[l++] = 0xe4;
		} else if (op->operands[0].reg == X86R_AX && op->operands[0].type & OT_BYTE) {
			data[l++] = 0x66;
			data[l++] = 0xe5;
		} else if (op->operands[0].reg == X86R_EAX &&
			op->operands[0].type & OT_DWORD) {
			data[l++] = 0xe5;
		}
		data[l++] = immediate;
	}
	return l;
}

static int opclflush(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int offset = 0;
	int mod_byte = 0;

	if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x0f;
		data[l++] = 0xae;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset) {
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			} else {
				mod_byte = 1;
			}
		}
		data[l++] = (mod_byte << 6) | (7 << 3) | op->operands[0].regs[0];
		if (mod_byte) {
			data[l++] = offset;
			if (mod_byte == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	}
	return l;
}

static int opinc(RArchSession *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type) {
		R_LOG_ERROR ("Invalid operands");
		return -1;
	}
	is_valid_registers (op);
	int l = 0;
	int size = op->operands[0].type & ALL_SIZE;
	if (op->operands[0].explicit_size) {
		size = op->operands[0].dest_size;
	}

	if (size & OT_WORD) {
		data[l++] = 0x66;
	}

	//rex prefix
	int rex = 1 << 6;
	bool use_rex = false;
	if (size & OT_QWORD) {			//W field
		use_rex = true;
		rex |= 1 << 3;
	}
	if (op->operands[0].extended) {		//B field
		use_rex = true;
		rex |= 1;
	}

	//opcode selection
	int opcode;
	if (size & OT_BYTE) {
		opcode = 0xfe;
	} else {
		opcode = 0xff;
	}

	if (!(op->operands[0].type & OT_MEMORY)) {
		if (use_rex) {
			data[l++] = rex;
		}
		if (a->config->bits > 32 || size & OT_BYTE) {
			data[l++] = opcode;
		}
		if (a->config->bits == 32 && size & (OT_DWORD | OT_WORD)) {
			data[l++] = 0x40 | op->operands[0].reg;
		} else {
			data[l++] = 0xc0 | op->operands[0].reg;
		}
		return l;
	}

	//modrm and SIB selection
	bool rip_rel = op->operands[0].regs[0] == X86R_RIP;
	int offset = op->operands[0].offset * op->operands[0].offset_sign;
	int modrm = 0;
	int mod;
	int reg = 0;
	int rm;
	bool use_sib = false;
	int sib = 0;
	//mod
	if (offset == 0) {
		mod = 0;
	} else if (offset < 128 && offset > -129) {
		mod = 1;
	} else {
		mod = 2;
	}

	if (op->operands[0].regs[0] & OT_WORD) {
		if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_SI) {
			rm = B0000;
		} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_DI) {
			rm = B0001;
		} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_SI) {
			rm = B0010;
		} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_DI) {
			rm = B0011;
		} else if (op->operands[0].regs[0] == X86R_SI && op->operands[0].regs[1] == -1) {
			rm = B0100;
		} else if (op->operands[0].regs[0] == X86R_DI && op->operands[0].regs[1] == -1) {
			rm = B0101;
		} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == -1) {
			rm = B0111;
		} else {
			//TODO allow for displacement only when parser is reworked
			return -1;
		}
		modrm = (mod << 6) | (reg << 3) | rm;
	} else {
		//rm
		if (op->operands[0].extended) {
			rm = op->operands[0].reg;
		} else {
			rm = op->operands[0].regs[0];
		}
		//[epb] alone is illegal, so we need to fake a [ebp+0]
		if (rm == 5 && mod == 0) {
			mod = 1;
		}

		//sib
		int index = op->operands[0].regs[1];
		int scale = getsib(op->operands[0].scale[1]);
		if (index != -1) {
			use_sib = true;
			sib = (scale << 6) | (index << 3) | rm;
		} else if (rm == 4) {
			use_sib = true;
			sib = 0x24;
		}
		if (use_sib) {
			rm = B0100;
		}
		if (rip_rel) {
			modrm = (B0000 << 6) | (reg << 3) | B0101;
			sib = (scale << 6) | (B0100 << 3) | B0101;
		} else {
			modrm = (mod << 6) | (reg << 3) | rm;
		}
	}

	if (use_rex) {
		data[l++] = rex;
	}
	data[l++] = opcode;
	data[l++] = modrm;
	if (use_sib) {
		data[l++] = sib;
	}
	//offset
	if (mod == 1) {
		data[l++] = offset;
	} else if (op->operands[0].regs[0] & OT_WORD && mod == 2) {
		data[l++] = offset;
		data[l++] = offset >> 8;
	} else if (mod == 2 || rip_rel) {
		data[l++] = offset;
		data[l++] = offset >> 8;
		data[l++] = offset >> 16;
		data[l++] = offset >> 24;
	}

	return l;
}

static int opint(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[0].type & OT_CONSTANT) {
		st32 immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate <= 255 && immediate >= -128) {
			data[l++] = 0xcd;
			data[l++] = immediate;
		}
	}
	return l;
}

static int opjc(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	bool is_short = op->is_short;
	// st64 bigimm = op->operands[0].immediate * op->operands[0].sign;
	st64 immediate = op->operands[0].immediate * op->operands[0].sign;
	if (is_short && (immediate > ST8_MAX || immediate < ST8_MIN)) {
		return l;
	}
	immediate -= op->addr;
	if (immediate > ST32_MAX || immediate < -ST32_MAX) {
		return -1;
	}
	if (!strcmp (op->mnemonic, "jmp")) {
		if (op->operands[0].type & OT_GPREG) {
			data[l++] = 0xff;
			if (op->operands[0].type & OT_MEMORY) {
				if (op->operands[0].offset) {
					int offset = op->operands[0].offset * op->operands[0].offset_sign;
					if (offset >= 128 || offset <= -129) {
						data[l] = 0xa0;
					} else {
						data[l] = 0x60;
					}
					data[l++] |= op->operands[0].regs[0];
					if (op->operands[0].regs[0] == X86R_ESP) {
						data[l++] = 0x24;
					}
					data[l++] = offset;
					if (op->operands[0].offset >= 0x80) {
						data[l++] = offset >> 8;
						data[l++] = offset >> 16;
						data[l++] = offset >> 24;
					}
				} else {
					data[l++] = 0x20 | op->operands[0].regs[0];
				}
			} else {
				data[l++] = 0xe0 | op->operands[0].reg;
			}
		} else {
			if (-0x80 <= (immediate - 2) && (immediate - 2) <= 0x7f) {
				/* relative byte address */
				data[l++] = 0xeb;
				data[l++] = immediate - 2;
			} else {
				/* relative address */
				immediate -= 5;
				data[l++] = 0xe9;
				data[l++] = immediate;
				data[l++] = immediate >> 8;
				data[l++] = immediate >> 16;
				data[l++] = immediate >> 24;
			}
		}
		return l;
	}
	if (immediate <= 0x81 && immediate > -0x7f) {
		is_short = true;
	}
	if (a->config->bits == 16 && (immediate > 0x81 || immediate < -0x7e)) {
		data[l++] = 0x66;
		is_short = false;
		immediate --;
	}

	if (!is_short) {
		data[l++] = 0x0f;
	}

	if (!strcmp (op->mnemonic, "ja")
			|| !strcmp (op->mnemonic, "jnbe")) {
		data[l++] = 0x87;
	} else if (!strcmp (op->mnemonic, "jae")
			|| !strcmp (op->mnemonic, "jnb")
			|| !strcmp (op->mnemonic, "jnc")) {
		data[l++] = 0x83;
	} else if (!strcmp (op->mnemonic, "jecxz") || !strcmp (op->mnemonic, "jrcxz") || !strcmp (op->mnemonic, "jcxz")) {
		data[l++] = 0xf3;
	} else if (!strcmp (op->mnemonic, "jz")
			|| !strcmp (op->mnemonic, "je")) {
		data[l++] = 0x84;
	} else if (!strcmp (op->mnemonic, "jb")
			|| !strcmp (op->mnemonic, "jnae")
			|| !strcmp (op->mnemonic, "jc")) {
		data[l++] = 0x82;
	} else if (!strcmp (op->mnemonic, "jbe")
			|| !strcmp (op->mnemonic, "jna")) {
		data[l++] = 0x86;
	} else if (!strcmp (op->mnemonic, "jg")
			|| !strcmp (op->mnemonic, "jnle")) {
		data[l++] = 0x8f;
	} else if (!strcmp (op->mnemonic, "jge")
			|| !strcmp (op->mnemonic, "jnl")) {
		data[l++] = 0x8d;
	} else if (!strcmp (op->mnemonic, "jl")
			|| !strcmp (op->mnemonic, "jnge")) {
		data[l++] = 0x8c;
	} else if (!strcmp (op->mnemonic, "jle")
			|| !strcmp (op->mnemonic, "jng")) {
		data[l++] = 0x8e;
	} else if (!strcmp (op->mnemonic, "jne")
			|| !strcmp (op->mnemonic, "jnz")) {
		data[l++] = 0x85;
	} else if (!strcmp (op->mnemonic, "jno")) {
		data[l++] = 0x81;
	} else if (!strcmp (op->mnemonic, "jnp")
			|| !strcmp (op->mnemonic, "jpo")) {
		data[l++] = 0x8b;
	} else if (!strcmp (op->mnemonic, "jns")) {
		data[l++] = 0x89;
	} else if (!strcmp (op->mnemonic, "jo")) {
		data[l++] = 0x80;
	} else if (!strcmp (op->mnemonic, "jp")
			|| !strcmp (op->mnemonic, "jpe")) {
		data[l++] = 0x8a;
	} else if (!strcmp (op->mnemonic, "js")
			|| !strcmp (op->mnemonic, "jz")) {
		data[l++] = 0x88;
	}
	if (is_short) {
		data[l-1] -= 0x10;
	}

	immediate -= is_short? 2: 6;
	data[l++] = immediate;
	if (!is_short) {
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int oplea(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int mod = 0;
	st32 offset = 0;
	int reg = 0;
	int rm = 0;
	if (op->operands[0].type & OT_REGALL && op->operands[1].type & (OT_MEMORY | OT_CONSTANT)) {
		if (a->config->bits == 64) {
			data[l++] = 0x48;
		}
		data[l++] = 0x8d;
		if (op->operands[1].regs[0] == X86R_UNDEFINED) {
			// RIP-relative LEA
			ut64 offset = op->operands[1].offset - op->addr;
			if (data[0] == 0x48) {
				offset -= 7;
			}
			ut32 high = 0xff00 & offset;
			data[l++] = op->operands[0].reg << 3 | 5;
			data[l++] = offset;
			data[l++] = high >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		} else {
			reg = op->operands[0].reg;
			rm = op->operands[1].regs[0];

			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (op->operands[1].regs[0] == X86R_RIP) {
				// RIP-relative LEA (not caught above, so "offset" is already relative)
				data[l++] = reg << 3 | 5;
				data[l++] = offset;
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
				return l;
			}
			if (offset != 0 || op->operands[1].regs[0] == X86R_EBP) {
				mod = 1;
				if (offset >= 128 || offset < -128) {
					mod = 2;
				}
				data[l++] = mod << 6 | reg << 3 | rm;
				if (op->operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				data[l++] = offset;
				if (mod == 2) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			} else {
				data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
				if (op->operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
			}

		}
	}
	return l;
}

static int oples(RArchSession *a, ut8* data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	int mod = 0;

	if (op->operands[1].type & OT_MEMORY) {
		data[l++] = 0xc4;
		if (op->operands[1].type & OT_GPREG) {
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (offset) {
				mod = 1;
				if (offset > 128 || offset < -128) {
					mod = 2;
				}
			}
			data[l++] = mod << 6 | op->operands[0].reg << 3 | op->operands[1].regs[0];
			if (mod) {
				data[l++] = offset;
				if (mod > 1) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		} else {
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			data[l++] = 0x05;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opmov(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	st64 offset = 0;
	int mod = 0;
	int base = 0;
	int rex = 0;
	ut64 immediate = 0;
	const int bits = a->config->bits;
	if (op->operands[1].type & OT_CONSTANT) {
#if 0
		if (!op->operands[1].is_good_flag) {
			return -1;
		}
#endif
		if (op->operands[1].immediate == -1 && a->arch->num && a->arch->num->nc.errors > 0) {
			return -1;
		}
		if (immediate_out_of_range (bits, op->operands[1].immediate)) {
			return -1;
		}
		immediate = op->operands[1].immediate * op->operands[1].sign;
		if (op->operands[0].type & OT_GPREG && !(op->operands[0].type & OT_MEMORY)) {
			if ((op->operands[0].type & OT_DWORD)
					&& immediate > UT32_MAX
					&& immediate < 0xffffffff80000000ULL /* -0x80000000 */) {
				return -1;
			}
			bool imm32in64 = false;
			if (op->operands[0].type & OT_WORD) {
				if (bits > 16) {
					data[l++] = 0x66;
				}
			}
			if (bits == 64 && (op->operands[0].type & OT_QWORD)) {
				if (op->operands[0].extended) {
					data[l++] = 0x49;
				} else {
					data[l++] = 0x48;
				}
			} else if (op->operands[0].extended) {
				data[l++] = 0x41;
			}
			if (op->operands[0].type & OT_BYTE) {
				if (op->operands[0].rex_prefixed) {
					data[l++] = 0x40;
				}
				data[l++] = 0xb0 | op->operands[0].reg;
				data[l++] = immediate;
			} else {
				if (bits == 64 && (op->operands[0].type & OT_QWORD)
						&& (immediate <= ST32_MAX
							|| immediate >= 0xffffffff80000000ULL /* -0x80000000 */)) {
					data[l++] = 0xc7;
					data[l++] = 0xc0 | op->operands[0].reg;
					imm32in64 = true;
				} else {
					data[l++] = 0xb8 | op->operands[0].reg;
				}
				data[l++] = immediate;
				data[l++] = immediate >> 8;
				if (!(op->operands[0].type & OT_WORD)) {
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
				if (bits == 64 && (((op->operands[0].type & OT_QWORD) && !imm32in64)
						|| (immediate > UT32_MAX
							&& immediate < 0xffffffff80000000ULL /* -0x80000000 */))) {
					data[l++] = immediate >> 32;
					data[l++] = immediate >> 40;
					data[l++] = immediate >> 48;
					data[l++] = immediate >> 56;
				}
			}
		} else if (op->operands[0].type & OT_MEMORY) {
			if (!op->operands[0].explicit_size) {
				if (op->operands[0].type & OT_GPREG) {
					((Opcode *)op)->operands[0].dest_size = op->operands[0].reg_size;
				} else {
					return -1;
				}
			}

			int dest_bits = 8 * ((op->operands[0].dest_size & ALL_SIZE) >> OPSIZE_SHIFT);
			int reg_bits = 8 * ((op->operands[0].reg_size & ALL_SIZE) >> OPSIZE_SHIFT);
			int offset = op->operands[0].offset * op->operands[0].offset_sign;

			//addr_size_override prefix
			bool use_aso = false;
			if (reg_bits < bits) {
				use_aso = true;
			}

			//op_size_override prefix
			bool use_oso = false;
			if (dest_bits == 16) {
				use_oso = true;
			}

			bool rip_rel = op->operands[0].regs[0] == X86R_RIP;

			//rex prefix
			int rex = 1 << 6;
			bool use_rex = false;
			if (dest_bits == 64) {			//W field
				use_rex = true;
				rex |= 1 << 3;
			}
			if (op->operands[0].extended) {		//B field
				use_rex = true;
				rex |= 1;
			}

			//opcode selection
			int opcode;
			if (dest_bits == 8) {
				opcode = 0xc6;
			} else {
				opcode = 0xc7;
			}

			//modrm and SIB selection
			int modrm = 0;
			int mod;
			int reg = 0;
			int rm;
			bool use_sib = false;
			int sib;
			//mod
			if (offset == 0) {
				mod = 0;
			} else if (offset < 128 && offset > -129) {
				mod = 1;
			} else {
				mod = 2;
			}

			if (reg_bits == 16) {
				if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_SI) {
					rm = B0000;
				} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == X86R_DI) {
					rm = B0001;
				} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_SI) {
					rm = B0010;
				} else if (op->operands[0].regs[0] == X86R_BP && op->operands[0].regs[1] == X86R_DI) {
					rm = B0011;
				} else if (op->operands[0].regs[0] == X86R_SI && op->operands[0].regs[1] == -1) {
					rm = B0100;
				} else if (op->operands[0].regs[0] == X86R_DI && op->operands[0].regs[1] == -1) {
					rm = B0101;
				} else if (op->operands[0].regs[0] == X86R_BX && op->operands[0].regs[1] == -1) {
					rm = B0111;
				} else {
					//TODO allow for displacement only when parser is reworked
					return -1;
				}
				modrm = (mod << 6) | (reg << 3) | rm;
			} else {
				//rm
				if (op->operands[0].extended) {
					rm = op->operands[0].reg;
				} else {
					rm = op->operands[0].regs[0];
				}
				//[ebp] alone is illegal, so we need to fake a [ebp+0]
				if (rm == 5 && mod == 0) {
					mod = 1;
				}

				//sib
				int index = op->operands[0].regs[1];
				int scale = getsib(op->operands[0].scale[1]);
				if (index != -1) {
					use_sib = true;
					sib = (scale << 6) | (index << 3) | rm;
				} else if (rm == 4) {
					use_sib = true;
					sib = 0x24;
				}
				if (use_sib) {
					rm = B0100;
				}
				if (rip_rel) {
					modrm = (B0000 << 6) | (reg << 3) | B0101;
					sib = (scale << 6) | (B0100 << 3) | B0101;
				} else {
					modrm = (mod << 6) | (reg << 3) | rm;
				}
			}

			//build the final result
			if (use_aso) {
				data[l++] = 0x67;
			}
			if (use_oso) {
				data[l++] = 0x66;
			}
			if (use_rex) {
				data[l++] = rex;
			}
			data[l++] = opcode;
			data[l++] = modrm;
			if (use_sib) {
				data[l++] = sib;
			}
			//offset
			if (mod == 1) {
				data[l++] = offset;
			} else if (reg_bits == 16 && mod == 2) {
				data[l++] = offset;
				data[l++] = offset >> 8;
			} else if (mod == 2 || rip_rel) {
				data[l++] = offset;
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
			//immediate
			int byte;
			for (byte = 0; byte < dest_bits && byte < 32; byte += 8) {
				data[l++] = (immediate >> byte);
			}
		}
	} else if (op->operands[1].type & OT_REGALL && !(op->operands[1].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_CONSTANT) {
			return -1;
		}
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG
				&& op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			return -1;
		}
		if (is_debug_or_control (op->operands[0]) &&
				!(op->operands[1].type & OT_REGTYPE & OT_GPREG)) {
			return -1;
		}
		if (is_debug_or_control (op->operands[1])
				&& !(op->operands[0].type & OT_REGTYPE & OT_GPREG)) {
			return -1;
		}
		// Check reg sizes match
		if (op->operands[0].type & OT_REGTYPE && op->operands[1].type & OT_REGTYPE) {
			if (!((op->operands[0].type & ALL_SIZE) & (op->operands[1].type & ALL_SIZE))) {
				return -1;
			}
		}

		if (bits == 64) {
			if (op->operands[0].extended) {
				rex = 1;
			}
			if (op->operands[1].extended) {
				rex += 4;
			}
			if (op->operands[1].type & OT_QWORD) {
				if (!(op->operands[0].type & OT_QWORD)) {
					data[l++] = 0x67;
					data[l++] = 0x48;
				}
			}
			if (op->operands[1].type & OT_QWORD &&
				op->operands[0].type & OT_QWORD) {
				data[l++] = 0x48 | rex;
			}
			if (op->operands[1].type & OT_DWORD &&
				op->operands[0].type & OT_DWORD) {
				data[l++] = 0x40 | rex;
			}
		} else if (op->operands[0].extended && op->operands[1].extended) {
			data[l++] = 0x45;
		}
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			data[l++] = 0x8c;
		} else if (is_debug_or_control (op->operands[0])) {
			data[l++] = 0x0f;
			if (op->operands[0].type & OT_REGTYPE & OT_DEBUGREG) {
				data[l++] = 0x23;
			} else {
				data[l++] = 0x22;
			}
		} else if (is_debug_or_control(op->operands[1])) {
			data[l++] = 0x0f;
			if (op->operands[1].type & OT_REGTYPE & OT_DEBUGREG) {
				data[l++] = 0x21;
			} else {
				data[l++] = 0x20;
			}
		} else {
			if (a->config->bits > 16 && op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			}
			data[l++] = (op->operands[0].type & OT_BYTE) ? 0x88 : 0x89;
		}

		if (op->operands[0].scale[0] > 1) {
			data[l++] = op->operands[1].reg << 3 | 4;
			data[l++] = getsib (op->operands[0].scale[0]) << 6
					| op->operands[0].regs[0] << 3
					| 5;

			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;

			return l;
		}

		if (!(op->operands[0].type & OT_MEMORY)) {
			if (op->operands[0].reg == X86R_UNDEFINED ||
				op->operands[1].reg == X86R_UNDEFINED) {
				return -1;
			}
			mod = 0x3;
			data[l++] = (is_debug_or_control (op->operands[0]))
				? mod << 6 | op->operands[0].reg << 3 | op->operands[1].reg
				: mod << 6 | op->operands[1].reg << 3 | op->operands[0].reg;
		} else if (op->operands[0].regs[0] == X86R_UNDEFINED) {
			data[l++] = op->operands[1].reg << 3 | 0x5;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		} else {
			if (op->operands[0].type & OT_MEMORY) {
				if (op->operands[0].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[1].reg << 3 | 0x4;
					data[l++] = op->operands[0].regs[1] << 3 | op->operands[0].regs[0];
					return l;
				}
				if (offset) {
					mod = (offset > 128 || offset < -129) ? 0x2 : 0x1;
				}
				if (op->operands[0].regs[0] == X86R_EBP) {
					mod = 0x2;
				}
				data[l++] = mod << 6 | op->operands[1].reg << 3 | op->operands[0].regs[0];
				if (op->operands[0].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				if (offset) {
					data[l++] = offset;
				}
				if (mod == 2) {
					// warning C4293: '>>': shift count negative or too big, undefined behavior
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		}
	} else if (op->operands[1].type & OT_MEMORY) {
		if (op->operands[0].type & OT_MEMORY) {
			return -1;
		}
		offset = op->operands[1].offset * op->operands[1].offset_sign;
		if (op->operands[0].reg == X86R_EAX && op->operands[1].regs[0] == X86R_UNDEFINED) {
			if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0x48;
			} else if (op->operands[0].type & OT_WORD && bits != 16) {
				data[l++] = 0x66;
			}
			if (op->operands[0].type & OT_BYTE) {
				data[l++] = 0xa0;
			} else {
				data[l++] = 0xa1;
			}
			data[l++] = offset;
			data[l++] = offset >> 8;
			if (bits >= 32) {
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
				if (bits == 64) {
					data[l++] = offset >> 32;
					data[l++] = offset >> 40;
					data[l++] = offset >> 48;
					data[l++] = offset >> 56;
				}
			}
			return l;
		}

		if (op->operands[0].type & OT_BYTE && bits == 64 && op->operands[1].regs[0]) {
			if (op->operands[1].regs[0] >= X86R_R8 && op->operands[0].reg < 4) {
				data[l++] = 0x41;
				data[l++] = 0x8a;
				data[l++] = op->operands[0].reg << 3 | (op->operands[1].regs[0] - 8);
				return l;
			}
			return -1;
		}

		if (op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			if (op->operands[1].scale[0] == 0) {
				return -1;
			}
			data[l++] = SEG_REG_PREFIXES[op->operands[1].regs[0] % 6];
			data[l++] = 0x8b;
			data[l++] = (((ut32)op->operands[0].reg) << 3) | 0x5;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		}

		if (bits == 64) {
			if (op->operands[0].type & OT_QWORD) {
				if (!(op->operands[1].type & OT_QWORD)) {
					if (op->operands[1].regs[0] != -1) {
						data[l++] = 0x67;
					}
					data[l++] = 0x48;
				}
			} else if (op->operands[1].type & OT_DWORD) {
				data[l++] = 0x44;
			} else if (!(op->operands[1].type & OT_QWORD)) {
				data[l++] = 0x67;
			}
			if (op->operands[1].type & OT_QWORD &&
				op->operands[0].type & OT_QWORD) {
				if (op->operands[0].extended) {
					data[l++] = 0x4c; // r12, r13, ..
				} else {
					data[l++] = 0x48; // rax, rbx, ..
				}
			}
		}

		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = op->operands[1].type & OT_BYTE ? 0x8a : 0x8b;
		} else {
			data[l++] = (op->operands[1].type & OT_BYTE ||
				op->operands[0].type & OT_BYTE) ?
				0x8a : 0x8b;
		}

		if (op->operands[1].regs[0] == X86R_UNDEFINED) {
			if (bits == 64) {
				data[l++] = op->operands[0].reg << 3 | 0x4;
				data[l++] = 0x25;
			} else {
				data[l++] = op->operands[0].reg << 3 | 0x5;
			}
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		} else {
			if (op->operands[1].scale[0] > 1) {
				data[l++] = op->operands[0].reg << 3 | 4;

				if (op->operands[1].scale[0] >= 2) {
					base = 5;
				}
				if (base) {
					data[l++] = getsib (op->operands[1].scale[0]) << 6 | op->operands[1].regs[0] << 3 | base;
				} else {
					data[l++] = getsib (op->operands[1].scale[0]) << 3 | op->operands[1].regs[0];
				}
				if (offset || base) {
					data[l++] = offset;
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
				return l;
			}
			if (op->operands[1].regs[1] != X86R_UNDEFINED) {
				data[l++] = op->operands[0].reg << 3 | 0x4;
				data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
				return l;
			}

			if (offset || op->operands[1].regs[0] == X86R_EBP) {
				mod = 0x2;
				if (op->operands[1].offset > 127) {
					mod = 0x4;
				}
			}
			if (bits == 64 && offset && op->operands[0].type & OT_QWORD) {
				if (op->operands[1].regs[0] == X86R_RIP) {
					data[l++] = 0x5;
				} else {
					const ut8 pfx = (op->operands[1].offset > 127)? 0x80: 0x40;
					data[l++] = pfx | op->operands[0].reg << 3 | op->operands[1].regs[0];
				}
				if (op->operands[1].offset > 127) {
					mod = 0x1;
				}
			} else {
				if (op->operands[1].regs[0] == X86R_EIP && (op->operands[0].type & OT_DWORD)) {
					data[l++] = 0x0d;
				} else if (op->operands[1].regs[0] == X86R_RIP && (op->operands[0].type & OT_QWORD)) {
					data[l++] = 0x05;
				} else {
					data[l++] = mod << 5 | op->operands[0].reg << 3 | op->operands[1].regs[0];
				}
			}
			if (op->operands[1].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			if (mod >= 0x2) {
				data[l++] = offset;
				if (op->operands[1].offset > 128 || op->operands[1].regs[0] == X86R_EIP) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			} else if (bits == 64 && (offset || op->operands[1].regs[0] == X86R_RIP)) {
				data[l++] = offset;
				if (op->operands[1].offset > 127 || op->operands[1].regs[0] == X86R_RIP) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		}
	}
	return l;
}

// Only for MOV r64, imm64
static int opmovabs(RArchSession *a, ut8 *data, const Opcode *op) {
	if (!(a->config->bits == 64 && (op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY)
			&& (op->operands[0].type & OT_QWORD) && (op->operands[1].type & OT_CONSTANT))) {
		return -1;
	}
	int l = 0;
	int byte_shift;
	ut64 immediate;
	if (op->operands[0].extended) {
		data[l++] = 0x49;
	} else {
		data[l++] = 0x48;
	}
	data[l++] = 0xb8 | op->operands[0].reg;
	immediate = op->operands[1].immediate * op->operands[1].sign;
	for (byte_shift = 0; byte_shift < 8; byte_shift++) {
		data[l++] = immediate >> (byte_shift * 8);
	}
	return l;
}

static int opmul(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;

	if (op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xe0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oppop(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int offset = 0;
	int mod = 0;
	if ((op->operands[0].type & OT_GPREG) && !(op->operands[0].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG) {
			ut8 base;
			if (op->operands[0].reg & X86R_FS) {
				data[l++] = 0x0f;
				base = 0x81;
			} else {
				base = 0x7;
			}
			data[l++] = base + (8 * op->operands[0].reg);
		} else {
			if (op->operands[0].extended && a->config->bits == 64) {
				data[l++] = 0x41;
			}
			ut8 base = 0x58;
			data[l++] = base + op->operands[0].reg;
		}
	} else if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x8f;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset != 0 || op->operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		} else {
			data[l++] = op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}

	}
	return l;
}

static int oppush(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int mod = 0;
	st32 immediate = 0;
	st32 offset = 0;
	if (op->operands[0].type & OT_GPREG
			&& !(op->operands[0].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG) {
			ut8 base;
			if (op->operands[0].reg & X86R_FS) {
				data[l++] = 0x0f;
				base = 0x80;
			} else {
				base = 0x6;
			}
			data[l++] = base + (8 * op->operands[0].reg);
		} else {
			if (op->operands[0].extended && a->config->bits == 64) {
				data[l++] = 0x41;
			}
			ut8 base = 0x50;
			if (op->operands[0].reg == X86R_RIP) {
				R_LOG_ERROR ("Invalid register");
				return -1;
			}
			data[l++] = base + op->operands[0].reg;
		}
	} else if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0xff;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset != 0 || op->operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | 6 << 3 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		} else {
			mod = 3;
			data[l++] = mod << 4 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}
	} else {
		if (immediate_out_of_range (a->config->bits, op->operands[0].immediate)) {
			return -1;
		}
		immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate >= 128 || immediate < -128) {
			data[l++] = 0x68;
			data[l++] = immediate;
			data[l++] = immediate >> 8;
			data[l++] = immediate >> 16;
			data[l++] = immediate >> 24;
		} else {
			data[l++] = 0x6a;
			data[l++] = immediate;
		}
	}
	return l;
}

static int opout(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	st32 immediate = 0;
	if (op->operands[0].reg == X86R_DX) {
		if (op->operands[1].reg == X86R_AL && op->operands[1].type & OT_BYTE) {
			data[l++] = 0xee;
			return l;
		}
		if (op->operands[1].reg == X86R_AX && op->operands[1].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xef;
			return l;
		}
		if (op->operands[1].reg == X86R_EAX && op->operands[1].type & OT_DWORD) {
			data[l++] = 0xef;
			return l;
		}
	} else if (op->operands[0].type & OT_CONSTANT) {
		if (op->operands[0].immediate > 255) {
			return -1;
		}
		immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op->operands[1].reg == X86R_AL && op->operands[1].type & OT_BYTE) {
			data[l++] = 0xe6;
		} else if (op->operands[1].reg == X86R_AX && op->operands[1].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xe7;
		} else if (op->operands[1].reg == X86R_EAX && op->operands[1].type & OT_DWORD) {
			data[l++] = 0xe7;
		} else {
			return -1;
		}
		data[l++] = immediate;
	} else {
		return -1;
	}
	return l;
}

static int oploop(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	data[l++] = 0xe2;
	st8 delta = op->operands[0].immediate - op->addr - 2;
	data[l++] = (ut8)delta;
	return l;
}

static int opret(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int immediate = 0;
	if (a->config->bits == 16) {
		data[l++] = 0xc3;
		return l;
	}
	if (op->operands[0].type == OT_UNKNOWN) {
		data[l++] = 0xc3;
	} else if (op->operands[0].type & (OT_CONSTANT | OT_WORD)) {
		data[l++] = 0xc2;
		immediate = op->operands[0].immediate * op->operands[0].sign;
		data[l++] = immediate;
		data[l++] = 0; // always zero and UB shifts (immediate << 8);
	}
	return l;
}

static int opretf(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	st32 immediate = 0;
	if (op->operands[0].type & OT_CONSTANT) {
		immediate = op->operands[0].immediate * op->operands[0].sign;
		data[l++] = 0xca;
		data[l++] = immediate;
		data[l++] = immediate >> 8;
	} else if (op->operands[0].type == OT_UNKNOWN) {
		data[l++] = 0xcb;
	}
	return l;
}

static int opstos(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	if (!strcmp (op->mnemonic, "stosw")) {
		data[l++] = 0x66;
	}
	if (!strcmp (op->mnemonic, "stosb")) {
		data[l++] = 0xaa;
	} else if (!strcmp (op->mnemonic, "stosw")) {
		data[l++] = 0xab;
	} else if (!strcmp (op->mnemonic, "stosd")) {
		data[l++] = 0xab;
	}
	return l;
}

static int opset(RArchSession *a, ut8 *data, const Opcode *op) {
	if (!(op->operands[0].type & (OT_GPREG | OT_BYTE))) {return -1;}
	int l = 0;
	int mod = 0;
	int reg = op->operands[0].regs[0];

	data[l++] = 0x0f;
	if (!strcmp (op->mnemonic, "seto")) {
		data[l++] = 0x90;
	} else if (!strcmp (op->mnemonic, "setno")) {
		data[l++] = 0x91;
	} else if (!strcmp (op->mnemonic, "setb")
			|| !strcmp (op->mnemonic, "setnae")
			|| !strcmp (op->mnemonic, "setc")) {
		data[l++] = 0x92;
	} else if (!strcmp (op->mnemonic, "setnb")
			|| !strcmp (op->mnemonic, "setae")
			|| !strcmp (op->mnemonic, "setnc")) {
		data[l++] = 0x93;
	} else if (!strcmp (op->mnemonic, "setz")
			|| !strcmp (op->mnemonic, "sete")) {
		data[l++] = 0x94;
	} else if (!strcmp (op->mnemonic, "setnz")
			|| !strcmp (op->mnemonic, "setne")) {
		data[l++] = 0x95;
	} else if (!strcmp (op->mnemonic, "setbe")
			|| !strcmp (op->mnemonic, "setna")) {
		data[l++] = 0x96;
	} else if (!strcmp (op->mnemonic, "setnbe")
			|| !strcmp (op->mnemonic, "seta")) {
		data[l++] = 0x97;
	} else if (!strcmp (op->mnemonic, "sets")) {
		data[l++] = 0x98;
	} else if (!strcmp (op->mnemonic, "setns")) {
		data[l++] = 0x99;
	} else if (!strcmp (op->mnemonic, "setp")
			|| !strcmp (op->mnemonic, "setpe")) {
		data[l++] = 0x9a;
	} else if (!strcmp (op->mnemonic, "setnp")
			|| !strcmp (op->mnemonic, "setpo")) {
		data[l++] = 0x9b;
	} else if (!strcmp (op->mnemonic, "setl")
			|| !strcmp (op->mnemonic, "setnge")) {
		data[l++] = 0x9c;
	} else if (!strcmp (op->mnemonic, "setnl")
			|| !strcmp (op->mnemonic, "setge")) {
		data[l++] = 0x9d;
	} else if (!strcmp (op->mnemonic, "setle")
			|| !strcmp (op->mnemonic, "setng")) {
		data[l++] = 0x9e;
	} else if (!strcmp (op->mnemonic, "setnle")
			|| !strcmp (op->mnemonic, "setg")) {
		data[l++] = 0x9f;
	} else {
		return -1;
	}
	if (!(op->operands[0].type & OT_MEMORY)) {
		mod = 3;
		reg = op->operands[0].reg;
	}
	data[l++] = mod << 6 | reg;
	return l;
}

static int optest(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	if (!op->operands[0].type || !op->operands[1].type) {
		R_LOG_ERROR ("Invalid operands");
		return -1;
	}
	if (a->config->bits == 64) {
		if (op->operands[0].type & OT_MEMORY &&
			op->operands[0].reg_size & OT_DWORD) {
			data[l++] = 0x67;
		}
		if (op->operands[0].type & OT_QWORD) {
			if (op->operands[0].extended &&
				op->operands[1].extended) {
				data[l++] = 0x4d;
			} else {
				data[l++] = 0x48;
			}
		}
	}

	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			if (op->operands[0].type & OT_WORD && a->config->bits != 16) {
				data[l++] = 0x66;
			}
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x00 | op->operands[0].reg;
		} else {
			data[l++] = 0xc0 | op->operands[0].reg;
		}
		data[l++] = op->operands[1].immediate >> 0;
		if (op->operands[0].type & OT_BYTE) {
			return l;
		}
		data[l++] = op->operands[1].immediate >> 8;
		if (op->operands[0].type & OT_WORD) {
			return l;
		}
		data[l++] = op->operands[1].immediate >> 16;
		data[l++] = op->operands[1].immediate >> 24;
		return l;
	}
	if (op->operands[0].type & OT_BYTE ||
		op->operands[1].type & OT_BYTE) {
		data[l++] = 0x84;
	} else {
		data[l++] = 0x85;
	}
	if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x00 | op->operands[1].reg << 3 | op->operands[0].regs[0];
	} else {
		if (op->operands[1].type & OT_MEMORY) {
			data[l++] = 0x00 | op->operands[0].reg << 3 | op->operands[1].regs[0];
		} else {
			data[l++] = 0xc0 | op->operands[1].reg << 3 | op->operands[0].reg;
		}
	}
	return l;
}

static int opxchg(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	st32 offset = 0;

	if (op->operands[0].type & OT_MEMORY || op->operands[1].type & OT_MEMORY) {
		data[l++] = 0x87;
		if (op->operands[0].type & OT_MEMORY) {
			rm = op->operands[0].regs[0];
			offset = op->operands[0].offset * op->operands[0].offset_sign;
			reg = op->operands[1].reg;
		} else if (op->operands[1].type & OT_MEMORY) {
			rm = op->operands[1].regs[0];
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			reg = op->operands[0].reg;
		}
		if (offset) {
			mod_byte = 1;
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}
		}
	} else {
		if (!((op->operands[0].type & ALL_SIZE)
			& (op->operands[1].type & ALL_SIZE))) { // unmatched operand sizes
			return -1;
		}
		if (a->config->bits == 64
				&& op->operands[0].reg == X86R_EAX
				&& !op->operands[0].extended
				&& op->operands[0].type & OT_DWORD
				&& op->operands[1].reg == X86R_EAX
				&& !op->operands[1].extended
				&& op->operands[1].type & OT_DWORD) {
			data[l++] = 0x87;
			data[l++] = 0xc0;
			return l;
		} else if (op->operands[0].reg == X86R_EAX
				&& !op->operands[0].extended
				&& !(op->operands[0].type & OT_BYTE)
				&& op->operands[1].type & OT_GPREG) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			} else if (op->operands[0].type & OT_DWORD
					&& op->operands[1].extended) {
				data[l++] = 0x41;
			} else if (op->operands[0].type & OT_QWORD) {
				if (op->operands[1].extended) {
					data[l++] = 0x49;
				} else {
					data[l++] = 0x48;
				}
			}
			data[l++] = 0x90 + op->operands[1].reg;
			return l;
		} else if (op->operands[1].reg == X86R_EAX
				&& !op->operands[1].extended
				&& !(op->operands[1].type & OT_BYTE)
				&& op->operands[0].type & OT_GPREG) {
			if (op->operands[1].type & OT_WORD) {
				data[l++] = 0x66;
			} else if (op->operands[1].type & OT_DWORD
					&& op->operands[0].extended) {
				data[l++] = 0x41;
			} else if (op->operands[1].type & OT_QWORD) {
				if (op->operands[0].extended) {
					data[l++] = 0x49;
				} else {
					data[l++] = 0x48;
				}
			}
			data[l++] = 0x90 + op->operands[0].reg;
			return l;
		} else if (op->operands[0].type & OT_GPREG
				&& op->operands[1].type & OT_GPREG) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			}
			ut8 rex = 0x40
					| op->operands[0].extended
					| op->operands[1].extended << 2
					| !!(op->operands[0].type & OT_QWORD) << 3;
			if (rex != 0x40) {
				data[l++] = rex;
			}
			if (op->operands[0].type & OT_BYTE) {
				data[l++] = 0x86;
			} else {
				data[l++] = 0x87;
			}
			mod_byte = 3;
			reg = op->operands[1].reg;
			rm = op->operands[0].reg;
		}
	}
	data[l++] = mod_byte << 6 | reg << 3 | rm;
	if (mod_byte > 0 && mod_byte < 3) {
		data[l++] = offset;
		if (mod_byte == 2) {
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opcdqe(RArchSession *a, ut8 *data, const Opcode *op) {
	is_valid_registers (op);
	int l = 0;
	if (a->config->bits == 64) {
		data[l++] = 0x48;
	}
	data[l++] = 0x98;
	return l;
}

static int opfcmov(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	char* fcmov = op->mnemonic + strlen("fcmov");
	switch (op->operands_count) {
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL && op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			if (!strcmp (fcmov, "b")) {
				data[l++] = 0xda;
				data[l++] = 0xc0 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "e")) {
				data[l++] = 0xda;
				data[l++] = 0xc8 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "be")) {
				data[l++] = 0xda;
				data[l++] = 0xd0 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "u")) {
				data[l++] = 0xda;
				data[l++] = 0xd8 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "nb")) {
				data[l++] = 0xdb;
				data[l++] = 0xc0 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "ne")) {
				data[l++] = 0xdb;
				data[l++] = 0xc8 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "nbe")) {
				data[l++] = 0xdb;
				data[l++] = 0xd0 | op->operands[1].reg;
			} else if (!strcmp (fcmov, "nu")) {
				data[l++] = 0xdb;
				data[l++] = 0xd8 | op->operands[1].reg;
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opffree(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL)  {
			data[l++] = 0xdd;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfrstor(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0xdd;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxch(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xd9;
		data[l++] = 0xc9;
		break;
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd9;
			data[l++] = 0xc8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfucom(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdd;
			data[l++] = 0xe0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xdd;
		data[l++] = 0xe1;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfucomp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdd;
			data[l++] = 0xe8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xdd;
		data[l++] = 0xe9;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfaddp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0) {
			data[l++] = 0xde;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xc1;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfiadd(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfadd(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xc0 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdc;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opficom(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opficomp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfild(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xdf;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xdb;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdf;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfldcw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0xd9;
			data[l++] = 0x28 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfldenv(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0xd9;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfbld(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_TBYTE) {
			data[l++] = 0xdf;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfbstp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_TBYTE) {
			data[l++] = 0xdf;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxrstor(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0xae;
			data[l++] = 0x08 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxsave(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0xae;
			data[l++] = 0x00 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfist(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xdf;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xdb;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfistp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xdf;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xdb;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdf;
				data[l++] = 0x38 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfisttp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xdf;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xdb;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdd;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfstenv(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x9b;
			data[l++] = 0xd9;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfnstenv(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0xd9;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfdiv(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x30 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x30 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xf0 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdc;
			data[l++] = 0xf8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfdivp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xf9;
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xde;
			data[l++] = 0xf8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfidiv(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x30 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x30 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfdivr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x38 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x38 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xf8 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
			       	&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdc;
			data[l++] = 0xf0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfdivrp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xf1;
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xde;
			data[l++] = 0xf0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfidivr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x38 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x38 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfmul(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xc8 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdc;
			data[l++] = 0xc8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfmulp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xc9;
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xde;
			data[l++] = 0xc8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfimul(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x08 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfsub(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x20 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x20 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[0].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xe0 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xdc;
			data[l++] = 0xe8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfsubp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xe9;
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].reg == 0
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xde;
			data[l++] = 0xe8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfisub(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x20 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x20 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfsubr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xd8;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_QWORD) {
				data[l++] = 0xdc;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL && op->operands[0].reg == 0
			&& op->operands[1].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd8;
			data[l++] = 0xe8 | op->operands[1].reg;
		} else if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
			&& op->operands[1].type & OT_FPUREG & ~OT_REGALL && op->operands[1].reg == 0) {
			data[l++] = 0xdc;
			data[l++] = 0xe0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfsubrp(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xe1;
		break;
	case 2:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL
				&& op->operands[1].type & OT_FPUREG & ~OT_REGALL && op->operands[1].reg == 0) {
			data[l++] = 0xde;
			data[l++] = 0xe0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfisubr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			if (op->operands[0].type & OT_DWORD) {
				data[l++] = 0xda;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0xde;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfnstcw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0xd9;
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfstcw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0x9b;
			data[l++] = 0xd9;
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfnstsw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0xdd;
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else if (op->operands[0].type & OT_GPREG
			&& op->operands[0].type & OT_WORD
			&& op->operands[0].reg == X86R_AX) {
			data[l++] = 0xdf;
			data[l++] = 0xe0;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfstsw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0x9b;
			data[l++] = 0xdd;
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else if (op->operands[0].type & OT_GPREG
				&& op->operands[0].type & OT_WORD
				&& op->operands[0].reg == X86R_AX) {
			data[l++] = 0x9b;
			data[l++] = 0xdf;
			data[l++] = 0xe0;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfnsave(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_DWORD) {
			data[l++] = 0xdd;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfsave(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_DWORD) {
			data[l++] = 0x9b;
			data[l++] = 0xdd;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oplldt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x0f;
			data[l++] = 0x00;
			if (op->operands[0].type & OT_MEMORY) {
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else {
				data[l++] = 0xd0 | op->operands[0].reg;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oplmsw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x0f;
			data[l++] = 0x01;
			if (op->operands[0].type & OT_MEMORY) {
				data[l++] = 0x30 | op->operands[0].regs[0];
			} else {
				data[l++] = 0xf0 | op->operands[0].reg;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oplgdt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0x01;
			data[l++] = 0x10 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oplidt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0x01;
			data[l++] = 0x18 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opsgdt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0x01;
			data[l++] = 0x00 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opstmxcsr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_DWORD) {
			data[l++] = 0x0f;
			data[l++] = 0xae;
			data[l++] = 0x18 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opstr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_WORD) {
			data[l++] = 0x0f;
			data[l++] = 0x00;
			data[l++] = 0x08 | op->operands[0].regs[0];
		} else if (op->operands[0].type & OT_GPREG && op->operands[0].type & OT_DWORD) {
			data[l++] = 0x0f;
			data[l++] = 0x00;
			data[l++] = 0xc8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opsidt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x0f;
			data[l++] = 0x01;
			data[l++] = 0x08 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opsldt(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (a->config->bits == 64) {
			data[l++] = 0x48;
		}
		data[l++] = 0x0f;
		data[l++] = 0x00;
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x00 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xc0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opsmsw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (a->config->bits == 64) {
			data[l++] = 0x48;
		}
		data[l++] = 0x0f;
		data[l++] = 0x01;
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xe0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opverr(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x0f;
			data[l++] = 0x00;
			if (op->operands[0].type & OT_MEMORY) {
				data[l++] = 0x20 | op->operands[0].regs[0];
			} else {
				data[l++] = 0xe0 | op->operands[0].reg;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opverw(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x0f;
			data[l++] = 0x00;
			if (op->operands[0].type & OT_MEMORY) {
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else {
				data[l++] = 0xe8 | op->operands[0].reg;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opvmclear(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_QWORD) {
			data[l++] = 0x66;
			data[l++] = 0x0f;
			data[l++] = 0xc7;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opvmon(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY && op->operands[0].type & OT_QWORD) {
			data[l++] = 0xf3;
			data[l++] = 0x0f;
			data[l++] = 0xc7;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opvmptrld(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY
			&& op->operands[0].type & OT_QWORD) {
			data[l++] = 0x0f;
			data[l++] = 0xc7;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opvmptrst(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY
			&& op->operands[0].type & OT_QWORD) {
			data[l++] = 0x0f;
			data[l++] = 0xc7;
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

typedef struct lookup_t {
	const char mnemonic[12];
	int only_x32;
	int (*opdo)(RArchSession*, ut8*, const Opcode*);
	ut64 opcode;
	int size;
} LookupTable;

static const LookupTable oplookup[] = {
	{ "aaa", 0, NULL, 0x37, 1},
	{ "aad", 0, NULL, 0xd50a, 2},
	{ "aam", 0, opaam, 0},
	{ "aas", 0, NULL, 0x3f, 1},
	{ "adc", 0, &opadc, 0},
	{ "add", 0, &opadd, 0},
	{ "adx", 0, NULL, 0xd4, 1},
	{ "amx", 0, NULL, 0xd5, 1},
	{ "and", 0, &opand, 0},
	{ "bsf", 0, &opbs, 0},
	{ "bsr", 0, &opbs, 0},
	{ "bswap", 0, &opbswap, 0},
	{ "call", 0, &opcall, 0},
	{ "cbw", 0, NULL, 0x6698, 2},
	{ "cdq", 0, NULL, 0x99, 1},
	{ "cdqe", 0, &opcdqe, 0},
	{ "cwde", 0, &opcdqe, 0},
	{ "clc", 0, NULL, 0xf8, 1},
	{ "cld", 0, NULL, 0xfc, 1},
	{ "clflush", 0, &opclflush, 0},
	{ "clgi", 0, NULL, 0x0f01dd, 3},
	{ "cli", 0, NULL, 0xfa, 1},
	{ "clts", 0, NULL, 0x0f06, 2},
	{ "cmc", 0, NULL, 0xf5, 1},
	{ "cmovo", 0, &opcmov, 0},
	{ "cmovno", 0, &opcmov, 0},
	{ "cmovb", 0, &opcmov, 0},
	{ "cmovc", 0, &opcmov, 0},
	{ "cmovnae", 0, &opcmov, 0},
	{ "cmovae", 0, &opcmov, 0},
	{ "cmovnb", 0, &opcmov, 0},
	{ "cmovnc", 0, &opcmov, 0},
	{ "cmove", 0, &opcmov, 0},
	{ "cmovz", 0, &opcmov, 0},
	{ "cmovne", 0, &opcmov, 0},
	{ "cmovnz", 0, &opcmov, 0},
	{ "cmovbe", 0, &opcmov, 0},
	{ "cmovna", 0, &opcmov, 0},
	{ "cmova", 0, &opcmov, 0},
	{ "cmovnbe", 0, &opcmov, 0},
	{ "cmovne", 0, &opcmov, 0},
	{ "cmovnz", 0, &opcmov, 0},
	{ "cmovs", 0, &opcmov, 0},
	{ "cmovns", 0, &opcmov, 0},
	{ "cmovp", 0, &opcmov, 0},
	{ "cmovpe", 0, &opcmov, 0},
	{ "cmovnp", 0, &opcmov, 0},
	{ "cmovpo", 0, &opcmov, 0},
	{ "cmovl", 0, &opcmov, 0},
	{ "cmovnge", 0, &opcmov, 0},
	{ "cmovge", 0, &opcmov, 0},
	{ "cmovnl", 0, &opcmov, 0},
	{ "cmovle", 0, &opcmov, 0},
	{ "cmovng", 0, &opcmov, 0},
	{ "cmovg", 0, &opcmov, 0},
	{ "cmovnle", 0, &opcmov, 0},
	{ "cmp", 0, &opcmp, 0},
	{ "cmpsb", 0, NULL, 0xa6, 1},
	{ "cmpsd", 0, NULL, 0xa7, 1},
	{ "cmpsw", 0, NULL, 0x66a7, 2},
	{ "cpuid", 0, NULL, 0x0fa2, 2},
	{ "cwd", 0, NULL, 0x6699, 2},
	{ "cwde", 0, NULL, 0x98, 1},
	{ "daa", 0, NULL, 0x27, 1},
	{ "das", 0, NULL, 0x2f, 1},
	{ "dec", 0, &opdec, 0},
	{ "div", 0, &opdiv, 0},
	{ "emms", 0, NULL, 0x0f77, 2},
	{ "endbr32", 0, endbr32, 0},
	{ "endbr64", 0, endbr64, 0},
	{ "f2xm1", 0, NULL, 0xd9f0, 2},
	{ "fabs", 0, NULL, 0xd9e1, 2},
	{ "fadd", 0, &opfadd, 0},
	{ "faddp", 0, &opfaddp, 0},
	{ "fbld", 0, &opfbld, 0},
	{ "fbstp", 0, &opfbstp, 0},
	{ "fchs", 0, NULL, 0xd9e0, 2},
	{ "fclex", 0, NULL, 0x9bdbe2, 3},
	{ "fcmovb", 0, &opfcmov, 0},
	{ "fcmove", 0, &opfcmov, 0},
	{ "fcmovbe", 0, &opfcmov, 0},
	{ "fcmovu", 0, &opfcmov, 0},
	{ "fcmovnb", 0, &opfcmov, 0},
	{ "fcmovne", 0, &opfcmov, 0},
	{ "fcmovnbe", 0, &opfcmov, 0},
	{ "fcmovnu", 0, &opfcmov, 0},
	{ "fcos", 0, NULL, 0xd9ff, 2},
	{ "fdecstp", 0, NULL, 0xd9f6, 2},
	{ "fdiv", 0, &opfdiv, 0},
	{ "fdivp", 0, &opfdivp, 0},
	{ "fdivr", 0, &opfdivr, 0},
	{ "fdivrp", 0, &opfdivrp, 0},
	{ "femms", 0, NULL, 0x0f0e, 2},
	{ "ffree", 0, &opffree, 0},
	{ "fiadd", 0, &opfiadd, 0},
	{ "ficom", 0, &opficom, 0},
	{ "ficomp", 0, &opficomp, 0},
	{ "fidiv", 0, &opfidiv, 0},
	{ "fidivr", 0, &opfidivr, 0},
	{ "fild", 0, &opfild, 0},
	{ "fimul", 0, &opfimul, 0},
	{ "fincstp", 0, NULL, 0xd9f7, 2},
	{ "finit", 0, NULL, 0x9bdbe3, 3},
	{ "fist", 0, &opfist, 0},
	{ "fistp", 0, &opfistp, 0},
	{ "fisttp", 0, &opfisttp, 0},
	{ "fisub", 0, &opfisub, 0},
	{ "fisubr", 0, &opfisubr, 0},
	{ "fld1", 0, NULL, 0xd9e8, 2},
	{ "fldcw", 0, &opfldcw, 0},
	{ "fldenv", 0, &opfldenv, 0},
	{ "fldl2t", 0, NULL, 0xd9e9, 2},
	{ "fldl2e", 0, NULL, 0xd9ea, 2},
	{ "fldlg2", 0, NULL, 0xd9ec, 2},
	{ "fldln2", 0, NULL, 0xd9ed, 2},
	{ "fldpi", 0, NULL, 0xd9eb, 2},
	{ "fldz", 0, NULL, 0xd9ee, 2},
	{ "fmul", 0, &opfmul, 0},
	{ "fmulp", 0, &opfmulp, 0},
	{ "fnclex", 0, NULL, 0xdbe2, 2},
	{ "fninit", 0, NULL, 0xdbe3, 2},
	{ "fnop", 0, NULL, 0xd9d0, 2},
	{ "fnsave", 0, &opfnsave, 0},
	{ "fnstcw", 0, &opfnstcw, 0},
	{ "fnstenv", 0, &opfnstenv, 0},
	{ "fnstsw", 0, &opfnstsw, 0},
	{ "fpatan", 0, NULL, 0xd9f3, 2},
	{ "fprem", 0, NULL, 0xd9f8, 2},
	{ "fprem1", 0, NULL, 0xd9f5, 2},
	{ "fptan", 0, NULL, 0xd9f2, 2},
	{ "frndint", 0, NULL, 0xd9fc, 2},
	{ "frstor", 0, &opfrstor, 0},
	{ "fsave", 0, &opfsave, 0},
	{ "fscale", 0, NULL, 0xd9fd, 2},
	{ "fsin", 0, NULL, 0xd9fe, 2},
	{ "fsincos", 0, NULL, 0xd9fb, 2},
	{ "fsqrt", 0, NULL, 0xd9fa, 2},
	{ "fstcw", 0, &opfstcw, 0},
	{ "fstenv", 0, &opfstenv, 0},
	{ "fstsw", 0, &opfstsw, 0},
	{ "fsub", 0, &opfsub, 0},
	{ "fsubp", 0, &opfsubp, 0},
	{ "fsubr", 0, &opfsubr, 0},
	{ "fsubrp", 0, &opfsubrp, 0},
	{ "ftst", 0, NULL, 0xd9e4, 2},
	{ "fucom", 0, &opfucom, 0},
	{ "fucomp", 0, &opfucomp, 0},
	{ "fucompp", 0, NULL, 0xdae9, 2},
	{ "fwait", 0, NULL, 0x9b, 1},
	{ "fxam", 0, NULL, 0xd9e5, 2},
	{ "fxch", 0, &opfxch, 0},
	{ "fxrstor", 0, &opfxrstor, 0},
	{ "fxsave", 0, &opfxsave, 0},
	{ "fxtract", 0, NULL, 0xd9f4, 2},
	{ "fyl2x", 0, NULL, 0xd9f1, 2},
	{ "fyl2xp1", 0, NULL, 0xd9f9, 2},
	{ "getsec", 0, NULL, 0x0f37, 2},
	{ "hlt", 0, NULL, 0xf4, 1},
	{ "idiv", 0, &opidiv, 0},
	{ "imul", 0, &opimul, 0},
	{ "in", 0, &opin, 0},
	{ "inc", 0, &opinc, 0},
	{ "ins", 0, NULL, 0x6d, 1},
	{ "insb", 0, NULL, 0x6c, 1},
	{ "insd", 0, NULL, 0x6d, 1},
	{ "insw", 0, NULL, 0x666d, 2},
	{ "int", 0, &opint, 0},
	{ "int1", 0, NULL, 0xf1, 1},
	{ "int3", 0, NULL, 0xcc, 1},
	{ "into", 0, NULL, 0xce, 1},
	{ "invd", 0, NULL, 0x0f08, 2},
	{ "iret", 0, NULL, 0x66cf, 2},
	{ "iretd", 0, NULL, 0xcf, 1},
	{ "ja", 0, &opjc, 0},
	{ "jae", 0, &opjc, 0},
	{ "jb", 0, &opjc, 0},
	{ "jbe", 0, &opjc, 0},
	{ "jc", 0, &opjc, 0},
	{ "je", 0, &opjc, 0},
	{ "jg", 0, &opjc, 0},
	{ "jge", 0, &opjc, 0},
	{ "jl", 0, &opjc, 0},
	{ "jle", 0, &opjc, 0},
	{ "jmp", 0, &opjc, 0},
	{ "jna", 0, &opjc, 0},
	{ "jnae", 0, &opjc, 0},
	{ "jnb", 0, &opjc, 0},
	{ "jnbe", 0, &opjc, 0},
	{ "jnc", 0, &opjc, 0},
	{ "jne", 0, &opjc, 0},
	{ "jng", 0, &opjc, 0},
	{ "jnge", 0, &opjc, 0},
	{ "jnl", 0, &opjc, 0},
	{ "jnle", 0, &opjc, 0},
	{ "jno", 0, &opjc, 0},
	{ "jnp", 0, &opjc, 0},
	{ "jns", 0, &opjc, 0},
	{ "jnz", 0, &opjc, 0},
	{ "jo", 0, &opjc, 0},
	{ "jp", 0, &opjc, 0},
	{ "jpe", 0, &opjc, 0},
	{ "jpo", 0, &opjc, 0},
	{ "js", 0, &opjc, 0},
	{ "jz", 0, &opjc, 0},
	{ "jcxz", 0, &opjc, 0},
	{ "jecxz", 0, &opjc, 0},
	{ "jrcxz", 0, &opjc, 0},
	{ "lahf", 0, NULL, 0x9f, 1},
	{ "lea", 0, &oplea, 0},
	{ "leave", 0, NULL, 0xc9, 1},
	{ "les", 0, &oples, 0},
	{ "lfence", 0, NULL, 0x0faee8, 3},
	{ "lgdt", 0, &oplgdt, 0},
	{ "lidt", 0, &oplidt, 0},
	{ "lldt", 0, &oplldt, 0},
	{ "lmsw", 0, &oplmsw, 0},
	{ "lodsb", 0, NULL, 0xac, 1},
	{ "lodsd", 0, NULL, 0xad, 1},
	{ "lodsw", 0, NULL, 0x66ad, 2},
	{ "loop", 0, &oploop, 0},
	{ "mfence", 0, NULL, 0x0faef0, 3},
	{ "monitor", 0, NULL, 0x0f01c8, 3},
	{ "mov", 0, &opmov, 0},
	{ "movsb", 0, NULL, 0xa4, 1},
	{ "movsd", 0, NULL, 0xa5, 1},
	{ "movsw", 0, NULL, 0x66a5, 2},
	{ "movzx", 0, &opmovx, 0},
	{ "movsx", 0, &opmovx, 0},
	{ "movabs", 0, &opmovabs, 0},
	{ "mul", 0, &opmul, 0},
	{ "mwait", 0, NULL, 0x0f01c9, 3},
	{ "neg", 0, &opneg, 0},
	{ "nop", 0, NULL, 0x90, 1},
	{ "not", 0, &opnot, 0},
	{ "or", 0, &opor, 0},
	{ "out", 0, &opout, 0},
	{ "outsb", 0, NULL, 0x6e, 1},
	{ "outs", 0, NULL, 0x6f, 1},
	{ "outsd", 0, NULL, 0x6f, 1},
	{ "outsw", 0, NULL, 0x666f, 2},
	{ "pop", 0, &oppop, 0},
	{ "popa", 1, NULL, 0x61, 1},
	{ "popad", 1, NULL, 0x61, 1},
	{ "popal", 1, NULL, 0x61, 1},
	{ "popaw", 1, NULL, 0x6661, 2},
	{ "popfd", 1, NULL, 0x9d, 1},
	{ "prefetch", 0, NULL, 0x0f0d, 2},
	{ "push", 0, &oppush, 0},
	{ "pusha", 1, NULL, 0x60, 1},
	{ "pushad", 1, NULL, 0x60, 1},
	{ "pushal", 1, NULL, 0x60, 1},
	{ "pushf", 0, NULL, 0x669c, 2},
	{ "popf", 0, NULL, 0x669d, 2},
	{ "pushfd", 0, NULL, 0x9c, 1},
	{ "rcl", 0, &process_group_2, 0},
	{ "rcr", 0, &process_group_2, 0},
	{ "rep", 0, &oprep, 0},
	{ "repe", 0, &oprep, 0},
	{ "repne", 0, &oprep, 0},
	{ "repz", 0, &oprep, 0},
	{ "repnz", 0, &oprep, 0},
	{ "rdmsr", 0, NULL, 0x0f32, 2},
	{ "rdpmc", 0, NULL, 0x0f33, 2},
	{ "rdtsc", 0, NULL, 0x0f31, 2},
	{ "rdtscp", 0, NULL, 0x0f01f9, 3},
	{ "ret", 0, &opret, 0},
	{ "retf", 0, &opretf, 0},
	{ "retw", 0, NULL, 0x66c3, 2},
	{ "rol", 0, &process_group_2, 0},
	{ "ror", 0, &process_group_2, 0},
	{ "rsm", 0, NULL, 0x0faa, 2},
	{ "sahf", 0, NULL, 0x9e, 1},
	{ "sal", 0, &process_group_2, 0},
	{ "salc", 0, NULL, 0xd6, 1},
	{ "sar", 0, &process_group_2, 0},
	{ "sbb", 0, &opsbb, 0},
	{ "scasb", 0, NULL, 0xae, 1},
	{ "scasd", 0, NULL, 0xaf, 1},
	{ "scasw", 0, NULL, 0x66af, 2},
	{ "seto", 0, &opset, 0},
	{ "setno", 0, &opset, 0},
	{ "setb", 0, &opset, 0},
	{ "setnae", 0, &opset, 0},
	{ "setc", 0, &opset, 0},
	{ "setnb", 0, &opset, 0},
	{ "setae", 0, &opset, 0},
	{ "setnc", 0, &opset, 0},
	{ "setz", 0, &opset, 0},
	{ "sete", 0, &opset, 0},
	{ "setnz", 0, &opset, 0},
	{ "setne", 0, &opset, 0},
	{ "setbe", 0, &opset, 0},
	{ "setna", 0, &opset, 0},
	{ "setnbe", 0, &opset, 0},
	{ "seta", 0, &opset, 0},
	{ "sets", 0, &opset, 0},
	{ "setns", 0, &opset, 0},
	{ "setp", 0, &opset, 0},
	{ "setpe", 0, &opset, 0},
	{ "setnp", 0, &opset, 0},
	{ "setpo", 0, &opset, 0},
	{ "setl", 0, &opset, 0},
	{ "setnge", 0, &opset, 0},
	{ "setnl", 0, &opset, 0},
	{ "setge", 0, &opset, 0},
	{ "setle", 0, &opset, 0},
	{ "setng", 0, &opset, 0},
	{ "setnle", 0, &opset, 0},
	{ "setg", 0, &opset, 0},
	{ "sfence", 0, NULL, 0x0faef8, 3},
	{ "sgdt", 0, &opsgdt, 0},
	{ "shl", 0, &process_group_2, 0},
	{ "shr", 0, &process_group_2, 0},
	{ "shlx", 0, &opshiftx, 0},
	{ "shrx", 0, &opshiftx, 0},
	{ "sarx", 0, &opshiftx, 0},
	{ "sidt", 0, &opsidt, 0},
	{ "sldt", 0, &opsldt, 0},
	{ "smsw", 0, &opsmsw, 0},
	{ "stc", 0, NULL, 0xf9, 1},
	{ "std", 0, NULL, 0xfd, 1},
	{ "stgi", 0, NULL, 0x0f01dc, 3},
	{ "sti", 0, NULL, 0xfb, 1},
	{ "stmxcsr", 0, &opstmxcsr, 0},
	{ "stosb", 0, &opstos, 0},
	{ "stosd", 0, &opstos, 0},
	{ "stosw", 0, &opstos, 0},
	{ "str", 0, &opstr, 0},
	{ "sub", 0, &opsub, 0},
	{ "swapgs", 0, NULL, 0x0f1ff8, 3},
	{ "syscall", 0, NULL, 0x0f05, 2},
	{ "sysenter", 0, NULL, 0x0f34, 2},
	{ "sysexit", 0, NULL, 0x0f35, 2},
	{ "sysret", 0, NULL, 0x0f07, 2},
	{ "ud2", 0, NULL, 0x0f0b, 2},
	{ "verr", 0, &opverr, 0},
	{ "verw", 0, &opverw, 0},
	{ "vmcall", 0, NULL, 0x0f01c1, 3},
	{ "vmclear", 0, &opvmclear, 0},
	{ "vmlaunch", 0, NULL, 0x0f01c2, 3},
	{ "vmload", 0, NULL, 0x0f01da, 3},
	{ "vmmcall", 0, NULL, 0x0f01d9, 3},
	{ "vmptrld", 0, &opvmptrld, 0},
	{ "vmptrst", 0, &opvmptrst, 0},
	{ "vmresume", 0, NULL, 0x0f01c3, 3},
	{ "vmrun", 0, NULL, 0x0f01d8, 3},
	{ "vmsave", 0, NULL, 0x0f01db, 3},
	{ "vmxoff", 0, NULL, 0x0f01c4, 3},
	{ "vmxon", 0, &opvmon, 0},
	{ "vzeroall", 0, NULL, 0xc5fc77, 3},
	{ "vzeroupper", 0, NULL, 0xc5f877, 3},
	{ "wait", 0, NULL, 0x9b, 1},
	{ "wbinvd", 0, NULL, 0x0f09, 2},
	{ "wrmsr", 0, NULL, 0x0f30, 2},
	{ "xadd", 0, &opxadd, 0},
	{ "xchg", 0, &opxchg, 0},
	{ "xgetbv", 0, NULL, 0x0f01d0, 3},
	{ "xlatb", 0, NULL, 0xd7, 1},
	{ "xor", 0, &opxor, 0},
	{ "xsetbv", 0, NULL, 0x0f01d1, 3},
	{ "test", 0, &optest, 0},
	{ "null", 0, NULL, 0, 0}
};

static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
	if (*begin > strlen (str)) {
		return TT_EOF;
	}
	// Skip whitespace
	while (begin && str[*begin] && isspace ((ut8)str[*begin])) {
		(*begin)++;
	}

	if (!str[*begin]) { // null byte
		*end = *begin;
		return TT_EOF;
	}
	if (isalpha ((ut8)str[*begin])) { // word token
		*end = *begin;
		while (end && str[*end] && isalnum ((ut8)str[*end])) {
			(*end)++;
		}
		return TT_WORD;
	}
	if (isdigit ((ut8)str[*begin])) { // number token
		*end = *begin;
		while (end && isalnum ((ut8)str[*end])) { // accept alphanumeric characters, because hex.
			(*end)++;
		}
		return TT_NUMBER;
	} else { // special character: [, ], +, *, ...
		*end = *begin + 1;
		return TT_SPECIAL;
	}
}

static bool is_xmm_register(const char *token) {
	// check xmm0..xmm15
	if (!r_str_ncasecmp ("xmm", token, 3)) {
		int n = atoi (token + 3);
		return (n >= 0 && n <= 15);
	}
	return false;
}

static bool is_mm_register(const char *token) {
	if (!r_str_ncasecmp ("mm", token, 2)) {
		const bool parn = token[2] == '(';
		if (parn) {
			token++;
		}
		if (isdigit ((ut8)token[2]) && !isdigit((ut8)token[3])) {
			int n = token[2];
			if (n >= '0' && n <= '7') {
				if (parn) {
					if (token[3] != ')') {
						return false;
					}
				}
				return true;
			}
		}
	}
	return false;
}

static bool is_st_register(const char *token) {
	if (!r_str_ncasecmp ("st", token, 2)) {
		const bool parn = token[2] == '(';
		if (parn) {
			token++;
		}
		if (isdigit ((ut8)token[2]) && !isdigit((ut8)token[3])) {
			int n = token[2];
			if (n >= '0' && n <= '7') {
				if (parn) {
					if (token[3] != ')') {
						return false;
					}
				}
				return true;
			}
		}
	}
	return false;
}

static ut64 getnum(RArchSession *a, const char *s, bool *berr) {
	*berr = false;
	if (!s) {
		return 0;
	}
	if (*s == '$') {
		s++;
	}
	s = r_str_trim_head_ro (s);
	// ut64 res = r_num_math (a->arch->num, s);
	const char *err = NULL;
	ut64 res = r_num_math_err (a->arch->num, s, &err);
	if (err) {
		*berr = true;
		return UT64_MAX;
	}
#if 0
	if (res == 0 && *s != '0') {
		return UT64_MAX;
	}
#endif
	return res;
}

/**
 * Get the register at position pos in str. Increase pos afterwards.
 */
static Register parseReg(RArchSession *a, const char *str, size_t *pos, ut32 *type, bool *extended, bool *rex_prefixed) {
	int i;
	// Must be the same order as in enum register_t
	const char *const regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", NULL };
	const char *const regsext[] = { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", NULL };
	const char *const regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	// const char *const regs8withREX[] = { "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", NULL };
	const char *const regs8ext[] = { "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", NULL };
	const char *const regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", NULL };
	const char *const regs16ext[] = { "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", NULL };
	const char *const regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "rip", NULL };
	const char *const regs64ext[] = { "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", NULL };
	const char *const sregs[] = { "es", "cs", "ss", "ds", "fs", "gs", NULL };
	// const char *const cregs[] = { "cr0", "cr1", "cr2","cr3", "cr4", "cr5", "cr6", "cr7", NULL };
	// const char *const dregs[] = { "dr0", "dr1", "dr2","dr3", "dr4", "dr5", "dr6", "dr7", NULL };

	// Get token (especially the length)
	size_t nextpos, length;
	const char *token;
	getToken (str, pos, &nextpos);
	token = str + *pos;
	length = nextpos - *pos;
	*pos = nextpos;

	// General purpose registers
	if (length == 3 && token[0] == 'e') {
		for (i = 0; regs[i]; i++) {
			if (!r_str_ncasecmp (regs[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_DWORD;
				return i;
			}
		}
	}
	// General purpose registers: sil, dil
	if (length == 3 && token[1] == 'i' && token[2] == 'l') {
		*rex_prefixed = true;
		if (token[0] == 's') {
			*type = (OT_GPREG & OT_REG (X86R_SIL)) | OT_BYTE;
			return X86R_SIL;
		} else if (token[0] == 'd') {
			*type = (OT_GPREG & OT_REG (X86R_DIL)) | OT_BYTE;
			return X86R_DIL;
		} else {
			return X86R_UNDEFINED;
		}
	}
	// Control registers
	if (length == 3 && token[0] == 'c' && token[1] == 'r') {
		i = token[2] - '0';
		if (i < 0 || i > 7) {
			return X86R_UNDEFINED;
		}
		*type = (OT_CONTROLREG & OT_REG (i)) | OT_DWORD;
		return i;
	}
	// Debug registers
	if (length == 3 && token[0] == 'd' && token[1] == 'r') {
		i = token[2] - '0';
		if (i < 0 || i > 7) {
			return X86R_UNDEFINED;
		}
		*type = (OT_DEBUGREG & OT_REG (i)) | OT_DWORD;
		return i;
	}
	if (length == 2) {
		if (token[1] == 'l' || token[1] == 'h') {
			for (i = 0; regs8[i]; i++) {
				if (!r_str_ncasecmp (regs8[i], token, length)) {
					*type = (OT_GPREG & OT_REG (i)) | OT_BYTE;
					return i;
				}
			}
		}
		for (i = 0; regs16[i]; i++) {
			if (!r_str_ncasecmp (regs16[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_WORD;
				return i;
			}
		}
		// This isn't working properly yet
		for (i = 0; sregs[i]; i++) {
			if (!r_str_ncasecmp (sregs[i], token, length)) {
				*type = (OT_SEGMENTREG & OT_REG (i)) | OT_WORD;
				return i;
			}
		}
	}
	if (token[0] == 'r') {
		for (i = 0; regs64[i]; i++) {
			if (!r_str_ncasecmp (regs64[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_QWORD;
				a->config->bits = 64;
				return i;
			}
		}
		for (i = 0; regs64ext[i]; i++) {
			if (!r_str_ncasecmp (regs64ext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_QWORD;
				a->config->bits = 64;
				*extended = true;
				return i;
			}
		}
		for (i = 0; regsext[i]; i++) {
			if (!r_str_ncasecmp (regsext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_DWORD;
				if (a->config->bits < 32) {
					a->config->bits = 32;
				}
				*extended = true;
				return i;
			}
		}
		for (i = 0; regs16ext[i]; i++) {
			if (!r_str_ncasecmp (regs16ext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_WORD;
				*extended = true;
				return i;
			}
		}
		for (i = 0; regs8ext[i]; i++) {
			if (!r_str_ncasecmp (regs8ext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_BYTE;
				*extended = true;
				return i;
			}
		}
	}
	// Extended registers
	if (is_st_register (token)) {
		*type = (OT_FPUREG & ~OT_REGALL);
		*pos = 2;
	}
	if (is_mm_register (token)) {
		*type = (OT_MMXREG & ~OT_REGALL);
		*pos = 2;
	}
	if (is_xmm_register (token)) {
		*type = (OT_XMMREG & ~OT_REGALL);
		*pos = 3;
	}
	// Now read number, possibly with parentheses
	if (*type & (OT_FPUREG | OT_MMXREG | OT_XMMREG) & ~OT_REGALL) {
		Register reg = X86R_UNDEFINED;
		// pass by '(',if there is one
		if (getToken (token, pos, &nextpos) == TT_SPECIAL && token[*pos] == '(') {
			*pos = nextpos;
		}
		// read number
		// const int maxreg = (a->config->bits == 64) ? 15 : 7;
		if (getToken (token, pos, &nextpos) != TT_NUMBER) {
			R_LOG_ERROR ("Expected register number '%s'", str + *pos);
			return X86R_UNDEFINED;
		}
		bool berr = false;
		reg = getnum (a, token + *pos, &berr);
		if (berr) {
			return X86R_UNDEFINED;
		}
		// st and mm go up to 7, xmm up to 15
		if ((reg > 15) || ((*type & (OT_FPUREG | OT_MMXREG) & ~OT_REGALL) && reg > 7))   {
			R_LOG_ERROR ("Too large register index!");
			return X86R_UNDEFINED;
		}
		*pos = nextpos;

		// pass by ')'
		if (getToken (token, pos, &nextpos) == TT_SPECIAL && token[*pos] == ')') {
			*pos = nextpos;
		}
		*type |= (OT_REG (reg) & ~OT_REGTYPE);
		return reg;
	}
	return X86R_UNDEFINED;
}

static void parse_segment_offset(RArchSession *a, const char *str, size_t *pos, Operand *op, int reg_index) {
	int nextpos = *pos;
	char *c = strchr (str + nextpos, ':');
	if (c) {
		nextpos ++; // Skip the ':'
		c = strchr (str + nextpos, '[');
		if (c) {nextpos ++;} // Skip the '['

		// Assign registers to match behaviour of OT_MEMORY type
		op->regs[reg_index] = op->reg;
		op->type |= OT_MEMORY;
		op->offset_sign = 1;
		char *p = strchr (str + nextpos, '-');
		if (p) {
			op->offset_sign = -1;
			nextpos ++;
		}
		bool berr;
		op->scale[reg_index] = getnum (a, str + nextpos, &berr);
		if (berr) {
			return;
		}
		op->offset = op->scale[reg_index];
	}
}

// Parse operand, should return bool. but its returning nextpos
static int parseOperand(RArchSession *a, const char *str, Operand *op, bool isrepop) {
	size_t pos, nextpos = 0;
	x86newTokenType last_type;
	int size_token = 1;
	bool explicit_size = false;
	int reg_index = 0;
	// Reset type
	op->type = 0;
	// Consume tokens denoting the operand size
	while (size_token) {
		pos = nextpos;
		last_type = getToken (str, &pos, &nextpos);

		// Token may indicate size: then skip
		if (!r_str_ncasecmp (str + pos, "ptr", 3)) {
			continue;
		}
		if (!r_str_ncasecmp (str + pos, "byte", 4)) {
			op->type |= OT_MEMORY | OT_BYTE | OT_GPREG;
			op->dest_size = OT_BYTE;
			explicit_size = true;
		} else if (!r_str_ncasecmp (str + pos, "word", 4)) {
			op->type |= OT_MEMORY | OT_WORD | OT_GPREG;
			op->dest_size = OT_WORD;
			explicit_size = true;
		} else if (!r_str_ncasecmp (str + pos, "dword", 5)) {
			op->type |= OT_MEMORY | OT_DWORD | OT_GPREG;
			op->dest_size = OT_DWORD;
			explicit_size = true;
		} else if (!r_str_ncasecmp (str + pos, "qword", 5)) {
			op->type |= OT_MEMORY | OT_QWORD | OT_GPREG;
			op->dest_size = OT_QWORD;
			explicit_size = true;
		} else if (!r_str_ncasecmp (str + pos, "oword", 5)) {
			op->type |= OT_MEMORY | OT_OWORD | OT_GPREG;
			op->dest_size = OT_OWORD;
			explicit_size = true;
		} else if (!r_str_ncasecmp (str + pos, "tbyte", 5)) {
			op->type |= OT_MEMORY | OT_TBYTE | OT_GPREG;
			op->dest_size = OT_TBYTE;
			explicit_size = true;
		} else { // the current token doesn't denote a size
			size_token = 0;
		}
	}

	// Next token: register, immediate, or '['
	if (str[pos] == '[') {
		// Don't care about size, if none is given.
		if (!op->type) {
			op->type = OT_MEMORY;
		}
		// At the moment, we only accept plain linear combinations:
		// part := address | [factor *] register
		// address := part {+ part}*
		op->offset = op->scale[0] = op->scale[1] = 0;

		ut64 temp = 1;
		Register reg = X86R_UNDEFINED;
		bool first_reg = true;
		while (str[pos] != ']') {
			if (pos > nextpos) {
				break;
			}
			pos = nextpos;
			if (!str[pos]) {
				break;
			}
			last_type = getToken (str, &pos, &nextpos);

			if (last_type == TT_SPECIAL) {
				if (str[pos] == '+' || str[pos] == '-' || str[pos] == ']') {
					if (reg != X86R_UNDEFINED) {
						if (reg_index < 2) {
							op->regs[reg_index] = reg;
							op->scale[reg_index] = temp;
						}
						reg_index++;
					} else {
						op->offset += temp;
						if (reg_index < 2) {
							op->regs[reg_index] = X86R_UNDEFINED;
						}
					}
					temp = 1;
					reg = X86R_UNDEFINED;
				} else if (str[pos] == '*') {
					// go to ], + or - to get scale

					// Something to do here?
					// Seems we are just ignoring '*' or assuming it implicitly.
				}
			} else if (last_type == TT_WORD) {
				ut32 reg_type = 0;

				// We can't multiply registers
				if (reg != X86R_UNDEFINED) {
					op->type = 0;	// Make the result invalid
				}

				// Reset nextpos: parseReg wants to parse from the beginning
				nextpos = pos;
				reg = parseReg (a, str, &nextpos, &reg_type, &op->extended, &op->rex_prefixed);

				if (first_reg) {
					op->reg = reg;
					first_reg = false;
				}
				if (reg_type & OT_REGTYPE & OT_SEGMENTREG) {
					op->reg = reg;
					op->type = reg_type;
					parse_segment_offset (a, str, &nextpos, op, reg_index);
					return nextpos;
				}

				// Still going to need to know the size if not specified
				if (!explicit_size) {
					op->type |= reg_type;
				}
				op->reg_size = reg_type;
				op->explicit_size = explicit_size;

				// Addressing only via general purpose registers
				if (!(reg_type & OT_GPREG)) {
					op->type = 0;	// Make the result invalid
				}
			} else {
				char *p = strchr (str, '+');
				op->offset_sign = 1;
				if (!p) {
					p = strchr (str, '-');
					if (p) {
						op->offset_sign = -1;
					}
				}
				//with SIB notation, we need to consider the right sign
				char *plus = strchr (str, '+');
				char *minus = strchr (str, '-');
				char *closeB = strchr (str, ']');
				if (plus && minus && plus < closeB && minus < closeB) {
					op->offset_sign = -1;
				}
				// If there's a scale, we don't want to parse out the
				// scale with the offset (scale + offset) otherwise the scale
				// will be the sum of the two. This splits the numbers
				char *tmp = malloc (strlen (str + pos) + 1);
				if (!tmp) {
					return -1;
				}
				strcpy (tmp, str + pos);
				char *save_ptr = NULL;
				r_str_tok_r (tmp, "+-", &save_ptr);
				char *bracket = strchr (tmp, ']');
				if (bracket) {
					*bracket = 0;
				}
				bool berr;
				st64 read = getnum (a, tmp, &berr);
				if (berr) {
					return -1;
				}
				if (bracket) {
					*bracket = ']';
				}
				free (tmp);
				temp *= read;
			}
		}
	} else if (last_type == TT_WORD) { // register
#if 0
		nextpos = pos;
		RFlagItem *flag;

		if (isrepop) {
			op->is_good_flag = false;
			strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
			op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
			return nextpos;
		}

		op->reg = parseReg (a, str, &nextpos, &op->type);

		if (op->type & OT_REGTYPE & OT_SEGMENTREG) {
			parse_segment_offset (a, str, &nextpos, op, reg_index);
			return nextpos;
		}
		if (op->reg == X86R_UNDEFINED) {
			op->is_good_flag = false;
			if (a->num && a->num->value == 0) {
				return nextpos;
			}
			op->type = OT_CONSTANT;
			RCore *core = a->num? (RCore *)(a->num->userptr): NULL;
			if (core && (flag = r_flag_get (core->flags, str))) {
				op->is_good_flag = true;
			}

			char *p = strchr (str, '-');
			if (p) {
				op->sign = -1;
				str = p++;
			}
			op->immediate = getnum (a, str);
		} else if (op->reg < X86R_UNDEFINED) {
			strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
			op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
		}
#else
		nextpos = pos;

		if (isrepop) {
			op->is_good_flag = false;
			strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
			op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
			return nextpos;
		}

		op->reg = parseReg (a, str, &nextpos, &op->type, &op->extended, &op->rex_prefixed);

		if (op->type & OT_REGTYPE & OT_SEGMENTREG) {
			parse_segment_offset (a, str, &nextpos, op, reg_index);
			return nextpos;
		}
		if (op->reg == X86R_UNDEFINED) {
			op->is_good_flag = false;
#if 1
			RNum *num = R_UNWRAP3 (a, arch, num);
			if (num && (num->value == 0 || num->value == UT64_MAX)) {
				return nextpos;
			}
#endif
			op->type = OT_CONSTANT;
#if 0
			RCore *core = a->num? (RCore *)(a->num->userptr): NULL;
			if (core && (flag = r_flag_get (core->flags, str))) {
				op->is_good_flag = true;
			}
#endif
			char *p = strchr (str, '-');
			if (p) {
				op->sign = -1;
				str = p++;
			}
			bool berr;
			op->immediate = getnum (a, str, &berr);
			if (berr) {
				return -1;
			}
		} else if (op->reg < X86R_UNDEFINED) {
			strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
			op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
		}
#endif
	} else { // immediate
		// We don't know the size, so let's just set no size flag.
		op->type = OT_CONSTANT;
		op->sign = 1;
		const char *p = strchr (str, '-');
		if (p) {
			op->sign = -1;
			str = ++p;
		}
		bool berr;
		ut64 n = getnum (a, str, &berr);
		if (berr) {
			return -1;
		}
		op->immediate = n;
	}
	return nextpos;
}

static int parseOpcode(RArchSession *a, const char *op, Opcode *out) {
	out->has_bnd = false;
	bool isrepop = false;
	if (r_str_startswith (op, "bnd ")) {
		out->has_bnd = true;
		op += 4;
	}
	char *args = strchr (op, ' ');
	out->mnemonic = args? r_str_ndup (op, args - op): strdup (op);
	out->operands[0].type = out->operands[1].type = 0;
	out->operands[0].extended = out->operands[1].extended = false;
	out->operands[0].rex_prefixed = out->operands[1].rex_prefixed = false;
	out->operands[0].reg = out->operands[0].regs[0] = out->operands[0].regs[1] = X86R_UNDEFINED;
	out->operands[1].reg = out->operands[1].regs[0] = out->operands[1].regs[1] = X86R_UNDEFINED;
	out->operands[0].immediate = out->operands[1].immediate = 0;
	out->operands[0].sign = out->operands[1].sign = 1;
	out->operands[0].is_good_flag = out->operands[1].is_good_flag = true;
	out->is_short = false;
	out->operands_count = 0;
	if (args) {
		args++;
	} else {
		return 1;
	}
	if (!r_str_ncasecmp (args, "short", 5)) {
		out->is_short = true;
		args += 5;
	}
	if (!strncmp (out->mnemonic, "rep", 3)) {
		isrepop = true;
	}
	if (parseOperand (a, args, &(out->operands[0]), isrepop) == -1) {
		return -1;
	}
	out->operands_count = 1;
	while (out->operands_count < MAX_OPERANDS) {
		args = strchr (args, ',');
		if (!args) {
			break;
		}
		args++;
		if (parseOperand (a, args, &(out->operands[out->operands_count]), isrepop) == -1) {
			return -1;
		}
		out->operands_count++;
	}
	return 0;
}

static int oprep(RArchSession *a, ut8 *data, const Opcode *op) {
	int l = 0;
	const LookupTable *lt_ptr;
	int retval;

	if (!strcmp (op->mnemonic, "rep")
			|| !strcmp (op->mnemonic, "repe")
			|| !strcmp (op->mnemonic, "repz")) {
		data[l++] = 0xf3;
	} else if (!strcmp (op->mnemonic, "repne")
			|| !strcmp (op->mnemonic, "repnz")) {
		data[l++] = 0xf2;
	}
	Opcode instr = {0};
	if (parseOpcode (a, op->operands[0].rep_op, &instr) == -1) {
		return -1;
	}

	for (lt_ptr = oplookup; strcmp (lt_ptr->mnemonic, "null"); lt_ptr++) {
		if (!r_str_casecmp (instr.mnemonic, lt_ptr->mnemonic)) {
			if (lt_ptr->opcode > 0) {
				if (lt_ptr->only_x32 && a->config->bits == 64) {
					free (instr.mnemonic);
					return -1;
				}
				ut64 opcode = lt_ptr->opcode;
				int i = lt_ptr->size - 1;
				for (; i >= 0; i--) {
					data[i + l] = opcode & 0xff;
					opcode >>= 8;
				}
				free (instr.mnemonic);
				return l + lt_ptr->size;
			} else {
				if (lt_ptr->opdo) {
					data += l;
					if (instr.has_bnd) {
						data[l] = 0xf2;
						data++;
					}
					retval = lt_ptr->opdo (a, data, &instr);
					// if op supports bnd then the first byte will
					// be 0xf2.
					if (instr.has_bnd) {
						retval++;
					}
					free (instr.mnemonic);
					return l + retval;
				}
				break;
			}
		}
	}
	free (instr.mnemonic);
	return -1;
}

R_API int x86nz_assemble(RArchSession *a, RAnalOp *ao, const char *str) {
	ut8 __data[32] = {0};
	ut8 *data = __data;
	const LookupTable *lt_ptr;
	int retval = -1;
	Opcode instr = {0};
	instr.addr = ao->addr;

	// XXX remove fixed size buffers!
	char op[128];
	r_str_ncpy (op, str, sizeof (op) - 1);
	if (parseOpcode (a, op, &instr) == -1) {
		return -1;
	}
	for (lt_ptr = oplookup; strcmp (lt_ptr->mnemonic, "null"); lt_ptr++) {
		if (!r_str_casecmp (instr.mnemonic, lt_ptr->mnemonic)) {
			if (lt_ptr->opcode > 0) {
				if (!lt_ptr->only_x32 || a->config->bits != 64) {
					ut64 opcode = lt_ptr->opcode;
					int i = lt_ptr->size - 1;
					for (; i >= 0; i--) {
						data[i] = opcode & 0xff;
						opcode >>= 8;
					}
					retval = lt_ptr->size;
					ao->size = lt_ptr->size;
				}
			} else {
				if (lt_ptr->opdo) {
					if (instr.has_bnd) {
						data[0] = 0xf2;
						data ++;
					}
					retval = lt_ptr->opdo (a, data, &instr);
					// if op supports bnd then the first byte will
					// be 0xf2.
					if (instr.has_bnd) {
						retval++;
					}
				}
			}
			break;
		}
	}
	if (retval > 0) {
		r_anal_op_set_bytes (ao, ao->addr, __data, retval);
	}
	free (instr.mnemonic);
	ao->size = retval;
	return retval;
}
