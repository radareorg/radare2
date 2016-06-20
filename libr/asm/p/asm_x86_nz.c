/* Copyright (C) 2008-2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>

static int getnum(RAsm *a, const char *s);

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

// For register operands, we mostl don't care about the size.
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

typedef enum tokentype_t {
	TT_EOF,
	TT_WORD,
	TT_NUMBER,
	TT_SPECIAL
} x86newTokenType;

typedef enum register_t {
	X86R_UNDEFINED = -1,
	X86R_EAX = 0, X86R_ECX, X86R_EDX, X86R_EBX, X86R_ESP, X86R_EBP, X86R_ESI, X86R_EDI,
	X86R_AX = 0, X86R_CX, X86R_DX, X86R_BX, X86R_SP, X86R_BP, X86R_SI, X86R_DI,
	X86R_AL = 0, X86R_CL, X86R_DL, X86R_BL, X86R_AH, X86R_CH, X86R_DH, X86R_BH,
	X86R_RAX = 0, X86R_RCX, X86R_RDX, X86R_RBX, X86R_RSP, X86R_RBP, X86R_RSI, X86R_RDI,
	X86R_CS = 0, X86R_SS, X86R_DS, X86R_ES, X86R_FS, X86R_GS	// Is this the right order?
} Register;

typedef struct operand_t {
	ut32 type;
	st8 sign;
	union {
		Register reg;
		struct {
			long offset;
			st8 offset_sign;
			Register regs[2];
			int scale[2];
		};
		ut32 immediate;
	};
} Operand;

typedef struct Opcode_t {
	char *mnemonic;
	ut32 op[3];
	size_t op_len;
	ut8 opcode[3];
	Operand operands[2];
} Opcode;

static ut8 getsib(const ut8 sib) {
	if (!sib) return 0;
	return (sib & 0x8) ? 3 : getsib ((sib << 1) | 1) - 1;
}

static int process_group_1(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int offset = 0;
	st32 immediate = 0;

	if (a->bits == 64) data[l++] = 0x48;

	if (!strcmp (op.mnemonic, "adc")) {
		modrm = 2;
	} else if (!strcmp (op.mnemonic, "add")) {
		modrm = 0;
	} else if (!strcmp (op.mnemonic, "or")) {
		modrm = 1;
	} else if (!strcmp (op.mnemonic, "and")) {
		modrm = 4;
	} else if (!strcmp (op.mnemonic, "xor")) {
		modrm = 6;
	} else if (!strcmp (op.mnemonic, "sbb")) {
		modrm = 3;
	} else if (!strcmp (op.mnemonic, "sub")) {
		modrm = 5;
	} else if (!strcmp (op.mnemonic, "cmp")) {
		modrm = 7;
	}
	immediate = op.operands[1].immediate * op.operands[1].sign;

	if (op.operands[0].type & OT_DWORD || op.operands[0].type & OT_QWORD) {
		data[l++] = (op.operands[1].immediate > 127) ? 0x81 : 0x83;
	} else if (op.operands[0].type & OT_BYTE) {
		if (immediate > 255 || immediate < -256) {
			eprintf ("Error: Immediate exceeds bounds\n");
			return -1;
		}
		data[l++] = 0x80;
	}
	if (op.operands[0].type & OT_MEMORY) {
		offset = op.operands[0].offset * op.operands[0].offset_sign;
		if (op.operands[0].offset || op.operands[0].regs[0] == X86R_EBP) {
			mod_byte = 1;
		}
		if (offset < ST8_MIN || offset > ST8_MAX) {
			mod_byte = 2;
		}
		data[l++] = mod_byte << 6 | modrm << 3 | op.operands[0].regs[0];

		if (op.operands[0].regs[0] == X86R_ESP) {
			data[l++] = 0x24;
		}
		if (mod_byte) {
			data[l++] = offset;
			if (mod_byte == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	} else {
		mod_byte = 3;
		data[l++] = mod_byte << 6 | modrm << 3 | op.operands[0].reg;
	}

	data[l++] = immediate;
	if ((immediate > 127 || immediate < -128) && op.operands[0].type & OT_DWORD) {
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int process_group_2(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int reg0 = 0;

	eprintf("size %d\n", sizeof(data));

	if (a->bits == 64) data[l++] = 0x48;

	if (!strcmp (op.mnemonic, "rol")) {
		modrm = 0;
	} else if (!strcmp (op.mnemonic, "ror")) {
		modrm = 1;
	} else if (!strcmp (op.mnemonic, "rcl")) {
		modrm = 2;
	} else if (!strcmp (op.mnemonic, "rcr")) {
		modrm = 3;
	} else if (!strcmp (op.mnemonic, "shl")) {
		modrm = 4;
	} else if (!strcmp (op.mnemonic, "shr")) {
		modrm = 5;
	} else if (!strcmp (op.mnemonic, "sal")) {
		modrm = 6;
	} else if (!strcmp (op.mnemonic, "sar")) {
		modrm = 7;
	}

	st32 immediate = op.operands[1].immediate * op.operands[1].sign;
	if (immediate > 255 || immediate < -128) {
		eprintf ("Error: Immediate exceeds bounds\n");
		return -1;
	}

	if (op.operands[0].type & (OT_DWORD | OT_QWORD)) {
		if (op.operands[1].type & (OT_GPREG | OT_BYTE)) {
			data[l++] = 0xd3;
		} else if (immediate == 1) {
			data[l++] = 0xd1;
		} else {
			data[l++] = 0xc1;
		}
	} else if (op.operands[0].type & OT_BYTE) {
		if (op.operands[1].type & (OT_GPREG | OT_WORD)) {
			data[l++] = 0xd2;
		} else if (immediate == 1) {
			data[l++] = 0xd0;
		} else {
			data[l++] = 0xc0;
		}
	}
	if (op.operands[0].type & OT_MEMORY) {
		reg0 = op.operands[0].regs[0];
		mod_byte = 0;
	} else {
		reg0 = op.operands[0].reg;
		mod_byte = 3;
	}
	data[l++] = mod_byte << 6 | modrm << 3 | reg0;
	if (immediate != 1 && !(op.operands[1].type & OT_GPREG)) {
		data[l++] = immediate;
	}
	return l;
}

static int process_1byte_op(RAsm *a, ut8 *data, const Opcode op, int op1) {
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	st32 offset = 0;

	if (a->bits == 64) data[l++] = 0x48;

	if (op.operands[0].type & OT_MEMORY && op.operands[1].type & OT_REGALL) {
		if (op.operands[0].type & OT_BYTE && op.operands[1].type & OT_BYTE) {
			data[l++] = op1;
		} else if (op.operands[0].type & (OT_DWORD | OT_QWORD) && op.operands[1].type & (OT_DWORD | OT_QWORD)) {
			data[l++] = op1 + 0x1;
		} else {
			eprintf ("Error: mismatched operand sizes\n");
			return -1;
		}
		reg = op.operands[1].reg;
		rm = op.operands[0].regs[0];

		offset = op.operands[0].offset * op.operands[0].offset_sign;
		if (offset) {
			mod_byte = 1;
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}
		}
	} else if (op.operands[0].type & OT_REGALL) {
		if (op.operands[1].type & OT_MEMORY) {
			if (op.operands[0].type & OT_BYTE && op.operands[1].type & OT_BYTE) {
				data[l++] = op1 + 0x2;
			} else if (op.operands[0].type & (OT_DWORD | OT_QWORD) && op.operands[1].type & (OT_DWORD | OT_QWORD)) {
				data[l++] = op1 + 0x3;
			} else {
				eprintf ("Error: mismatched operand sizes\n");
				return -1;
			}
			reg = op.operands[0].reg;
			rm = op.operands[1].regs[0];

			if (op.operands[1].scale[0] > 1) {
				if (op.operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = op.operands[0].reg << 3 | 4;
					data[l++] = getsib (op.operands[1].scale[0]) << 6 | op.operands[1].regs[0] << 3 | op.operands[1].regs[1];
					return l;
				}
				data[l++] = op.operands[0].reg << 3 | 4; // 4 = SIB
				data[l++] = getsib (op.operands[1].scale[0]) << 6 | op.operands[1].regs[0] << 3 | 5;
				data[l++] = op.operands[1].offset * op.operands[1].offset_sign;
				data[l++] = 0;
				data[l++] = 0;
				data[l++] = 0;
				return l;
			}
			offset = op.operands[1].offset * op.operands[1].offset_sign;
			if (offset) {
				mod_byte = 1;
				if (offset < ST8_MIN || offset > ST8_MAX) {
					mod_byte = 2;
				}
			}

		} else if (op.operands[1].type & OT_REGALL) {
			if (op.operands[0].type & OT_BYTE && op.operands[1].type & OT_BYTE) {
				data[l++] = op1;
			} else if (op.operands[0].type & OT_DWORD && op.operands[1].type & OT_DWORD) {
				data[l++] = op1 + 0x1;
			}
			mod_byte = 3;
			reg = op.operands[1].reg;
			rm = op.operands[0].reg;
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

static int opadc(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x10);
}

static int opadd(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x00);
}

static int opand(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x20);
}

static int opcmp(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x38);
}

static int opsub(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x28);
}

static int opor(RAsm *a, ut8 * data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x08);
}

static int opxor(RAsm *a, ut8 * data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x30);
}

static int opsbb(RAsm *a, ut8 *data, const Opcode op) {
	if (op.operands[1].type & OT_CONSTANT) {
		return process_group_1 (a, data, op);
	}
	return process_1byte_op (a, data, op, 0x18);
}

static int opbswap(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (op.operands[0].type | OT_REGALL) {
		if (op.operands[0].reg == X86R_UNDEFINED) {return -1;}
		data[l++] = 0x0f;
		data[l++] = 0xc8 + op.operands[0].reg;
	}
	return l;
}

static int opcall(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (op.operands[0].type | OT_REGALL) {
		if (op.operands[0].reg == X86R_UNDEFINED) {return -1;}
		data[l++] = 0xff;
		data[l++] = op.operands[0].reg | 0xd0;
	}
	return l;
}

static int opdec(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (op.operands[1].type) {
		eprintf ("Error: Invalid operands\n");
		return -1;
	}
	if (op.operands[0].type & OT_BYTE) {
		data[l++] = 0xfe;
		if (op.operands[0].type & OT_MEMORY) {
			data[l++] = 0x1 << 3 | op.operands[0].regs[0];
		} else {
			data[l++] = 0x19 << 3 | op.operands[0].reg;
		}
	} else {
		if (op.operands[0].type & OT_MEMORY) {
			data[l++] = 0xff;
			data[l++] = 0x1 << 3 | op.operands[0].regs[0];
		} else {
			if (a->bits == 32) {
				data[l++] = 0x48 | op.operands[0].reg;
			} else if (a->bits == 64) {
				data[l++] = 0x48;
				data[l++] = 0xff;
				data[l++] = 0xc8 | op.operands[0].reg;
			}
		}
	}
	return l;
}

static int opin(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	st32 immediate = 0;
	if (op.operands[1].reg == X86R_DX) {
		if (op.operands[0].reg == X86R_AL && op.operands[0].type & OT_BYTE) {
			data[l++] = 0xec;
			return l;
		}
		if (op.operands[0].reg == X86R_AX && op.operands[0].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xed;
			return l;
		}
		if (op.operands[0].reg == X86R_EAX && op.operands[0].type & OT_DWORD) {
			data[l++] = 0xed;
			return l;
		}
	} else if (op.operands[1].type & OT_CONSTANT) {
		immediate = op.operands[1].immediate * op.operands[1].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op.operands[0].reg == X86R_AL && op.operands[0].type & OT_BYTE) {
			data[l++] = 0xe4;
		} else if (op.operands[0].reg == X86R_AX && op.operands[0].type & OT_BYTE) {
			data[l++] = 0x66;
			data[l++] = 0xe5;
		} else if (op.operands[0].reg == X86R_EAX && op.operands[0].type & OT_DWORD) {
			data[l++] = 0xe5;
		}
		data[l++] = immediate;
	}
	return l;
}

static int opinc(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (op.operands[0].type & OT_REGALL) {
		if (op.operands[0].type & OT_BYTE) {
			data[l++] = 0xfe;
			data[l++] = 0xc0 | op.operands[0].reg;
		} else {
			data[l++] = 0x40 | op.operands[0].reg;
		}
	} else {
		if (op.operands[0].type & OT_BYTE) {
			data[l++] = 0xfe;
		} else {
			data[l++] = 0xff;
		}
		data[l++] = op.operands[0].regs[0];
	}
	return l;
}

static int opint(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (op.operands[0].type & OT_CONSTANT) {
		st32 immediate = op.operands[0].immediate * op.operands[0].sign;
		if (immediate <= 255 && immediate >= -128) {
			data[l++] = 0xcd;
			data[l++] = immediate;
		}
	}
	return l;
}

static int oplea(RAsm *a, ut8 *data, const Opcode op){
	int l =0;
	int mod = 0;
	st32 offset = 0;
	int reg = 0;
	int rm = 0;
	if(op.operands[0].type & OT_REGALL && op.operands[1].type & OT_MEMORY) {
		data[l++] = 0x8d;
		if (op.operands[1].regs[0] == X86R_UNDEFINED) {
			data[l++] = op.operands[0].reg << 3 | 5;
			data[l++] = op.operands[1].offset;
			data[l++] = op.operands[1].offset >> 6;
			data[l++] = op.operands[1].offset >> 16;
			data[l++] = op.operands[1].offset >> 24;
			return l;
		} else {
			reg = op.operands[0].reg;
			rm = op.operands[1].regs[0];

			offset = op.operands[1].offset * op.operands[1].offset_sign;
			if (offset != 0 || op.operands[1].regs[0] == X86R_EBP) {
				mod = 1;
				if (offset >= 128 || offset < -128) {
					mod = 2;
				}
				data[l++] = mod << 6 | reg << 3 | rm;
				if (op.operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				data[l++] = offset;
				if (mod == 2) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			} else {
				data[l++] = op.operands[0].reg << 3 | op.operands[1].regs[0];
				if (op.operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
			}

		}
	}
	return l;
}

static int oppop(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	int offset = 0;
	int mod = 0;
	if (op.operands[0].type & OT_GPREG) {
		ut8 base = 0x58;
		data[l++] = base + op.operands[0].reg;
	} else if (op.operands[0].type & OT_MEMORY) {
		data[l++] = 0x8f;
		offset = op.operands[0].offset * op.operands[0].offset_sign;
		if (offset != 0 || op.operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | op.operands[0].regs[0];
			if (op.operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		} else {
			data[l++] = op.operands[0].regs[0];
			if (op.operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}

	}
	return l;
}

static int oppush(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	int mod = 0;
	st32 immediate = 0;;
	st32 offset = 0;
	if (op.operands[0].type & OT_GPREG) {
		ut8 base = 0x50;
		data[l++] = base + op.operands[0].reg;
	} else if (op.operands[0].type & OT_MEMORY) {
		data[l++] = 0xff;
		offset = op.operands[0].offset * op.operands[0].offset_sign;
		mod = 0;
		if (offset != 0 || op.operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | 6 << 3 | op.operands[0].regs[0];
			if (op.operands[0].regs[0] == X86R_ESP) {
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
			data[l++] = mod << 4 | op.operands[0].regs[0];
			if (op.operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}
	} else {
		immediate = op.operands[0].immediate * op.operands[0].sign;
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

static int opout(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	st32 immediate = 0;
	if (op.operands[0].reg == X86R_DX) {
		if (op.operands[1].reg == X86R_AL && op.operands[1].type & OT_BYTE) {
			data[l++] = 0xec;
			return l;
		}
		if (op.operands[1].reg == X86R_AX && op.operands[1].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xed;
			return l;
		}
		if (op.operands[1].reg == X86R_EAX && op.operands[1].type & OT_DWORD) {
			data[l++] = 0xed;
			return l;
		}
	} else if (op.operands[0].type & OT_CONSTANT) {
		immediate = op.operands[0].immediate * op.operands[0].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op.operands[0].reg == X86R_AL && op.operands[1].type & OT_BYTE) {
			data[l++] = 0xe6;
		} else if (op.operands[0].reg == X86R_AX && op.operands[0].type & OT_BYTE) {
			data[l++] = 0x66;
			data[l++] = 0xe7;
		} else if (op.operands[1].reg == X86R_EAX && op.operands[1].type & OT_DWORD) {
			data[l++] = 0xe7;
		}
		data[l++] = immediate;
	}
	return l;
}

static int opretf(RAsm *a, ut8 *data, const Opcode op) {
	int l =0;
	st32 immediate = 0;
	if (op.operands[0].type & OT_CONSTANT) {
		immediate = op.operands[0].immediate * op.operands[0].sign;
		data[l++] = 0xca;
		data[l++] = immediate;
		data[l++] = immediate >> 8;
	} else if (op.operands[0].type == OT_UNKNOWN) {
		data[l++] = 0xcb;
	}
	return l;
}

static int optest(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	if (!op.operands[0].type || !op.operands[1].type) {
		eprintf ("Error: Invalid operands\n");
		return -1;
	}
	if (a->bits == 64) 	data[l++] = 0x48;

	if (op.operands[1].type & OT_CONSTANT) {
		if (op.operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
			data[l++] = op.operands[0].regs[0];
			data[l++] = op.operands[1].reg;
			return l;
		}
		data[l++] = 0xf7;
		if (op.operands[0].type & OT_MEMORY) {
			data[l++] = 0x01 | op.operands[0].reg;
		} else {
			data[l++] = 0xc0 | op.operands[0].reg;
		}
		data[l++] = op.operands[1].reg >> 0;
		data[l++] = op.operands[1].reg >> 8;
		data[l++] = op.operands[1].reg >> 16;
		data[l++] = op.operands[1].reg >> 24;
		return l;
	}
	data[l++] = 0x85;
	if (op.operands[0].type & OT_MEMORY) {
		data[l++] = 0x01 | op.operands[1].reg << 3 | op.operands[0].reg;
	} else {
		data[l++] = 0xc0 | op.operands[1].reg << 3 | op.operands[0].reg;
	}
	return l;
}

static int opxchg(RAsm *a, ut8 *data, const Opcode op) {
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	st32 offset = 0;

	if (op.operands[0].type & OT_MEMORY || op.operands[1].type & OT_MEMORY) {
		data[l++] = 0x87;
		if (op.operands[0].type & OT_MEMORY) {
			rm = op.operands[0].regs[0];
			offset = op.operands[0].offset * op.operands[0].offset_sign;
			reg = op.operands[1].reg;
		} else if (op.operands[1].type & OT_MEMORY) {
			rm = op.operands[1].regs[0];
			offset = op.operands[1].offset * op.operands[1].offset_sign;
			reg = op.operands[0].reg;
		}
		if (offset) {
			mod_byte = 1;
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}
		}
	} else {
		if (op.operands[0].reg == X86R_EAX && op.operands[1].type & OT_GPREG) {
			data[l++] = 0x90 + op.operands[1].reg;
			return l;
		} else if (op.operands[1].reg == X86R_EAX && op.operands[0].type & OT_GPREG) {
			data[l++] = 0x90 + op.operands[0].reg;
			return l;
		} else if (op.operands[0].type & OT_GPREG && op.operands[1].type & OT_GPREG) {
			mod_byte = 3;
			data[l++] = 0x87;
			reg = op.operands[1].reg;
			rm = op.operands[0].reg;
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

typedef struct lookup_t {
	char mnemonic[12];
	int (*opdo)(RAsm*, ut8*, const Opcode);
	ut64 opcode;
	int size;
} LookupTable;

LookupTable oplookup[] = {
	{"aaa", NULL, 0x37, 1},
	{"aad", NULL, 0xd50a, 2},
	{"aam", NULL, 0xd40a, 2},
	{"aas", NULL, 0x3f, 1},
	{"adc", &opadc, 0},
	{"add", &opadd, 0},
	{"adx", NULL, 0xd4, 1},
	{"amx", NULL, 0xd5, 1},
	{"and", &opand, 0},
	{"bswap", &opbswap, 0},
	{"call", &opcall, 0},
	{"cbw", NULL, 0x6698, 2},
	{"cdq", NULL, 0x99, 1},
	{"cdqe", NULL, 0x98, 1},
	{"clc", NULL, 0xf8, 1},
	{"cld", NULL, 0xfc, 1},
	{"clgi", NULL, 0x0f01dd, 3},
	{"cli", NULL, 0xfa, 1},
	{"clts", NULL, 0x0f06, 2},
	{"cmc", NULL, 0xf5, 1},
	{"cmp", &opcmp, 0},
	{"cpuid", NULL, 0x0fa2, 2},
	{"cwd", NULL, 0x6699, 2},
	{"cwde", NULL, 0x98, 1},
	{"daa", NULL, 0x27, 1},
	{"das", NULL, 0x2f, 1},
	{"dec", &opdec, 0},
	{"emms", NULL, 0x0f77, 2},
	{"femms", NULL, 0x0f0e, 2},
	{"fsincos", NULL, 0xd9fb, 2},
	{"getsec", NULL, 0x0f37, 2},
	{"hlt", NULL, 0xf4, 1},
	{"in", &opin, 0},
	{"inc", &opinc, 0},
	{"int", &opint, 0},
	{"int1", NULL, 0xf1, 1},
	{"int3", NULL, 0xcc, 1},
	{"into", NULL, 0xce, 1},
	{"invd", NULL, 0x0f08, 2},
	{"iret", NULL, 0x66cf, 2},
	{"iretd", NULL, 0xcf, 1},
	{"lea", &oplea, 0},
	{"leave", NULL, 0xc9, 1},
	{"lfence", NULL, 0x0faee8, 3},
	{"mfence", NULL, 0x0faef0, 3},
	{"monitor", NULL, 0x0f01c8, 3},
	{"mwait", NULL, 0x0f01c9, 3},
	{"nop", NULL, 0x90, 1},
	{"or", &opor, 0},
	{"out", &opout, 0},
	{"pop", &oppop, 0},
	{"popal", NULL, 0x61, 1},
	{"popaw", NULL, 0x6661, 2},
	{"popfd", NULL, 0x9d, 1},
	{"push", &oppush, 0},
	{"pushal", NULL, 0x60, 1},
	{"pushfd", NULL, 0x9c, 1},
	{"rcl", &process_group_2, 0},
	{"rcr", &process_group_2, 0},
	{"rdmsr", NULL, 0x0f32, 2},
	{"rdpmc", NULL, 0x0f33, 2},
	{"rdtsc", NULL, 0x0f31, 2},
	{"rdtscp", NULL, 0x0f01f9, 3},
	{"ret", NULL, 0xc3, 1},
	{"retf", &opretf, 0},
	{"retw", NULL, 0x66c3, 2},
	{"rol", &process_group_2, 0},
	{"ror", &process_group_2, 0},
	{"rsm", NULL, 0x0faa, 2},
	{"sahf", NULL, 0x9e, 1},
	{"sal", &process_group_2, 0},
	{"salc", NULL, 0xd6, 1},
	{"sar", &process_group_2, 0},
	{"sbb", &opsbb, 0},
	{"sfence", NULL, 0x0faef8, 3},
	{"shl", &process_group_2, 0},
	{"shr", &process_group_2, 0},
	{"stc", NULL, 0xf9, 1},
	{"std", NULL, 0xfd, 1},
	{"stgi", NULL, 0x0f01dc, 3},
	{"sti", NULL, 0xfb, 1},
	{"sub", &opsub, 0},
	{"swapgs", NULL, 0x0f1ff8, 3},
	{"syscall", NULL, 0x0f05, 2},
	{"sysenter", NULL, 0x0f34, 2},
	{"sysexit", NULL, 0x0f35, 2},
	{"sysret", NULL, 0x0f07, 2},
	{"ud2", NULL, 0x0f0b, 2},
	{"vmcall", NULL, 0x0f01c1, 3},
	{"vmlaunch", NULL, 0x0f01c2, 3},
	{"vmload", NULL, 0x0f01da, 3},
	{"vmmcall", NULL, 0x0f01d9, 3},
	{"vmresume", NULL, 0x0f01c3, 3},
	{"vmrun", NULL, 0x0f01d8, 3},
	{"vmsave", NULL, 0x0f01db, 3},
	{"vmxoff", NULL, 0x0f01c4, 3},
	{"vzeroall", NULL, 0xc5fc77, 3},
	{"vzeroupper", NULL, 0xc5f877, 3},
	{"wbinvd", NULL, 0x0f09, 2},
	{"wrmsr", NULL, 0x0f30, 2},
	{"xchg", &opxchg, 0},
	{"xgetbv", NULL, 0x0f01d0, 3},
	{"xlatb", NULL, 0xd7, 1},
	{"xor", &opxor, 0},
	{"xsetbv", NULL, 0x0f01d1, 3},
	{"test", &optest, 0},
};

static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
	// Skip whitespace
	while (isspace ((int)str[*begin]))
		++(*begin);

	if (!str[*begin]) {                // null byte
		*end = *begin;
		return TT_EOF;
	} else if (isalpha ((int)str[*begin])) {   // word token
		*end = *begin;
		while (isalnum ((int)str[*end]))
			++(*end);
		return TT_WORD;
	} else if (isdigit ((int)str[*begin])) {   // number token
		*end = *begin;
		while (isalnum ((int)str[*end]))     // accept alphanumeric characters, because hex.
			++(*end);
		return TT_NUMBER;
	} else {                             // special character: [, ], +, *, ...
		*end = *begin + 1;
		return TT_SPECIAL;
	}
}

/**
 * Get the register at position pos in str. Increase pos afterwards.
 */
static Register parseReg(RAsm *a, const char *str, size_t *pos, ut32 *type) {
	int i;
	// Must be the same order as in enum register_t
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", NULL };
	const char *regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	const char *regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", NULL };
	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", NULL };
	const char *sregs[] = { "es", "cs", "ss", "ds", "fs", "gs", NULL};

	// Get token (especially the length)
	size_t nextpos, length;
	const char *token;
	getToken (str, pos, &nextpos);
	token = str + *pos;
	length = nextpos - *pos;
	*pos = nextpos;

	// General purpose registers
	if (length == 3 && token[0] == 'e')
		for (i = 0; regs[i]; i++)
			if (!strncasecmp (regs[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_DWORD;
				return i;
			}
	if (length == 2 && (token[1] == 'l' || token[1] == 'h'))
		for (i = 0; regs8[i]; i++)
			if (!strncasecmp (regs8[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_BYTE;
				return i;
			}
	if (length == 2) {
		for (i = 0; regs16[i]; i++) {
			if (!strncasecmp (regs16[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_WORD;
				return i;
			}
		}
		// This isn't working properly yet
		for (i = 0; sregs[i]; i++) {
			if (!strncasecmp (sregs[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_BYTE;
				return i;
			}
		}
	}
	if (token[0] == 'r') {
		for (i = 0; regs64[i]; i++) {
			if (!strncasecmp (regs64[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_QWORD;
				return i;
			}
		}
	}

	// Numbered registers
	if (!strncasecmp ("st", token, length)) {
		*type = (OT_FPUREG & ~OT_REGALL);
	}
	if (!strncasecmp ("mm", token, length)) {
		*type = (OT_MMXREG & ~OT_REGALL);
	}
	if (!strncasecmp ("xmm", token, length)) {
		*type = (OT_XMMREG & ~OT_REGALL);
	}

	// Now read number, possibly with parantheses
	if (*type & (OT_FPUREG | OT_MMXREG | OT_XMMREG) & ~OT_REGALL) {
		Register reg = X86R_UNDEFINED;

		// pass by '(',if there is one
		if (getToken (str, pos, &nextpos) == TT_SPECIAL && str[*pos] == '(')
			*pos = nextpos;

		// read number
		if (getToken (str, pos, &nextpos) != TT_NUMBER ||
				(reg = getnum (a, str + *pos)) > 7)
			eprintf ("Too large register index!");
		*pos = nextpos;

		// pass by ')'
		if (getToken (str, pos, &nextpos) == TT_SPECIAL && str[*pos] == ')')
			*pos = nextpos;

		*type |= (OT_REG(reg) & ~OT_REGTYPE);
		return reg;
	}

	return X86R_UNDEFINED;
}

// Parse operand
static int parseOperand(RAsm *a, const char *str, Operand *op) {
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
		if (!strncasecmp (str + pos, "ptr", 3))
			continue;
		else if (!strncasecmp (str + pos, "byte", 4)) {
			op->type |= OT_MEMORY | OT_BYTE;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "word", 4)) {
			op->type |= OT_MEMORY | OT_WORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "dword", 5)) {
			op->type |= OT_MEMORY | OT_DWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "qword", 5)) {
			op->type |= OT_MEMORY | OT_QWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "oword", 5)) {
			op->type |= OT_MEMORY | OT_OWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "tbyte", 5)) {
			op->type |= OT_MEMORY | OT_TBYTE;
			explicit_size = true;
		} else	// the current token doesn't denote a size
			size_token = 0;
	}

	// Next token: register, immediate, or '['
	if (str[pos] == '[') {
		// Don't care about size, if none is given.
		if (!op->type)
			op->type = OT_MEMORY;

		// At the moment, we only accept plain linear combinations:
		// part := address | [factor *] register
		// address := part {+ part}*
		op->offset = op->scale[0] = op->scale[1] = 0;

		ut64 temp = 1;
		Register reg = X86R_UNDEFINED;
		while (str[pos] != ']') {
			pos = nextpos;
			last_type = getToken (str, &pos, &nextpos);

			if (last_type == TT_SPECIAL) {
				if (str[pos] == '+' || str[pos] == '-' || str[pos] == ']') {
					if (reg != X86R_UNDEFINED) {
						op->regs[reg_index] = reg;
						op->scale[reg_index] = temp;
						++reg_index;
					}
					else {
						op->offset += temp;
						op->regs[reg_index] = X86R_UNDEFINED;
					}

					temp = 1;
					reg = X86R_UNDEFINED;
				}
				else if (str[pos] == '*') {
					// go to ], + or - to get scale

					// Something to do here?
					// Seems we are just ignoring '*' or assuming it implicitly.
				}
			}
			else if (last_type == TT_WORD) {
				ut32 reg_type = 0;

				// We can't multiply registers
				if (reg != X86R_UNDEFINED)
					op->type = 0;	// Make the result invalid

				// Reset nextpos: parseReg wants to parse from the beginning
				nextpos = pos;
				reg = parseReg (a, str, &nextpos, &reg_type);
				// Still going to need to know the size if not specified
				if (!explicit_size) op->type |= reg_type;
				// Addressing only via general purpose registers
				if (!(reg_type & OT_GPREG))
					op->type = 0;	// Make the result invalid
			}
			else {
				char *p = strchr (str, '+');
				if (p) {
					op->offset_sign = 1;
				}
				else {
					p = strchr (str, '-');
					if (p) {
						op->offset_sign = -1;
					}
				}
				// If there's a scale, we don't want to parse out the
				// scale with the offset (scale + offset) otherwise the scale
				// will be the sum of the two. This splits the numbers
				char *tmp;
				tmp = malloc (strlen (str + pos) + 1);
				strcpy (tmp, str + pos);
				strtok (tmp, "+-");
				st64 read = getnum (a, tmp);
				free (tmp);
				temp *= read;
			}
		}
	} else if (last_type == TT_WORD) {   // register
		nextpos = pos;
		op->reg = parseReg (a, str, &nextpos, &op->type);
	} else {                             // immediate
		// We don't know the size, so let's just set no size flag.
		op->type = OT_CONSTANT;
		op->sign = 1;
		char *p = strchr (str, '-');
		if (p) {
			op->sign = -1;
			str = ++p;
		}
		op->immediate = getnum (a, str);
	}

	return nextpos;
}

static int parseOpcode(RAsm *a, const char *op, Opcode *out) {
	char *args = strchr (op, ' ');
	out->mnemonic = args ? strndup (op, args - op) : strdup (op);
	out->operands[0].type = out->operands[1].type = 0;
	if (args) {
		args++;
	} else {
		return 1;
	}
	parseOperand (a, args, &(out->operands[0]));
	args = strchr (args, ',');
	if (args) {
		args++;
		parseOperand (a, args, &(out->operands[1]));
	}
	return 0;
}

static int getnum(RAsm *a, const char *s) {
	if (!s) return 0;
	if (*s == '$') s++;
	return r_num_math (a->num, s);
}

static int assemble16(RAsm *a, RAsmOp *ao, const char *str) {
	int l = 0;
	ut8 *data = ao->buf;
	if (!strcmp (str, "nop")) {
		data[l++] = 0x90;
	} else if (!strcmp (str, "ret")) {
		data[l++] = 0xc3;
	} else if (!strcmp (str, "int3")) {
		data[l++] = 0xcc;
	} else if (!strncmp (str, "xor al,", 7)) {
		// just to make the test happy, this needs much more work
		const char *comma = strchr (str, ',');
		if (comma) {
			int n = getnum (a, comma + 1);
			data[l++] = 0x34;
			data[l++] = n;
		}
	}
	return l;
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ut8 *data = ao->buf;
	char op[128];
	LookupTable *lt_ptr;

	if (a->bits == 16) {
		return assemble16 (a, ao, str);
	}

	strncpy (op, str, sizeof (op) - 1);
	op[sizeof (op) - 1] = '\0';

	Opcode instr;
	parseOpcode (a, op, &instr);

	for (lt_ptr = oplookup; lt_ptr - oplookup < sizeof (oplookup); ++lt_ptr) {
		if (!strcasecmp (instr.mnemonic, lt_ptr->mnemonic)) {
			if (lt_ptr->opcode > 0) {
				ut8 *ptr = (ut8 *)&lt_ptr->opcode;
				int i = 0;
				for (; i < lt_ptr->size; i++) {
					data[i] = ptr[lt_ptr->size - (i + 1)];
				}
				return lt_ptr->size;
			} else {
				return lt_ptr->opdo (a, data, instr);
			}
		}
	}
	eprintf ("Error: Unknown instruction (%s)\n", instr.mnemonic);
	return -1;
}

RAsmPlugin r_asm_plugin_x86_nz = {
	.name = "x86.nz",
	.desc = "x86 handmade assembler",
	.license = "LGPL3",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble };

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nz,
	.version = R2_VERSION };
#endif
