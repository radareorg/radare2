/* radare - LGPL - Copyright 2015-2018 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>

typedef enum optype_t {
	ARM_NOTYPE = -1,
	ARM_GPR = 1,
	ARM_CONSTANT = 2,
	ARM_FP = 4,
	ARM_MEM_OPT = 8,
	ARM_SHIFT = 16,
	ARM_EXTEND = 32
} OpType;

typedef enum regtype_t {
	ARM_UNDEFINED = -1,
	ARM_REG64 = 1,
	ARM_REG32 = 2,
	ARM_SP = 4,
	ARM_PC = 8,
	ARM_SIMD = 16
} RegType;

typedef enum shifttype_t {
	ARM_LSL = 0,
	ARM_LSR = 1,
	ARM_ASR = 2,
	ARM_ROR = 3,
	ARM_UXTB,
	ARM_UXTH,
	ARM_UXTW,
	ARM_UXTX,
	ARM_SXTB,
	ARM_SXTH,
	ARM_SXTW,
	ARM_SXTX
} ShiftType;

typedef enum logicalop_t {
	ARM_AND = 0,
	ARM_ORR = 1,
	ARM_EOR = 2,
	ARM_ANDS = 3
} LogicalOp;

typedef struct operand_t {
	OpType type;
	union {
		struct {
			int reg;
			RegType reg_type;
			ut16 sp_val;
		};
		struct {
			ut64 immediate;
			bool sign;
			bool preindex;
		};
		struct {
			ut64 shift_amount;
			ShiftType shift;
			bool amount_present;
		};
		struct {
			ut32 mem_option;
		};
	};
} Operand;

#define MAX_OPERANDS 7

typedef struct Opcode_t {
	char *mnemonic;
	ut32 op[3];
	size_t op_len;
	ut8 opcode[3];
	bool writeback;
	int operands_count;
	Operand operands[MAX_OPERANDS];
} ArmOp;

#define check_cond(cond) if (!(cond)) { return data; }

static int get_mem_option(char *token) {
	// values 4, 8, 12, are unused. XXX to adjust
	const char *options[] = {"sy", "st", "ld", "xxx", "ish", "ishst",
	                         "ishld", "xxx", "nsh", "nshst", "nshld",
	                         "xxx", "osh", "oshst", "oshld", NULL};
	int i = 0;
	while (options[i]) {
		if (!r_str_casecmp (token, options[i])) {
			return 15 - i;
		}
		i++;
	}
	return -1;
}

static int countLeadingZeros(ut64 x) {
	int count = 64;
	while (x) {
		x >>= 1;
		--count;
	}
	return count;
}

static int countTrailingZeros(ut64 x) {
	int count = 0;
	while (x && !(x & 1)) {
		count++;
		x >>= 1;
	}
	return count;
}

static int calcNegOffset(int n, int shift) {
	int a = n >> shift;
	if (a == 0) {
		return 0xff;
	}
	// find first set bit then invert it and all
	// bits below it
	int t = 0x400;
	while (!(t & a) && a != 0 && t != 0) {
		t = t >> 1;
	}
	t = t & (t - 1);
	a = a ^ t;
	// If bits below 32 are set
	if (countTrailingZeros(n) > shift) {
		a--;
	}
	return 0xff & (0xff - a);
}

static int countLeadingOnes(ut64 x) {
	return countLeadingZeros (~x);
}

static int countTrailingOnes(ut64 x) {
	return countTrailingZeros (~x);
}

static bool isMask(ut64 value) {
  return value && ((value + 1) & value) == 0;
}

static bool isShiftedMask (ut64 value) {
  return value && isMask ((value - 1) | value);
}

// https://llvm.org/doxygen/AArch64AddressingModes_8h_source.html
static ut32 encodeBitMasksWithSize(ut64 imm, ut32 reg_size) {
	if (imm == 0 || imm == UT64_MAX || (reg_size != 64
		&& (imm >> reg_size != 0 || imm == (~0ULL >> (64 - reg_size))))) {
		return UT32_MAX;
	}
	// get element size
	ut32 size = reg_size;
	do {
		size >>= 1;
		ut64 mask = (1ull << size) - 1;
		if ((imm & mask) != ((imm >> size) & mask)) {
			size <<= 1;
			break;
		}
   } while (size > 2);
	// determine rot to make element be 0^m 1^n
	ut32 cto, i;
	ut64 mask = UT64_MAX >> (64 - size);
	imm &= mask;

	if (isShiftedMask (imm)) {
		i = countTrailingZeros (imm);
		cto = countTrailingOnes (imm >> i);
	} else {
		imm |= ~mask;
		if (!isShiftedMask (~imm)) {
			return UT32_MAX;
		}

		ut32 clo = countLeadingOnes (imm);
		i = 64 - clo;
		cto = clo + countTrailingOnes (imm) - (64 - size);
	}

	// Encode in Immr the number of RORs it would take to get *from* 0^m 1^n
	// to our target value, where I is the number of RORs to go the opposite
	// direction
	ut32 immr = (size - i) & (size - 1);
	// If size has a 1 in the n'th bit, create a value that has zeroes in
	// bits [0, n] and ones above that.
	ut64 nimms = ~(size - 1) << 1;
	// Or the cto value into the low bits, which must be below the Nth bit
	// bit mentioned above.
	nimms |= (cto - 1);
	// Extract and toggle seventh bit to make N field.
	ut32 n = ((nimms >> 6) & 1) ^ 1;
	ut32 encoding = (n << 12) | (immr << 6) | (nimms & 0x3f);
	return encoding;
}

static inline ut32 encode1reg(ArmOp *op) {
	return op->operands[0].reg << 24;
}

static inline ut32 encode2regs(ArmOp *op) {
	return (op->operands[1].reg & 0x7) << 29 | (op->operands[1].reg & 0x18) << 13
		| encode1reg (op);
}

static inline ut32 encodeImm9(ut32 n) {
	return (n & 0x1f0) << 4 | (n & 0xf) << 20;
}

static ut32 mov(ArmOp *op) {
	ut32 k = 0;
	ut32 data = UT32_MAX;
	check_cond (op->operands_count >= 2);
	check_cond (op->operands[0].type == ARM_GPR);
	int bits = (op->operands[0].reg_type & ARM_REG64) ? 64 : 32;
	if (bits == 64) {
		k = 0x0080;
	}
	k |= encode1reg (op);
	if (!strcmp (op->mnemonic, "mov")) {
		check_cond (op->operands_count == 2);
		if (op->operands[1].type == ARM_GPR) {
			check_cond (bits == ((op->operands[1].reg_type & ARM_REG64) ? 64 : 32));
			if (op->operands[0].reg_type & ARM_SP || op->operands[1].reg_type & ARM_SP) { // alias of add
				k |= 0x0011;
				data = k | encode2regs (op);
				return data;
			}
			k |= 0xe003002a; // alias of orr
			data = k | op->operands[1].reg << 8;
			return data;
		}
		check_cond (op->operands[1].type & ARM_CONSTANT);
		ut64 imm = op->operands[1].immediate;
		ut64 imm_inverse = ~imm;
		if (bits == 32) {
			check_cond (imm <= 0xffffffff || imm_inverse <= 0xffffffff);
			imm &= 0xffffffff;
			imm_inverse &= 0xffffffff;
		}
		int shift;
		ut64 mask = 0xffff;
		for (shift = 0; shift < bits; shift += 16, mask <<= 16) {
			if (imm == (imm & mask)) { // movz
				data = k | 0x00008052;
				imm >>= shift;
				data |= (imm & 7) << 29 | (imm & 0x7f8) << 13 | (imm & 0xf800) >> 3;
				data |= shift << 9;
				return data;
			}
		}
		mask = 0xffff;
		for (shift = 0; shift < bits; shift += 16, mask <<= 16) {
			if (imm_inverse == (imm_inverse & mask)) { // movn
				data = k | 0x00008012;
				imm_inverse >>= shift;
				data |= (imm_inverse & 7) << 29 | (imm_inverse & 0x7f8) << 13 | (imm_inverse & 0xf800) >> 3;
				data |= shift << 9;
				return data;
			}
		}
		ut32 bitmask = encodeBitMasksWithSize (op->operands[1].immediate, bits); // orr
		check_cond (bitmask != UT32_MAX);
		data = k | 0xe0030032;
		data |= (bitmask & 0x3f) << 18 | (bitmask & 0x1fc0) << 2;
		return data;
	}
	if (!strcmp (op->mnemonic, "movz")) {
		k |= 0x8052;
	} else if (!strcmp (op->mnemonic, "movk")) {
		k |= 0x8072;
	} else if (!strcmp (op->mnemonic, "movn")) {
		k |= 0x8012;
	} else {
		return data;
	}
	check_cond (op->operands[1].type == ARM_CONSTANT);
	ut64 imm = op->operands[1].immediate;
	check_cond (imm <= 0xffff);
	int shift = 0;
	if (op->operands_count >= 3) {
		check_cond (op->operands_count == 3);
		check_cond (op->operands[2].type == ARM_SHIFT);
		check_cond (op->operands[2].shift == ARM_LSL);
		shift = op->operands[2].shift_amount;
		check_cond (!(shift & 0xf));
		check_cond (shift < bits);
	}
	data = k;
	data |= (imm & 7) << 29; // arg(1)
	data |= (imm & 0x7f8) << 13; // arg(1)
	data |= (imm & 0xf800) >> 3; // arg(1)
	data |= shift << 9; // arg(2)
	return data;
}

static ut32 cb(ArmOp *op) {
	ut32 data = UT32_MAX;
	int k = 0;
    if (!strncmp (op->mnemonic, "cbnz", 4)) {
        if (op->operands[0].reg_type & ARM_REG64) {
            k =  0x000000b5;
        } else if (op->operands[0].reg_type & ARM_REG32) {
            k =  0x00000035;
        } else {
            return UT32_MAX;
        }
    } else if (!strncmp (op->mnemonic, "cbz", 3)) {
        if (op->operands[0].reg_type & ARM_REG64) {
            k =  0x000000b4;
        } else if (op->operands[0].reg_type & ARM_REG32) {
            k =  0x00000034;
        } else {
            return UT32_MAX;
        }
    } else {
        return UT32_MAX;
    }
    //printf ("%s %d, %llu\n", op->mnemonic, op->operands[0].reg, op->operands[1].immediate);
    ut32 imm = op->operands[1].immediate;
	data = k | encode1reg (op) | ((imm & 0x1c) << 27) | ((imm & 0x1fe0) << 11);
    data = data | ((imm & 0x1fe000) >> 5);

	return data;
}


static ut32 cmp(ArmOp *op) {
	ut32 data = UT32_MAX;
	int k = 0;
	if (op->operands[0].reg_type & ARM_REG64 && op->operands[1].reg_type & ARM_REG64) {
		k =  0x1f0000eb;
	} else if (op->operands[0].reg_type & ARM_REG32 && op->operands[1].reg_type & ARM_REG32) {
		if (op->operands[2].shift_amount > 31) {
			return UT32_MAX;
		}
		k =  0x1f00006b;
	} else {
		return UT32_MAX;
	}

	data = k | (op->operands[0].reg & 0x18) << 13 | op->operands[0].reg << 29 | op->operands[1].reg << 8;

	if (op->operands[2].type != ARM_SHIFT) {
		data |= op->operands[2].shift_amount << 18 | op->operands[2].shift << 14;
	}
	return data;
}


static ut32 regsluop(ArmOp *op, int k) {
	ut32 data = UT32_MAX;

	if (op->operands[1].reg_type & ARM_REG32) {
		return data;
	}
	if (op->operands[0].reg_type & ARM_REG32) {
		k -= 0x40;
	}
	if (op->operands[2].type & ARM_GPR) {
		return data;
	}

	int n = op->operands[2].immediate;
	if (n > 0xff || n < -0x100) {
		return data;
	}

	data = k | encode2regs (op);

	if (n < 0) {
		n *= -1;
		data |= ( 0xf & (0xf - (n - 1)) ) << 20;

		if (countTrailingZeros(n) > 3) {
			data |= (0x1f - ((n >> 4) - 1)) << 8;
		} else {
			data |= (0x1f - (n >> 4)) << 8;
		}
	} else {
		data |= (0xf & (n & 63)) << 20;
		if (countTrailingZeros(n) < 4) {
			data |= (n >> 4) << 8;
		} else {
			data |= (0xff & n) << 4;
		}
		data |= (n >> 8) << 8;
	}

	return data;
}

// Register Load/store ops
static ut32 reglsop(ArmOp *op, int k) {
	ut32 data = UT32_MAX;

	if (op->operands[1].reg_type & ARM_REG32) {
		return data;
	}
	if (op->operands[0].reg_type & ARM_REG32) {
		k -= 0x40;
	}
	if (op->operands[2].type & ARM_GPR) {
		k += 0x00682000;
		data = k | encode2regs (op);
		data |= op->operands[2].reg << 8;
	} else {
		int n = op->operands[2].immediate;
		if (n > 0x100 || n < -0x100) {
			return UT32_MAX;
		}

		if (n == 0 || (n > 0 && countTrailingZeros(n) >= 4)) {
			k ++;
		}
		data = k | encode2regs (op);

		if (n < 0) {
			n *= -1;
			data |= ( 0xf & (0xf - (n - 1)) ) << 20;
			if (countTrailingZeros(n) > 3) {
				data |= (0x1f - ((n >> 4) - 1)) << 8;
			} else {
				data |= (0x1f - (n >> 4)) << 8;
			}
		} else {
			if (op->operands[0].reg_type & ARM_REG32) {
				if (countTrailingZeros(n) < 2) {
					data |= (0xf & (n & 63)) << 20;
					data |= (n >> 4) << 8;
				} else {
						data++;
						data |= (0xff & n) << 16;
				}
				data |= (n >> 8) << 8;
			} else {
				data |= (0xf & (n & 63)) << 20;
				if (countTrailingZeros(n) < 4) {
					data |= (n >> 4) << 8;
				} else {
					data |= (0xff & n) << 15;
				}
				data |= (n >> 8) << 23;
			}
		}
	}
	return data;
}

// load/store ops
static ut32 lsop(ArmOp *op, int k, ut64 addr) {
	ut32 data = UT32_MAX;
	int op_count = op->operands_count;
	if (k == 0x00000098) { // ldrsw
		if (op->operands[0].type & ARM_GPR
			&& op->operands[1].type & ARM_CONSTANT) { // (literal)
			st64 offset = op->operands[1].immediate - addr;
			check_cond (op->operands[0].reg_type & ARM_REG64);
			check_cond (!(offset & 0x3));
			check_cond (-0x100000 <= offset && offset < 0x100000);
			offset >>= 2;
			data = k | (offset & 0x7f800) >> 3 | (offset & 0x7f8) << 13
				| (offset & 0x7) << 29 | encode1reg (op);
			return data;
		}
		k = 0x000080b8;
	}
	check_cond (op->operands[0].type == ARM_GPR);
	check_cond (op->operands[1].type == ARM_GPR);
	check_cond (op->operands[1].reg_type & ARM_REG64);
	k |= encode2regs (op);
	if (!strcmp (op->mnemonic, "ldrb") || !strcmp (op->mnemonic, "ldrh")
		|| !strcmp (op->mnemonic, "strb") || !strcmp (op->mnemonic, "strh")) {
		check_cond (op->operands[0].reg_type & ARM_REG32);
	} else if (!strcmp (op->mnemonic, "ldrsw")) {
		check_cond (op->operands[0].reg_type & ARM_REG64);
	} else { // ldrsh, ldrsb
		if (op->operands[0].reg_type & ARM_REG32) {
			k |= 0x00004000;
		}
	}
	char width = op->mnemonic[strlen (op->mnemonic) - 1];
	if (op->operands[2].type & ARM_GPR) {
		k |= 0x00482000;
		if (op->operands[3].type == ARM_EXTEND) {
			switch (op->operands[3].shift) {
			case ARM_SXTW:
				k |= 0x00800000;
			// fall through
			case ARM_UXTW:
				check_cond (op->operands[2].reg_type & ARM_REG32);
				break;
			case ARM_SXTX:
				k |= 0x00a00000;
				check_cond (op->operands[2].reg_type & ARM_REG64);
				break;
			default:
				return data;
			}
		} else if (op->operands[3].type == ARM_SHIFT) {
			check_cond (op->operands[3].shift == ARM_LSL);
			check_cond (op->operands[2].reg_type & ARM_REG64);
			k |= 0x00200000;
		}
		if (op->operands[3].type == ARM_EXTEND || op->operands[3].type == ARM_SHIFT) {
			if (width == 'b') {
				check_cond (op->operands[3].shift_amount == 0);
				if (op->operands[3].amount_present) {
					k |= 0x00100000;
				}
			} else if (width == 'h') {
				switch (op->operands[3].shift_amount) {
				case 1:
					k |= 0x00100000;
				// fall through
				case 0:
					break;
				default:
					return data;
				}
			} else { // w
				switch (op->operands[3].shift_amount) {
				case 2:
					k |= 0x00100000;
				// fall through
				case 0:
					break;
				default:
					return data;
				}
			}
		} else { // lsl 0 by default
			check_cond (op->operands[2].reg_type & ARM_REG64);
			k |= 0x00200000;
		}
		data = k | op->operands[2].reg << 8;
		return data;
	}
	check_cond (op_count == 2 || op->operands[2].type == ARM_CONSTANT);
	check_cond (!op->writeback || op->operands[2].preindex);
	int n = op_count == 2 ? 0 : op->operands[2].immediate;
	if (!op->writeback && (op_count == 2 || op->operands[2].preindex)) { // unsigned offset
		check_cond (n >= 0);
		if (width == 'b') {
			check_cond (n <= 0xfff);
		} else if (width == 'h') {
			check_cond (n <= 0x1ffe && !(n & 1))
			n >>= 1;
		} else { // w
			check_cond (n <= 0x3ffc && !(n & 3));
			n >>= 2;
		}
		data = k | (n & 0x3f) << 18 | (n & 0xfc0) << 2 | 1;
		return data;
	}
	check_cond (-0x100 <= n && n < 0x100)
	if (op->operands[2].preindex) {
		k |= 0x00080000;
	}
	data = k | encodeImm9 (n) | 0x00040000;
	return data;
}

static ut32 branch(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;
	ut64 n = 0;
	if (op->operands[0].type & ARM_CONSTANT) {
		n = op->operands[0].immediate;
		if (!(n & 0x3)) {
			if (n >= addr) {
				n -= addr;
			} else {
				n -= addr;
				n = n & 0xfffffff;
				k |= 3;
			}
			n = n >> 2;
			int t = (n & 0xff000000) >> 24;
			int h = (n & 0xff0000) >> 16;
			int m = (n & 0xff00) >> 8;
			n &= 0xff;
			data = k;
			data |= n << 24;
			data |= m << 16;
			data |= h << 8;
			data |= t;
		}
	} else {
		n = op->operands[0].reg;
		if (n >= 31) {
			return -1;
		}
		n = n << 5;
		int h = n >> 8;
		n &= 0xff;
		data = k;
		data |= n << 24;
		data |= h << 16;
	}
	return data;
}

static ut32 bdot(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;
	int n = 0;
	int a = 0;
	n = op->operands[0].immediate;
	// I am sure there's a logical way to do negative offsets,
	// but I was unable to find any sensible docs so I did my best
	if (!(n & 0x3 || n > 0x7ffffff)) {
		n -= addr;
		data = k;
		if (n < 0) {
			n *= -1;
			a = (n << 3) - 1;
			data |= (0xff - a) << 24;

			a = calcNegOffset(n, 5);
			data |= a << 16;

			a = calcNegOffset(n, 13);
			data |= a << 8;
		} else {
			data |= (n & 31) << 27;
			data |= (0xff & (n >> 5)) << 16;
			data |= (0xff & (n >> 13)) << 8;
		}
	}

	return data;
}

static ut32 mem_barrier(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;
	data = k;
	if (!strncmp (op->mnemonic, "isb", 3)) {
		if (op->operands[0].mem_option == 15 || op->operands[0].type == ARM_NOTYPE) {
			return data;
		} else {
			return UT32_MAX;
		}
	}
	if (op->operands[0].type == ARM_MEM_OPT) {
		data |= op->operands[0].mem_option << 16;
	} else if (op->operands_count == 1 && op->operands[0].type == ARM_CONSTANT) {
		data |= (op->operands[0].immediate << 16);
	}
	return data;
}

#include "armass64_const.h"

static ut32 msr(ArmOp *op, int w) {
	ut32 data = UT32_MAX;
	ut32 seq_data = UT32_MAX;
	int is_immediate = 0;
	int i;
	ut32 r, b;
	/* handle swapped args */
	if (w) {
		if (op->operands[1].reg_type != (ARM_REG64 | ARM_SP)) {
			if (op->operands[1].type == ARM_CONSTANT) {
				for (i = 0; msr_const[i].name; i++) {
					if (op->operands[1].immediate == msr_const[i].val) {
						op->operands[1].sp_val = msr_const[i].val;
						op->operands[1].reg = op->operands[1].immediate;
						break;
					}
				}
			} else {
				return data;
			}
		}
		r = op->operands[0].reg;
		b = op->operands[1].sp_val;
	} else {
		if (op->operands[0].reg_type != (ARM_REG64 | ARM_SP)) {
			if (op->operands[0].type == ARM_CONSTANT) {
				for (i = 0; msr_const[i].name; i++) {
					if (op->operands[0].immediate == msr_const[i].val) {
						op->operands[0].sp_val = msr_const[i].val;
						op->operands[0].reg = op->operands[0].immediate;
						break;
					}
				}
			} else {
				return data;
			}
		}
		r = op->operands[1].reg;
		if ( op->operands[1].sp_val == 0xfffe ) {
			is_immediate = 1;
			r = op->operands[1].immediate;
		}
		b = op->operands[0].sp_val;
	}
	data = 0x00000000;

	if (is_immediate) {
		//only msr has immediate mode
		data = 0xd500401f;
		if (b == 0xc210) { //op0 is SPSel
			b = 0x05; //set to immediate mode encoding
		}

		data |= (b & 0xf0) << 12; //op1
		data |= (b & 0x0f) << 5; //op2
		data |= (r & 0xf) << 8; //CRm(#imm)

	} else {
		if (w) {
			/* mrs */
			data |= 0xd5200000;
		} else {
			data |= 0xd5000000;
		}
		data |= b << 5;
		data |= r;
	}
	seq_data = 0x00000000;
	seq_data |= (data & 0xff) << 8*3;
	seq_data |= (data & 0xff00) << 8*1;
	seq_data |= (data & 0xff0000) >> 8*1;
	seq_data |= (data & 0xff000000) >> 8*3;
/*
if (op->operands[1].reg_type == ARM_REG64) {
		data |= op->operands[1].reg << 24;
	}
*/
	return seq_data;
}

static ut32 logical(ArmOp *op, bool invert, LogicalOp opc) {
	ut32 data = UT32_MAX;
	RegType reg_type = op->operands[0].reg_type;

	// Reg types need to match
	if (!(reg_type == op->operands[1].reg_type)) {
		return data;
	}

	OpType op2_type = op->operands[2].type;
	if (op2_type == ARM_CONSTANT) {
		if (invert) {
			/* there aren't inverted immediates in arm64 */
			return UT32_MAX;
		}
		if (reg_type & ARM_REG64) {
			data = 0x92000000;
		} else if (reg_type & ARM_REG32) {
			data = 0x12000000;
		} else {
			return UT32_MAX;
		}

		bool is64bit = reg_type & ARM_REG64;

		data |= op->operands[0].reg;
		data |= op->operands[1].reg << 5;
		data |= (opc & 3) << 29;

		ut32 imm_orig = op->operands[2].immediate;
		ut32 imm = encodeBitMasksWithSize (invert? ~imm_orig: imm_orig, is64bit? 64: 32);
		if (imm == UT32_MAX) {
			return UT32_MAX;
		}
		data |= (imm & 0x1fff) << 10;
	} else if (op2_type == ARM_GPR) {
		if (reg_type & ARM_REG64) {
			data = 0x8a000000;
		} else if (reg_type & ARM_REG32) {
			data = 0x0a000000;
		} else {
			return UT32_MAX;
		}

		data |= op->operands[0].reg;
		data |= op->operands[1].reg << 5;
		data |= op->operands[2].reg << 16;
		data |= (opc & 3) << 29;

		if (op->operands_count == 4) {
			Operand shift_op = op->operands[3];
			if (shift_op.type == ARM_SHIFT) {
				data |= (shift_op.shift_amount & 0x3f) << 10;
				data |= (shift_op.shift & 0x3) << 22;
			}
		}

		if (invert) {
			data |= 1 << 21;
		}
	} else {
		return UT32_MAX;
	}

	return r_read_be32 (&data);
}

static ut32 adrp(ArmOp *op, ut64 addr, ut32 k) { //, int reg, ut64 dst) {
	ut64 at = 0LL;
	ut32 data = k;
	if (op->operands[0].type == ARM_GPR) {
		data |= encode1reg (op);
	} else {
		eprintf ("Usage: adrp x0, addr\n");
		return UT32_MAX;
	}
	if (op->operands[1].type == ARM_CONSTANT) {
		// XXX what about negative values?
		at = op->operands[1].immediate - addr;
		at /= 4;
	} else {
		eprintf ("Usage: adrp, x0, addr\n");
		return UT32_MAX;
	}
	ut8 b0 = at;
	ut8 b1 = (at >> 3) & 0xff;

#if 0
	ut8 b2 = (at >> (8 + 7)) & 0xff;
	data += b0 << 29;
	data += b1 << 16;
	data += b2 << 24;
#endif
	data += b0 << 16;
	data += b1 << 8;
	return data;
}

static ut32 adr(ArmOp *op, int addr) {
	ut32 data = UT32_MAX;
	ut64 at = 0LL;

	if (op->operands[1].type & ARM_CONSTANT) {
		// XXX what about negative values?
		at = op->operands[1].immediate - addr;
		at /= 4;
	}
	data = 0x00000030;
	data |= encode1reg (op);
	ut8 b0 = at;
	ut8 b1 = (at >> 3) & 0xff;
	ut8 b2 = (at >> (8 + 7)) & 0xff;
	data += b0 << 29;
	data += b1 << 16;
	data += b2 << 24;
	return data;
}

static ut32 stp(ArmOp *op, int k) {
	ut32 data = UT32_MAX;

	if (op->operands[3].immediate & 0x7) {
		return data;
	}
	if (k == 0x000040a9 && (op->operands[0].reg == op->operands[1].reg)) {
		return data;
	}

	data = k;
	data |= encode2regs (op);
	data += (op->operands[3].immediate & 0x8) << 20;
	data += (op->operands[3].immediate >> 4) << 8;
	return data;
}

static ut32 exception(ArmOp *op, ut32 k) {
	ut32 data = UT32_MAX;

	if (op->operands[0].type == ARM_CONSTANT) {
		int n = op->operands[0].immediate;
		data = k;
		data += (((n / 8) & 0xff) << 16);
		data += n << 29;//((n >> 8) << 8);
	}
	return data;
}

static ut32 arithmetic(ArmOp *op, int k) {
	ut32 data = UT32_MAX;
	if (op->operands_count < 3) {
		return data;
	}

	if (!(op->operands[0].type & ARM_GPR &&
	      op->operands[1].type & ARM_GPR)) {
		return data;
	}
	if (op->operands[2].type & ARM_GPR) {
		k -= 6;
	}

	data = k;
	data += encode1reg (op);
	data += (op->operands[1].reg & 7) << (24 + 5);
	data += (op->operands[1].reg >> 3) << 16;
	if (op->operands[2].type & ARM_GPR) {
		data += op->operands[2].reg << 8;
	} else {
		data += (op->operands[2].reg & 0x3f) << 18;
		data += (op->operands[2].reg >> 6) << 8;
	}
	return data;
}

static ut32 neg(ArmOp *op) {
	if (op->operands_count < 2) {
		return -1;
	}
	op->operands_count++;
	op->operands[2] = op->operands[1];
	op->operands[1].reg = 31; // xzr

	return arithmetic (op, 0xd1); // sub reg0, xzr, reg1
}

static ut32 bitfield(ArmOp *op, int k) {
	ut32 data = UT32_MAX;
	check_cond (op->operands_count == 4);
	check_cond (op->operands[0].type == ARM_GPR);
	check_cond (op->operands[1].type == ARM_GPR);
	check_cond (op->operands[0].reg_type == op->operands[1].reg_type);
	check_cond (op->operands[2].type == ARM_CONSTANT);
	check_cond (op->operands[3].type == ARM_CONSTANT);
	int bits = (op->operands[0].reg_type & ARM_REG64) ? 64 : 32;
	// unalias
	if (!strcmp (op->mnemonic, "sbfx") || !strcmp (op->mnemonic, "ubfx")) {
		op->operands[3].immediate += op->operands[2].immediate - 1;
	} else if (!strcmp (op->mnemonic, "sbfiz") || !strcmp (op->mnemonic, "ubfiz")) {
		check_cond (op->operands[2].immediate < bits);
		int temp = bits - op->operands[2].immediate;
		check_cond (op->operands[3].immediate <= temp);
		op->operands[2].immediate = temp & (bits - 1);
		op->operands[3].immediate--;
	}
	check_cond (op->operands[2].immediate < bits);
	check_cond (op->operands[3].immediate < bits);
	if (bits == 64) {
		k |= 0x00004080;
	}
	k |= op->operands[2].immediate << 8 | op->operands[3].immediate << 18;
	data = k | encode2regs (op);
	return data;
}

static bool parseOperands(char* str, ArmOp *op) {
	char *t = strdup (str);
	int operand = 0;
	char *token = t;
	char *x;
	int imm_count = 0;
	int mem_opt = 0;
	int msr_op_index = 0;
	size_t index_bound = strcspn (t, "]");
	if (!token) {
		return false;
	}

	while (token) {
		char *next = strchr (token, ',');
		if (next) {
			// Change the ',' in token to null byte
			// essentialy split the token by commas
			*next++ = '\0';
		}
		while (token[0] == ' ') {
			token++;
		}
		if (operand >= MAX_OPERANDS) {
			eprintf ("Too many operands\n");
			return false;
		}
		op->operands[operand].type = ARM_NOTYPE;
		op->operands[operand].reg_type = ARM_UNDEFINED;

		//parse MSR (immediate) operand 1
		if (strcmp (op->mnemonic, "msr") == 0 && operand == 1) {

			//operand 1 must be a immediate
			if ( token[0] == '#' || (token[0] >= '0' && token[0] <= '9')) {
				//immediate operand found.
				op->operands[operand].sp_val = 0xfffe; //not regiter, but a immediate
				op->operands[operand].immediate = r_num_math (NULL, token[0]=='#'?token+1:token);
				operand ++;
				token = next;
				continue;
			}
		}

		//parse system registers
		if ((strcmp (op->mnemonic, "mrs") == 0 && operand == 1) || (strcmp (op->mnemonic, "msr") == 0 && operand == 0)) {
			for(msr_op_index = 0; msr_const[msr_op_index].name; msr_op_index++) {
				if (strcasecmp (token, msr_const[msr_op_index].name) == 0) {
					op->operands_count ++;
					op->operands[operand].type = ARM_CONSTANT;
					op->operands[operand].immediate = msr_const[msr_op_index].val;
					imm_count++;
					break;
				}
			}
			if (msr_const[msr_op_index].name) {
				operand ++;
				token = next;
				continue;
			}
		}

		while (token[0] == ' ' || token[0] == '[' || token[0] == ']') {
			token ++;
		}

		if (!strncmp (token, "lsl", 3)) {
			op->operands[operand].type = ARM_SHIFT;
			op->operands[operand].shift = ARM_LSL;
		} else if (!strncmp (token, "lsr", 3)) {
			op->operands[operand].type = ARM_SHIFT;
			op->operands[operand].shift = ARM_LSR;
		} else if (!strncmp (token, "asr", 3)) {
			op->operands[operand].type = ARM_SHIFT;
			op->operands[operand].shift = ARM_ASR;
		} else if (!strncmp (token, "ror", 3)) {
			op->operands[operand].type = ARM_SHIFT;
			op->operands[operand].shift = ARM_ROR;
		} else if (!strncmp (token, "uxtb", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_UXTB;
		} else if (!strncmp (token, "uxth", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_UXTH;
		} else if (!strncmp (token, "uxtw", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_UXTW;
		} else if (!strncmp (token, "uxtx", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_UXTX;
		} else if (!strncmp (token, "sxtb", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_SXTB;
		} else if (!strncmp (token, "sxth", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_SXTH;
		} else if (!strncmp (token, "sxtw", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_SXTW;
		} else if (!strncmp (token, "sxtx", 4)) {
			op->operands[operand].type = ARM_EXTEND;
			op->operands[operand].shift = ARM_SXTX;
		}
		if (op->operands[operand].type == ARM_SHIFT) {
			op->operands_count ++;
			token += 3;
			while (*token && *token == ' ') {
				token++;
			}
			if (*token == '#') {
				token++;
			}
			if (!*token || !isdigit((unsigned char)*token)) {
				return false;
			}
			op->operands[operand].shift_amount = r_num_math (NULL, token);
			op->operands[operand].amount_present = true;
			if (op->operands[operand].shift_amount > 63) {
				free (t);
				return false;
			}
			operand ++;
			token = next;
			continue;
		}
		if (op->operands[operand].type == ARM_EXTEND) {
			op->operands_count++;
			token += 4;
			while (*token && *token == ' ') {
				token++;
			}
			bool present = false;
			if (*token == '#') {
				present = true;
				++token;
			}
			if (!*token || !isdigit((unsigned char)*token)) {
				if (present) {
					return false;
				}
				op->operands[operand].shift_amount = 0;
				op->operands[operand].amount_present = false;
			} else {
				op->operands[operand].shift_amount = r_num_math (NULL, token);
				op->operands[operand].amount_present = true;
			}
			operand++;
			token = next;
			continue;
		}

		switch (token[0]) {
		case 'x':
			x = strchr (token, ',');
			if (x) {
				x[0] = '\0';
			}
			op->operands_count ++;
			op->operands[operand].type = ARM_GPR;
			op->operands[operand].reg_type = ARM_REG64;

			if (!strncmp(token + 1, "zr", 2)) {
				// XZR
				op->operands[operand].reg = 31;
			} else {
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			}

			if (op->operands[operand].reg > 31) {
				free (t);
				return false;
			}
			break;
		case 'w':
			op->operands_count ++;
			op->operands[operand].type = ARM_GPR;
			op->operands[operand].reg_type = ARM_REG32;

			if (!strncmp(token + 1, "zr", 2)) {
				// WZR
				op->operands[operand].reg = 31;
			} else if (!strncmp(token + 1, "sp", 2)) {
				// WSP
				op->operands[operand].reg = 31;
				op->operands[operand].reg_type |= ARM_SP;
			} else {
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			}

			if (op->operands[operand].reg > 31) {
				free (t);
				return false;
			}
			break;
		case 'v':
			op->operands_count ++;
			op->operands[operand].type = ARM_FP;
			op->operands[operand].reg = r_num_math (NULL, token + 1);
			break;
		case 's':
		case 'S':
			if (token[1] == 'P' || token [1] == 'p') {
				int i;
				for (i = 0; msr_const[i].name; i++) {
					if (!r_str_ncasecmp (token, msr_const[i].name, strlen (msr_const[i].name))) {
						op->operands[operand].sp_val = msr_const[i].val;
						break;
					}
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_GPR;
				op->operands[operand].reg_type = ARM_SP | ARM_REG64;
				op->operands[operand].reg = 31;
				break;
			}
			mem_opt = get_mem_option (token);
			if (mem_opt != -1) {
				op->operands_count ++;
				op->operands[operand].type = ARM_MEM_OPT;
				op->operands[operand].mem_option = mem_opt;
			}
			break;
		case 'L':
		case 'l':
		case 'I':
		case 'i':
		case 'N':
		case 'n':
		case 'O':
		case 'o':
		case 'p':
		case 'P':
			mem_opt = get_mem_option (token);
			if (mem_opt != -1) {
				op->operands_count ++;
				op->operands[operand].type = ARM_MEM_OPT;
				op->operands[operand].mem_option = mem_opt;
			}
			break;
		case '#':
			if (token[1] == '-') {
				op->operands[operand].sign = -1;
			}
			op->operands_count ++;
			op->operands[operand].type = ARM_CONSTANT;
			op->operands[operand].immediate = r_num_math (NULL, token + 1);
			op->operands[operand].preindex = token - t < index_bound;
			imm_count++;
			break;
		case '-':
			op->operands[operand].sign = -1;
			// falthru
		default:
			op->operands_count ++;
			op->operands[operand].type = ARM_CONSTANT;
			op->operands[operand].immediate = r_num_math (NULL, token);
			op->operands[operand].preindex = token - t < index_bound;
			imm_count++;
			break;
		}
		token = next;

		operand ++;
		if (operand > MAX_OPERANDS) {
			free (t);
			return false;
		}
	}
	free (t);
	return true;
}

static bool parseOpcode(const char *str, ArmOp *op) {
	char *in = strdup (str);
	char *space = strchr (in, ' ');
	if (!space) {
		op->operands[0].type = ARM_NOTYPE;
		op->mnemonic = in;
 		return true;
	}
	space[0] = '\0';
	op->mnemonic = in;
	space ++;
	op->writeback = strstr (space, "]!") != NULL;
	return parseOperands (space, op);
}

static bool handlePAC(ut32 *op, const char *str) {
	if (!strcmp (str, "autiasp")) {
		*op = 0xbf2303d5;
		return true;
	}
	if (!strcmp (str, "autiaz")) {
		*op = 0x9f2303d5;
		return true;
	}
	if (!strcmp (str, "autibsp")) {
		*op = 0xff2303d5;
		return true;
	}
	if (!strcmp (str, "autibz")) {
		*op = 0xdf2303d5;
		return true;
	}
	if (!strcmp (str, "paciaz")) {
		*op = 0x1f2303d5;
		return true;
	}
	if (!strcmp (str, "pacibz")) {
		*op = 0x5f2303d5;
		return true;
	}
	if (!strcmp (str, "paciasp")) {
		*op = 0x3f2303d5;
		return true;
	}
	if (!strcmp (str, "pacibsp")) {
		*op = 0x7f2303d5;
		return true;
	}
	if (!strcmp (str, "retab")) {
		*op = 0xff0f5fd6;
		return true;
	}
	return false;
}

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	ArmOp ops = {0};
	if (!parseOpcode (str, &ops)) {
		free (ops.mnemonic);
		return false;
	}
	/* TODO: write tests for this and move out the regsize logic into the mov */
	if (!strncmp (str, "mov", 3)) {
		*op = mov (&ops);
	} else if (!strncmp (str, "cb", 2)) {
		*op = cb (&ops);
	} else if (!strncmp (str, "cmp", 3)) {
		*op = cmp (&ops);
	} else if (!strncmp (str, "ldrb", 4)) {
		*op = lsop (&ops, 0x00004038, -1);
	} else if (!strncmp (str, "ldrh", 4)) {
		*op = lsop (&ops, 0x00004078, -1);
	} else if (!strncmp (str, "ldrsh", 5)) {
		*op = lsop (&ops, 0x00008078, -1);
	} else if (!strncmp (str, "ldrsw", 5)) {
		*op = lsop (&ops, 0x00000098, addr);
	} else if (!strncmp (str, "ldrsb", 5)) {
		*op = lsop (&ops, 0x00008038, -1);
	} else if (!strncmp (str, "strb", 4)) {
		*op = lsop (&ops, 0x00000038, -1);
	} else if (!strncmp (str, "strh", 4)) {
		*op = lsop (&ops, 0x00000078, -1);
	} else if (!strncmp (str, "ldr", 3)) {
		*op = reglsop (&ops, 0x000040f8);
	} else if (!strncmp (str, "stur", 4)) {
		*op = regsluop (&ops, 0x000000f8);
	} else if (!strncmp (str, "ldur", 4)) {
		*op = regsluop (&ops, 0x000040f8);
	} else if (!strncmp (str, "str", 3)) {
		*op = reglsop (&ops, 0x000000f8);
	} else if (!strncmp (str, "stp", 3)) {
		*op = stp (&ops, 0x000000a9);
	} else if (!strncmp (str, "ldp", 3)) {
		*op = stp (&ops, 0x000040a9);
	} else if (!strncmp (str, "sub", 3)) { // w
		*op = arithmetic (&ops, 0xd1);
	} else if (!strncmp (str, "add x", 5)) {
		*op = arithmetic (&ops, 0x91);
	} else if (!strncmp (str, "add w", 5)) {
		*op = arithmetic (&ops, 0x11);
	} else if (!strncmp (str, "adr x", 5)) { // w
		*op = adr (&ops, addr);
	} else if (!strncmp (str, "adrp x", 6)) {
		*op = adrp (&ops, addr, 0x00000090);
	} else if (!strncmp (str, "neg", 3)) {
		*op = neg (&ops);
	} else if (!strcmp (str, "isb")) {
		*op = 0xdf3f03d5;
	} else if (handlePAC (op, str)) { // PAC
		free (ops.mnemonic);
		return true;
	} else if (!strcmp (str, "nop")) {
		*op = 0x1f2003d5;
	} else if (!strcmp (str, "ret")) {
		*op = 0xc0035fd6;
	} else if (!strncmp (str, "msr ", 4)) {
		*op = msr (&ops, 0);
	} else if (!strncmp (str, "mrs ", 4)) {
		*op = msr (&ops, 1);
	} else if (!strncmp (str, "ands ", 5)) {
		*op = logical (&ops, false, ARM_ANDS);
	} else if (!strncmp (str, "and ", 4)) {
		*op = logical (&ops, false, ARM_AND);
	} else if (!strncmp (str, "bics ", 5)) {
		*op = logical (&ops, true, ARM_ANDS);
	} else if (!strncmp (str, "bic ", 4)) {
		*op = logical (&ops, true, ARM_AND);
	} else if (!strncmp (str, "eon ", 4)) {
		*op = logical (&ops, true, ARM_EOR);
	} else if (!strncmp (str, "eor ", 4)) {
		*op = logical (&ops, false, ARM_EOR);
	} else if (!strncmp (str, "orn ", 4)) {
		*op = logical (&ops, true, ARM_ORR);
	} else if (!strncmp (str, "orr ", 4)) {
		*op = logical (&ops, false, ARM_ORR);
	} else if (!strncmp (str, "svc ", 4)) { // system level exception
		*op = exception (&ops, 0x010000d4);
	} else if (!strncmp (str, "hvc ", 4)) { // hypervisor level exception
		*op = exception (&ops, 0x020000d4);
	} else if (!strncmp (str, "smc ", 4)) { // secure monitor exception
		*op = exception (&ops, 0x030000d4);
	} else if (!strncmp (str, "brk ", 4)) { // breakpoint
		*op = exception (&ops, 0x000020d4);
	} else if (!strncmp (str, "hlt ", 4)) { // halt
		*op = exception (&ops, 0x000040d4);
	} else if (!strncmp (str, "b ", 2)) {
		*op = branch (&ops, addr, 0x14);
	} else if (!strncmp (str, "b.eq ", 5)) {
		*op = bdot (&ops, addr, 0x00000054);
	} else if (!strncmp (str, "b.hs ", 5)) {
		*op = bdot (&ops, addr, 0x02000054);
	} else if (!strncmp (str, "bl ", 3)) {
		*op = branch (&ops, addr, 0x94);
	} else if (!strncmp (str, "br x", 4)) {
		*op = branch (&ops, addr, 0x1fd6);
	} else if (!strncmp (str, "blr x", 5)) {
		*op = branch (&ops, addr, 0x3fd6);
	} else if (!strncmp (str, "dmb ", 4)) {
		*op = mem_barrier (&ops, addr, 0xbf3003d5);
	} else if (!strncmp (str, "dsb ", 4)) {
		*op = mem_barrier (&ops, addr, 0x9f3003d5);
	} else if (!strncmp (str, "isb", 3)) {
		*op = mem_barrier (&ops, addr, 0xdf3f03d5);
	} else if (!strncmp (str, "sbfiz ", 6) || !strncmp (str, "sbfm ", 5)
		|| !strncmp (str, "sbfx ", 5)) {
		*op = bitfield (&ops, 0x00000013);
	} else if (!strncmp (str, "ubfiz ", 6) || !strncmp (str, "ubfm ", 5)
		|| !strncmp (str, "ubfx ", 5)) {
		*op = bitfield (&ops, 0x00000053);
	}
	free (ops.mnemonic);
	return *op != UT32_MAX;
}
