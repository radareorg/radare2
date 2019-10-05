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
	ARM_MEM_OPT = 8
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
	ARM_NO_SHIFT = -1,
	ARM_LSL = 0,
	ARM_LSR = 1,
	ARM_ASR = 2
} ShiftType;

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
			int sign;
		};
		struct {
			ut64 shift_amount;
			ShiftType shift;
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
	int operands_count;
	Operand operands[MAX_OPERANDS];
} ArmOp;

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

static int countLeadingZeros(ut32 x) {
	int count = 0;
	while (x) {
		x >>= 1;
		--count;
	}
	return count;
}

static int countTrailingZeros(ut32 x) {
	int count = 0;
	while (x > 0) {
		if ((x & 1) == 1) {
			break;
		} else {
			count ++;
			x = x >> 1;
		}
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

static int countLeadingOnes(ut32 x) {
	return countLeadingZeros (~x);
}

static int countTrailingOnes(ut32 x) {
	return countTrailingZeros (~x);
}

static bool isMask(ut32 value) {
  return value && ((value + 1) & value) == 0;
}

static bool isShiftedMask (ut32 value) {
  return value && isMask ((value - 1) | value);
}

static ut32 decodeBitMasks(ut32 imm) {
	// get element size
	int size = 32;
	// determine rot to make element be 0^m 1^n
	ut32 cto, i;
	ut32 mask = ((ut64) - 1LL) >> (64 - size);

	if (isShiftedMask (imm)) {
		i = countTrailingZeros (imm);
		cto = countTrailingOnes (imm >> i);
	} else {
		imm |= ~mask;
		if (!isShiftedMask (imm)) {
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
	ut64 encoding = (n << 12) | (immr << 6) | (nimms & 0x3f);
	return encoding;
}

static ut32 mov(ArmOp *op) {
	int k = 0;
	ut32 data = UT32_MAX;
	if (!strncmp (op->mnemonic, "movz", 4)) {
		if (op->operands[0].reg_type & ARM_REG64) {
			k = 0x80d2;
		} else if (op->operands[0].reg_type & ARM_REG32) {
			k = 0x8052;
		}
	} else if (!strncmp (op->mnemonic, "movk", 4)) {
		if (op->operands[0].reg_type & ARM_REG32) {
			k = 0x8072;
		} else if (op->operands[0].reg_type & ARM_REG64) {
			k = 0x80f2;
		}
	} else if (!strncmp (op->mnemonic, "movn", 4)) {
		if (op->operands[0].reg_type & ARM_REG32) {
			k = 0x8012;
		} else if (op->operands[0].reg_type & ARM_REG64) {
			k = 0x8092;
		}
	} else if (!strncmp (op->mnemonic, "mov", 3)) {
		//printf ("%d - %d [%d]\n", op->operands[0].type, op->operands[1].type, ARM_GPR);
		if (op->operands[0].type & ARM_GPR) {
			if (op->operands[1].type & ARM_GPR) {
				if (op->operands[1].reg_type & ARM_REG64) {
					k = 0xe00300aa;
				} else {
					k = 0xe003002a;
				}
				data = k | op->operands[1].reg << 8;
			} else if (op->operands[1].type & ARM_CONSTANT) {
				k = 0x80d2;
				data = k | op->operands[1].immediate << 29;
			}
			data |=  op->operands[0].reg << 24;
		}
		return data;
	}

	data = k;
	data |= (op->operands[0].reg << 24); // arg(0)
	data |= ((op->operands[1].immediate & 7) << 29); // arg(1)
	data |= (((op->operands[1].immediate >> 3) & 0xff) << 16); // arg(1)
	data |= ((op->operands[1].immediate >> 10) << 7); // arg(1)
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

	if (op->operands[2].shift != ARM_NO_SHIFT) {
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

	data = k | op->operands[0].reg << 24 | op->operands[1].reg << 29 | (op->operands[1].reg & 56) << 13;

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
		data = k | op->operands[0].reg << 24 | op->operands[1].reg << 29 | (op->operands[1].reg & 56) << 13;
		data |= op->operands[2].reg << 8;
	} else {
		int n = op->operands[2].immediate;
		if (n > 0x100 || n < -0x100) {
			return UT32_MAX;
		}

		if (n == 0 || (n > 0 && countTrailingZeros(n) >= 4)) {
			k ++;
		}
		data = k | op->operands[0].reg << 24 | op->operands[1].reg << 29 | (op->operands[1].reg & 56) << 13;

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

// Byte load/store ops
static ut32 bytelsop(ArmOp *op, int k) {
	ut32 data = UT32_MAX;

	if (op->operands[0].reg_type & ARM_REG64) {
		return data;
	}
	if (op->operands[1].reg_type & ARM_REG32) {
		return data;
	}
	if (op->operands[2].type & ARM_GPR) {
		if ((k & 0xf) != 8) {
			k--;
		}
		k += 0x00682000;
		data = k | op->operands[0].reg << 24 | op->operands[1].reg << 29 | (op->operands[1].reg & 56) << 13;
		data |= op->operands[2].reg << 8;
		return data;
	}

	int n = op->operands[2].immediate;
	if (n > 0xfff || n < -0x100) {
		return UT32_MAX;
	}
	// Half ops
	int halfop = false;
	if ((k & 0xf) == 8) {
		halfop = true;
		if (n == 0 || (countTrailingZeros(n) && n > 0)) {
			k++;
		}
	} else {
		if (n < 0) {
			k--;
		}
	}

	data = k | op->operands[0].reg << 24 | op->operands[1].reg << 29 | (op->operands[1].reg & 56) << 13;

	int imm = n;
	int low_shift = 20;
	int high_shift = 8;
	int top_shift = 10;
	if (n < 0) {
		imm = 0xfff + (n + 1);
	}
	if (halfop) {
		if (imm & 0x1 || n < 0) {
			data |= (0xf & imm) << low_shift ;
			data |= (0x7 & (imm >> 4)) << high_shift;
			data |= (0x7 & (imm >> 6)) << top_shift;
		} else {
			data |= (0xf & imm) << (low_shift - 3);
			data |= (0x7 & (imm >> 4)) << (high_shift + 13);
			data |= (0x7 & (imm >> 7)) << (top_shift  - 2);
		}
	} else {
		if (n < 0) {
			data |= (0xf & imm) << 20;
			data |= (0x1f & (imm >> 4)) << 8;
		} else {
			data |= (0xf & imm) << 18;
			data |= (0x3 & (imm >> 4)) << 22;
			data |= (0x7 & (imm >> 6)) << 8;
		}
	}
	return data;
}

static ut32 branch(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;
	int n = 0;
	if (op->operands[0].type & ARM_CONSTANT) {
		n = op->operands[0].immediate;
		if (!(n & 0x3 || n > 0x7ffffff)) {
			if (n >= addr) {
				n -= addr;
			} else {
				n -= addr;
				n = n & 0xfffffff;
				k |= 3;
			}
			n = n >> 2;
			int t = n >> 24;
			int h = n >> 16;
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
		if (n < 0 || n > 31) {
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

static ut32 mem_barrier (ArmOp *op, ut64 addr, int k) {
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

static ut32 orr(ArmOp *op, int addr) {
	ut32 data = UT32_MAX;

	if (op->operands[2].type & ARM_GPR) {
		// All operands need to be the same
		if (!(op->operands[0].reg_type == op->operands[1].reg_type &&
	 	    op->operands[1].reg_type == op->operands[2].reg_type)) {
		 	   return data;
		}
		if (op->operands[0].reg_type & ARM_REG64) {
			data = 0x000000aa;
		} else {
			data = 0x0000002a;
		}
		data += op->operands[0].reg << 24;
		data += op->operands[1].reg << 29;
		data += (op->operands[1].reg >> 3)  << 16;
		data += op->operands[2].reg << 8;
	} else if (op->operands[2].type & ARM_CONSTANT) {
		// Reg types need to match
		if (!(op->operands[0].reg_type == op->operands[1].reg_type)) {
			return data;
		}
		if (op->operands[0].reg_type & ARM_REG64) {
			data = 0x000040b2;
		} else {
			data = 0x00000032;
		}

		data += op->operands[0].reg << 24;
		data += op->operands[1].reg << 29;
		data += (op->operands[1].reg >> 3)  << 16;

		ut32 imm = decodeBitMasks (op->operands[2].immediate);
		if (imm == -1) {
			return imm;
		}
		int low = imm & 0xF;
		if (op->operands[0].reg_type & ARM_REG64) {
			imm = ((imm >> 6) | 0x78);
			if (imm > 120) {
				data |= imm << 8;
			}
		} else {
			imm = ((imm >> 2));
			if (imm > 120) {
				data |= imm << 4;
			}
		}
		data |= (4 * low) << 16;
	}
	return data;
}

static ut32 adrp(ArmOp *op, ut64 addr, ut32 k) { //, int reg, ut64 dst) {
	ut64 at = 0LL;
	ut32 data = k;
	if (op->operands[0].type == ARM_GPR) {
		data += ((op->operands[0].reg & 0xff) << 24);
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
	data += 0x01000000 * op->operands[0].reg;
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
	data += op->operands[0].reg << 24;
	data += op->operands[1].reg << 18;
	data += (op->operands[2].reg & 0x7) << 29;
	data += (op->operands[2].reg >> 3) << 16;
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

static ut32 arithmetic (ArmOp *op, int k) {
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
	data += op->operands[0].reg << 24;
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

static bool parseOperands(char* str, ArmOp *op) {
	char *t = strdup (str);
	int operand = 0;
	char *token = t;
	char *x;
	int imm_count = 0;
	int mem_opt = 0;
	int msr_op_index = 0;
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
		op->operands[operand].shift = ARM_NO_SHIFT;

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
			op->operands[operand].shift = ARM_LSL;
		} else if (!strncmp (token, "lsr", 3)) {
			op->operands[operand].shift = ARM_LSR;
		} else if (!strncmp (token, "asr", 3)) {
			op->operands[operand].shift = ARM_ASR;
		}
		if (strlen (token) > 4 && op->operands[operand].shift != ARM_NO_SHIFT) {
			op->operands_count ++;
			op->operands[operand].shift_amount = r_num_math (NULL, token + 4);
			if (op->operands[operand].shift_amount > 63) {
				free (t);
				return false;
			}
			operand ++;
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
			imm_count++;
			break;
		case '-':
			op->operands[operand].sign = -1;
			// falthru
		default:
			op->operands_count ++;
			op->operands[operand].type = ARM_CONSTANT;
			op->operands[operand].immediate = r_num_math (NULL, token);
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
		return false;
	}
	/* TODO: write tests for this and move out the regsize logic into the mov */
	if (!strncmp (str, "mov", 3)) {
		*op = mov (&ops);
		return *op != -1;
	}
	if (!strncmp (str, "cmp", 3)) {
		*op = cmp (&ops);
		return *op != -1;
	}
	if (!strncmp (str, "ldrb", 4)) {
		*op = bytelsop (&ops, 0x00004039);
		return *op != -1;
	}
	if (!strncmp (str, "ldrh", 4)) {
		*op = bytelsop (&ops, 0x00004078);
		return *op != -1;
	}
	if (!strncmp (str, "ldrsh", 5)) {
		*op = bytelsop (&ops, 0x0000c078);
		return *op != -1;
	}
	if (!strncmp (str, "ldrsw", 5)) {
		*op = bytelsop (&ops, 0x000080b8);
		return *op != -1;
	}
	if (!strncmp (str, "ldrsb", 5)) {
		*op = bytelsop (&ops, 0x0000c039);
		return *op != -1;
	}
	if (!strncmp (str, "strb", 4)) {
		*op = bytelsop (&ops, 0x00000039);
		return *op != -1;
	}
	if (!strncmp (str, "strh", 4)) {
		*op = bytelsop (&ops, 0x00000078);
		return *op != -1;
	}
	if (!strncmp (str, "ldr", 3)) {
		*op = reglsop (&ops, 0x000040f8);
		return *op != -1;
	}
	if (!strncmp (str, "stur", 4)) {
		*op = regsluop (&ops, 0x000000f8);
		return *op != -1;
	}
	if (!strncmp (str, "ldur", 4)) {
		*op = regsluop (&ops, 0x000040f8);
		return *op != -1;
	}
	if (!strncmp (str, "str", 3)) {
		*op = reglsop (&ops, 0x000000f8);
		return *op != -1;
	}
	if (!strncmp (str, "stp", 3)) {
		*op = stp (&ops, 0x000000a9);
		return *op != -1;
	}
	if (!strncmp (str, "ldp", 3)) {
		*op = stp (&ops, 0x000040a9);
		return *op != -1;
	}
	if (!strncmp (str, "sub", 3)) { // w
		*op = arithmetic (&ops, 0xd1);
		return *op != -1;
	}
	if (!strncmp (str, "add x", 5)) {
		*op = arithmetic (&ops, 0x91);
		return *op != -1;
	}
	if (!strncmp (str, "add w", 5)) {
		*op = arithmetic (&ops, 0x11);
		return *op != -1;
	}
	if (!strncmp (str, "adr x", 5)) { // w
		*op = adr (&ops, addr);
		return *op != -1;
	}
	if (!strncmp (str, "adrp x", 6)) {
		*op = adrp (&ops, addr, 0x00000090);
		return *op != -1;
	}
	if (!strncmp (str, "neg", 3)) {
		*op = neg (&ops);
		return *op != -1;
	}
	if (!strcmp (str, "isb")) {
		*op = 0xdf3f03d5;
		return *op != -1;
	}
	// PAC
	if (handlePAC (op, str)) {
		return true;
	}
	if (!strcmp (str, "nop")) {
		*op = 0x1f2003d5;
		return *op != -1;
	}
	if (!strcmp (str, "ret")) {
		*op = 0xc0035fd6;
		return true;
	}
	if (!strncmp (str, "msr ", 4)) {
		*op = msr (&ops, 0);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "mrs ", 4)) {
		*op = msr (&ops, 1);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "orr ", 4)) {
		*op = orr (&ops, addr);
		return *op != UT32_MAX;
	}
	if (!strncmp (str, "svc ", 4)) { // system level exception
		*op = exception (&ops, 0x010000d4);
		return *op != -1;
	}
	if (!strncmp (str, "hvc ", 4)) { // hypervisor level exception
		*op = exception (&ops, 0x020000d4);
		return *op != -1;
	}
	if (!strncmp (str, "smc ", 4)) { // secure monitor exception
		*op = exception (&ops, 0x030000d4);
		return *op != -1;
	}
	if (!strncmp (str, "brk ", 4)) { // breakpoint
		*op = exception (&ops, 0x000020d4);
		return *op != -1;
	}
	if (!strncmp (str, "hlt ", 4)) { // halt
		*op = exception (&ops, 0x000040d4);
		return *op != -1;
	}
	if (!strncmp (str, "b ", 2)) {
		*op = branch (&ops, addr, 0x14);
		return *op != -1;
	}
	if (!strncmp (str, "b.eq ", 5)) {
		*op = bdot (&ops, addr, 0x00000054);
		return *op != -1;
	}
	if (!strncmp (str, "b.hs ", 5)) {
		*op = bdot (&ops, addr, 0x02000054);
		return *op != -1;
	}
	if (!strncmp (str, "bl ", 3)) {
		*op = branch (&ops, addr, 0x94);
		return *op != -1;
	}
	if (!strncmp (str, "br x", 4)) {
		*op = branch (&ops, addr, 0x1fd6);
		return *op != -1;
	}
	if (!strncmp (str, "blr x", 5)) {
		*op = branch (&ops, addr, 0x3fd6);
		return *op != -1;
	}
	if (!strncmp (str, "dmb ", 4)) {
		*op = mem_barrier (&ops, addr, 0xbf3003d5);
		return *op != -1;
	}
	if (!strncmp (str, "dsb ", 4)) {
		*op = mem_barrier (&ops, addr, 0x9f3003d5);
		return *op != -1;
	}
	if (!strncmp (str, "isb", 3)) {
		*op = mem_barrier (&ops, addr, 0xdf3f03d5);
		return *op != -1;
	}
	return false;
}
