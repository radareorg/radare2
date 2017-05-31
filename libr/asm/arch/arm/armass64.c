/* radare - LGPL - Copyright 2015-2017 - pancake */

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
			ut64 lsl;
			ut64 shift;
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
		if (!strcasecmp (token, options[i])) {
			return 15 - i;
		}
		i++;
	}
	return -1;
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
	//printf ("Immediate %d\n", op->operands[1].immediate);
	data |= (op->operands[0].reg << 24); // arg(0)
	data |= ((op->operands[1].immediate & 7) << 29); // arg(1)
	data |= (((op->operands[1].immediate >> 3) & 0xff) << 16); // arg(1)
	data |= ((op->operands[1].immediate >> 10) << 7); // arg(1)
	return data;

}

static ut32 branch(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;
	int n = 0;
	if (op->operands[0].type & ARM_CONSTANT) {
		n = op->operands[0].immediate;
		if (!(n & 0x3 || n > 0x7ffffff)) {
			n -= addr;
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
	}
	return data;
}

#include "armass64_const.h"

static ut32 msrk(ut16 v) {
	ut32 r = 0;
	ut32 a = ((v >> 12) & 0xf) << 1;
	ut32 b = ((v & 0xfff) >> 3) & 0xff;
	r |= a << 8;
	r |= b << 16;
	return r;
}

static ut32 msr(ArmOp *op, int w) {
	ut32 data = UT32_MAX;
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
		b = msrk (op->operands[0].sp_val);
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
		r = op->operands[0].reg;
		b = msrk (op->operands[0].sp_val);
	}
	data = (r << 24) | b | 0xd5;
	if (w) {
		/* mrs */
		data |= 0x413000;
	}
	if (op->operands[1].reg_type == ARM_REG64) {
		data |= op->operands[1].reg << 24;
	}

	return data;
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
	if (op->operands[2].reg_type & ARM_REG64) {
		data += op->operands[2].reg << 8;
	} else {
		data += (op->operands[2].reg & 0x3f) << 18;
		data += (op->operands[2].reg >> 6) << 8;
	}
	return data;
}

static bool parseOperands(char* str, ArmOp *op) {
	char *t = strdup (str);
	int operand = 0;
	char *token = t;
	char *x;
	int imm_count = 0;
	int mem_opt = 0;

	while (token[0] != '\0') {
		op->operands[operand].type = ARM_NOTYPE;
		op->operands[operand].reg_type = ARM_UNDEFINED;
		switch (token[0]) {
			case ' ':
				token ++;
				continue;
				break;
			case 'x':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_GPR;
				op->operands[operand].reg_type = ARM_REG64;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			break;
			case 'w':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_GPR;
				op->operands[operand].reg_type = ARM_REG32;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			break;
			case 'v':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_FP;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			break;
			case 's':
			case 'S':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				if (token[1] == 'P' || token [1] == 'p') {
					int i;
					for (i = 0; msr_const[i].name; i++) {
						if (!strncasecmp (token, msr_const[i].name, strlen (msr_const[i].name))) {
							op->operands[operand].sp_val = msr_const[i].val;
							break;
						}
					}
					op->operands_count ++;
					op->operands[operand].type = ARM_GPR;
					op->operands[operand].reg_type = ARM_SP | ARM_REG64;
					op->operands[operand].reg = r_num_math (NULL, token + 1);
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
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				mem_opt = get_mem_option (token);
				if (mem_opt != -1) {
					op->operands_count ++;
					op->operands[operand].type = ARM_MEM_OPT;
					op->operands[operand].mem_option = mem_opt;
				}
			break;
			case '-':
				op->operands[operand].sign = -1;
			default:
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_CONSTANT;
				op->operands[operand].immediate = r_num_math (NULL, token);
				imm_count++;
			break;
		}
		if (x && x[0] == '\0') {
			free (t);
			return true;
		}
		token = ++x;
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

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	ArmOp ops = {0};
	if (!parseOpcode (str, &ops)) {
		return -1;
	}
	/* TODO: write tests for this and move out the regsize logic into the mov */
	if (!strncmp (str, "mov", 3)) {
		*op = mov (&ops);
		return *op != -1;
	}
	if (!strncmp (str, "sub", 3)) { // w
		*op = arithmetic (&ops, 0xd1);
		return *op != -1;
	}
	if (!strncmp (str, "add", 3)) { // w
		*op = arithmetic (&ops, 0x91);
		return *op != -1;
	}
	if (!strncmp (str, "adr x", 5)) { // w
		*op = adr (&ops, addr);
		return *op != -1;
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
