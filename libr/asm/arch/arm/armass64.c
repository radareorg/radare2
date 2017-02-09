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
	ARM_LSL = 8,
	ARM_SHIFT = 16
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
		};
		struct {
			ut64 immediate;
			int sign;
		};
		struct {
			ut64 lsl;
			ut64 shift;
		};
	};
} Operand;

typedef struct Opcode_t {
	char *mnemonic;
	ut32 op[3];
	size_t op_len;
	ut8 opcode[3];
	int operands_count;
	Operand operands[5];
} ArmOp;

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

static ut32 branch_reg(ArmOp *op, ut64 addr, int k) {
	ut32 data = UT32_MAX;

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

#include "armass64_const.h"

static ut32 msrk(const char *arg) {
	int i;
	ut32 r = 0;
	ut32 v = r_num_get (NULL, arg);
	arg = r_str_chop_ro (arg);
	if (!v) {
		for (i = 0; msr_const[i].name; i++) {
			if (!strncasecmp (arg, msr_const[i].name, strlen (msr_const[i].name))) {
				v = msr_const[i].val;
				break;
			}
		}
		if (!v) {
			return UT32_MAX;
		}
	}
	ut32 a = ((v >> 12) & 0xf) << 1;
	ut32 b = ((v & 0xfff) >> 3) & 0xff;
	r |= a << 8;
	r |= b << 16;
	return r;
}

static ut32 msr(const char *str, int w) {
	const char *comma = strchr (str, ',');
	ut32 op = UT32_MAX;
	if (comma) {
		ut32 r, b;
		/* handle swapped args */
		if (w) {
			char *reg = strchr (str, 'x');
			if (!reg) {
				return op;
			}
			r = atoi (reg + 1);
			b = msrk (comma + 1);
		} else {
			char *reg = strchr (comma + 1, 'x');
			if (!reg) {
				return op;
			}
			r = atoi (reg + 1);
			b = msrk (str + 4);
		}
		op = (r << 24) | b | 0xd5;
		if (w) {
			/* mrs */
			op |= 0x2000;
		}
	}
	return op;
}

static bool exception(ut32 *op, const char *arg, ut32 type) {
	int n = (int)r_num_math (NULL, arg);
	n /= 8;
	*op = type;
	*op += ((n & 0xff) << 16);
	*op += ((n >> 8) << 8);
	return *op != -1;
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

	while (token[0] != '\0') {
		op->operands[operand].type = ARM_NOTYPE;
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
				op->operands_count ++;
				op->operands[operand].type = ARM_GPR;
				op->operands[operand].reg_type = ARM_SP | ARM_REG64;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			break;
			case 'p':
			case 'P':
			break;
			case '-':
				op->operands[operand].sign = -1;
			default:
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				switch (imm_count) {
					case 0:
						op->operands[operand].type = ARM_CONSTANT;
						op->operands[operand].immediate = r_num_math (NULL, token);
					break;
					case 1:
						op->operands[operand].type = ARM_LSL;
						op->operands[operand].lsl = r_num_math (NULL, token);
					break;
					case 2:
						op->operands[operand].type = ARM_SHIFT;
						op->operands[operand].shift = r_num_math (NULL, token);
					break;
					case 3:
					break;
				}
				imm_count++;
			break;
		}
		//printf ("operand %d type is %d - reg_type %d\n", operand, op->operands[operand].type, op->operands[operand].reg_type);
		if (x == '\0') {
			free (t);
			return true;
		}
		token = ++x;
		operand ++;

	}
	free (t);
	return true;
}

static bool parseOpcode(const char *str, ArmOp *op) {
	char *in = strdup (str);
	char *space = strchr (in, ' ');
	space[0] = '\0';
	op->mnemonic = in;
	space ++;
	parseOperands (space, op);
	return true;
}

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	ArmOp ops = {0};
	parseOpcode (str, &ops);

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
		int regnum = atoi (str + 5);
		char *arg = strchr (str + 5, ',');
		ut64 at = 0LL;
		if (arg) {
			at = r_num_math (NULL, arg + 1);
			// XXX what about negative values?
			at = at - addr;
			at /= 4;
		}
		*op = 0x00000010;
		*op += 0x01000000 * regnum;
		ut8 b0 = at;
		ut8 b1 = (at >> 3) & 0xff;
		ut8 b2 = (at >> (8 + 7)) & 0xff;
		*op += b0 << 29;
		*op += b1 << 16;
		*op += b2 << 24;
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
		*op = msr (str, 0);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "mrs ", 4)) {
		*op = msr (str, 1);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "svc ", 4)) { // system level exception
		return exception (op, str + 4, 0x010000d4);
	}
	if (!strncmp (str, "hvc ", 4)) { // hypervisor level exception
		return exception (op, str + 4, 0x020000d4);
	}
	if (!strncmp (str, "smc ", 4)) { // secure monitor exception
		return exception (op, str + 4, 0x040000d4);
	}
	if (!strncmp (str, "brk ", 4)) { // breakpoint
		return exception (op, str + 4, 0x000020d4);
	}
	if (!strncmp (str, "hlt ", 4)) { // halt
		return exception (op, str + 4, 0x000040d4);
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
	if (!strncmp (str, "blr x", 4)) {
		*op = branch (&ops, addr, 0x3fd6);
		return *op != -1;
	}
	return false;
}
