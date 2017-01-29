/* radare - LGPL - Copyright 2015-2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>

static ut32 mov(const char *str, int k) {
	ut32 op = UT32_MAX;
	const char *op1 = strchr (str, ' ') + 1;
	char *comma = strchr (str, ',');
	comma[0] = '\0';
	const char *op2 = (comma[1]) == ' ' ? comma + 2 : comma + 1;

	int n = (int)r_num_math (NULL, op1 + 1);
	int w = (int)r_num_math (NULL, op2);
	if (!strncmp (str, "mov x", 5)) {
		// TODO handle values > 32
		if (n >= 0 && n < 32) {
			if (op2[0] == 'x') {
				w = (int)r_num_math (NULL, op2 + 1);
				k = 0xE00300AA;
				op = k | w << 8;
			} else {
				op = k | w << 29;
			}
		}
		op |= n << 24;
	} else if (!strncmp (str, "mov", 3) && strlen (str) > 5) {
		if (n >= 0 && n < 32 && comma) {
			op = k;
			op |= (n << 24); // arg(0)
			op |= ((w & 7) << 29); // arg(1)
			op |= (((w >> 3) & 0xff) << 16); // arg(1)
			op |= ((w >> 10) << 7); // arg(1)
		}
	}
	return op;
}

static ut32 branch_reg(const char *str, ut64 addr, int k) {
	ut32 op = UT32_MAX;
	const char *operand = strchr (str, 'x');
	if (!operand) {
		return -1;
	}
	operand++;
	int n = (int)r_num_math (NULL, operand);
	if (n < 0 || n > 31) {
		return -1;
	}
	n = n << 5;
	int h = n >> 8;
	n &= 0xff;
	op = k;
	op |= n << 24;
	op |= h << 16;
	return op;
}

static ut32 branch(const char *str, ut64 addr, int k) {
	ut32 op = UT32_MAX;
	const char *operand = strchr (str, ' ');
	if (operand) {
		operand++;
		int n = (int)r_num_math (NULL, operand);

		if (n & 0x3 || n > 0x7ffffff) {
			/* return -1 */
		} else {
			n -= addr;
			n = n >> 2;
			int t = n >> 24;
			int h = n >> 16;
			int m = (n & 0xff00) >> 8;
			n &= 0xff;
			op = k;
			op |= n << 24;
			op |= m << 16;
			op |= h << 8;
			op |= t;
		}
	}
	return op;
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

static exception(ut32 *op, const char *arg, ut32 type) {
	int n = (int)r_num_math (NULL, arg);
	n /= 8;
	*op = type;
	*op += ((n & 0xff) << 16);
	*op += ((n >> 8) << 8);
	return *op != -1;
}

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	/* TODO: write tests for this and move out the regsize logic into the mov */
	if (!strncmp (str, "movk w", 6)) {
		return mov (str, 0x8072) != -1;
	}
	if (!strncmp (str, "movk x", 6)) {
		return mov (str, 0x80f2) != -1;
	}
	if (!strncmp (str, "movn x", 6)) {
		return mov (str, 0x8092) != -1;
	}
	if (!strncmp (str, "movn w", 6)) {
		*op = mov (str, 0x8012);
		return *op != -1;
	}
	if (!strncmp (str, "movz x", 6)) {
		*op = mov (str, 0x80d2);
		return *op != -1;
	}
	if (!strncmp (str, "movz ", 5)) { // w
		*op = mov (str, 0x8052);
		return *op != -1;
	}
	if (!strncmp (str, "mov x", 5)) { // w
		*op = mov (str, 0x80d2);
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
		*op = branch (str, addr, 0x14);
		return *op != -1;
	}
	if (!strncmp (str, "bl ", 3)) {
		*op = branch (str, addr, 0x94);
		return *op != -1;
	}
	if (!strncmp (str, "br x", 4)) {
		*op = branch_reg (str, addr, 0x1fd6);
		return *op != -1;
	}
	if (!strncmp (str, "blr x", 4)) {
		*op = branch_reg (str, addr, 0x3fd6);
		return *op != -1;
	}
	return false;
}
