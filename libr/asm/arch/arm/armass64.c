/* radare - LGPL - Copyright 2015-2016 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>

static ut32 mov(const char *str, int k) {
	const char *comma = strchr (str, ',');
	ut32 op = UT32_MAX;
	if (!strncmp (str, "mov", 3) && strlen (str)> 5) {
		if (!strncmp (str + 4, " w", 2)) {
			int w = atoi (str + 6);
			if (w >= 0 && w < 32 && comma) {
				int n = (int)r_num_math (NULL, comma + 1);
				op = k;
				op |= (w << 24); // arg(0)
				op |= ((n & 7)<<29); // arg(1)
				op |= (((n >> 3) & 0xff)<<16); // arg(1)
				op |= ((n >> 10)<<7); // arg(1)
			}
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

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	if (!strncmp (str, "movk ", 5)) {
		*op = mov (str, 0x8072);
		return *op != -1;
	}
	if (!strncmp (str, "movz ", 5)) {
		*op = mov (str, 0x8052);
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
	return false;
}
