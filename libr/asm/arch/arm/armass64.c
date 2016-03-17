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

bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	if (!strncmp (str, "movk ", 5)) {
		*op = mov (str, 0x8072);
		return *op != -1;
	}
	if (!strncmp (str, "movz ", 5)) {
		*op = mov (str, 0x8052);
		return *op != -1;
	}
	if (!strcmp (str, "ret")) {
		*op = 0xc0035fd6;
		return true;
	}
	return false;
}
