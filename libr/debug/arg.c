/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_debug.h>

R_API ut64 r_debug_arg_get (RDebug *dbg, int type, int num) {
	char reg[8];
	// TODO
	sprintf (reg, "a%d", num);
	return r_debug_reg_get (dbg, reg);
}

R_API int r_debug_arg_set (RDebug *dbg, int fast, int num, ut64 value) {
	// TODO
	return R_FALSE;
}
