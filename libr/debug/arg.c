/* radare - LGPL - Copyright 2010-2015 pancake<nopcode.org> */

#include <r_debug.h>

R_API ut64 r_debug_arg_get (RDebug *dbg, int cctype, int num) {
	char reg[32];
	switch (cctype) {
	case R_ANAL_CC_TYPE_NONE:
	case R_ANAL_CC_TYPE_SYSV:
	case R_ANAL_CC_TYPE_FASTCALL:
		snprintf (reg, 30, "a%d", num);
		return r_debug_reg_get (dbg, reg);
	case R_ANAL_CC_TYPE_STDCALL:
	case R_ANAL_CC_TYPE_PASCAL:
		/* TODO: get from stack */
		break;
	}
	snprintf (reg, 30, "a%d", num);
	return r_debug_reg_get (dbg, reg);
}

R_API bool r_debug_arg_set (RDebug *dbg, int cctype, int num, ut64 val) {
	// TODO
	char reg[32];
	switch (cctype) {
	case R_ANAL_CC_TYPE_NONE:
	case R_ANAL_CC_TYPE_SYSV:
	case R_ANAL_CC_TYPE_FASTCALL:
		sprintf (reg, 30, "a%d", num);
		return r_debug_reg_set (dbg, reg, val);
	case R_ANAL_CC_TYPE_STDCALL:
	case R_ANAL_CC_TYPE_PASCAL:
		/* TODO: get from stack */
		break;
	}
	return false;
}
