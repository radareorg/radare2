/* radare - LGPL - Copyright 2010-2022 - pancake, condret */

#include <r_arch.h>

#if 0
R_API const char *r_arch_cond_tostring(RArchCond cc) {
	switch (cc) {
	case R_ARCH_COND_EQ: return "eq";
	case R_ARCH_COND_NV: return "nv";
	case R_ARCH_COND_NE: return "ne";
	case R_ARCH_COND_HS: return "hs";
	case R_ARCH_COND_LO: return "lo";
	case R_ARCH_COND_MI: return "mi";
	case R_ARCH_COND_PL: return "pl";
	case R_ARCH_COND_VS: return "vs";
	case R_ARCH_COND_VC: return "vc";
	case R_ARCH_COND_HI: return "hi";
	case R_ARCH_COND_LS: return "ls";
	case R_ARCH_COND_GE: return "ge";
	case R_ARCH_COND_LT: return "lt";
	case R_ARCH_COND_GT: return "gt";
	case R_ARCH_COND_LE: return "le";
	case R_ARCH_COND_AL: return "al";
	}
	return "??";
}
#endif
