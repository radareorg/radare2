/* radare - LGPL - Copyright 2014-2022 - pancake */

#include <r_reg.h>

#undef Z
#undef S
#undef C
#undef O
#undef P
#define Z f->z
#define S f->s
#define C f->c
#define O f->o
#define P f->p

R_API RRegItem *r_reg_cond_get(RReg *reg, const char *name) {
	R_RETURN_VAL_IF_FAIL (reg && name, NULL);
	RListIter *iter;
	RRegItem *r;

	r_list_foreach (reg->regset[R_REG_TYPE_GPR].regs, iter, r) {
		if (r->flags && !strcmp (name, r->flags)) {
			return r;
		}
	}
	return NULL;
}

R_API bool r_reg_cond_get_value(RReg *r, const char *name) {
	RRegItem *ri = r_reg_cond_get (r, name);
	return ri && r_reg_get_value (r, ri) != 0;
}

R_API bool r_reg_cond_set(RReg *r, const char *name, bool val) {
	RRegItem *item = r_reg_cond_get (r, name);
	if (item) {
		r_reg_set_value (r, item, val);
		return true;
	}
	return false;
}

R_API const char *r_reg_cond_tostring(int n) {
	const char *cs[] = {
		"eq", "ne", "cf", "neg", "of", "hi", "he",
		"lo", "loe", "ge", "gt", "lt", "le"
	};
	if (n < 0 || (n > (sizeof (cs) / sizeof (*cs)) - 1)) {
		return NULL;
	}
	return cs[n];
}

R_API int r_reg_cond_from_string(const char *str) {
#define CK(x,y) ((x) | ((y)<<8))
	switch (str[0] | (str[1] << 8)) {
	case CK('e','q'): return R_REG_COND_EQ;
	case CK('n','e'): return strcmp (str, "neg")? R_REG_COND_NE: R_REG_COND_NEG;
	case CK('c','f'): return R_REG_COND_CF;
	case CK('o','f'): return R_REG_COND_OF;
	case CK('h','i'): return R_REG_COND_HI;
	case CK('h','e'): return R_REG_COND_HE;
	case CK('l','o'): return strcmp (str, "loe")? R_REG_COND_LO: R_REG_COND_LOE;
	case CK('g','e'): return R_REG_COND_GE;
	case CK('g','t'): return R_REG_COND_GT;
	case CK('l','t'): return R_REG_COND_LT;
	case CK('l','e'): return R_REG_COND_LE;
	}
	// TODO: move this help message into the core
	eprintf ("Usage: drc[=] [condition](=1,0)\n"
		 "| eq    equal\n"
		 "| ne    not equal\n"
		 "| cf    carry flag set\n"
		 "| neg   negative value (has sign)\n"
		 "| of    overflow\n"
		 "|unsigned:\n"
		 "| hi    higher\n"
		 "| he    higher or equal\n"
		 "| lo    lower\n"
		 "| loe   lower or equal\n"
		 "|signed:\n"
		 "| ge    greater or equal\n"
		 "| gt    greater than\n"
		 "| le    less or equal\n"
		 "| lt    less than\n");
	return -1;
}

R_API bool r_reg_cond_bits(RReg *r, int type, RRegFlags *f) {
	switch (type) {
	case R_REG_COND_EQ: return Z;
	case R_REG_COND_NE: return !Z;
	case R_REG_COND_CF: return C;
	case R_REG_COND_NEG: return S;
	case R_REG_COND_OF:
		return O;
	// unsigned
	case R_REG_COND_HI: return (!Z && C); // HIGHER
	case R_REG_COND_HE: return Z || (!Z && C); // HIGHER OR EQUAL
	case R_REG_COND_LO: return (Z || !C); // LOWER
	case R_REG_COND_LOE:
		return (Z || !C); // LOWER OR EQUAL
	// signed
	case R_REG_COND_GE: return ((S && O) || (!S && !O));
	case R_REG_COND_GT: return ((S && !Z && O) || (!S && !Z && !O));
	case R_REG_COND_LT: return ((S && !O) || (!S && O));
	case R_REG_COND_LE: return (Z || (S && !O) || (!S && O));
	}
	return false;
}

R_API bool r_reg_cond_bits_set(RReg *r, int type, RRegFlags *f, bool v) {
	switch (type) {
	case R_REG_COND_EQ: Z = v; break;
	case R_REG_COND_NE: Z = !v; break;
	case R_REG_COND_CF: C = v; break;
	case R_REG_COND_NEG: S = v; break;
	case R_REG_COND_OF: O = v; break;
	case R_REG_COND_HI:
		if (v) {
			Z = 0;
			C = 1;
		} else {
			Z = 1;
			C = 0;
		}
		break;
	case R_REG_COND_HE:
		if (v) {
			Z = 1;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	case R_REG_COND_LO:
		if (v) {
			Z = 1;
			C = 0;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	case R_REG_COND_LOE:
		if (v) {
			Z = 1;
			C = 0;
		} else {
			Z = 0;
			C = 1;
		}
		break;
	// signed
	case R_REG_COND_GE:
		if (v) {
			S = O = 1;
		} else {
			S = 1;
			O = 0;
		}
		break;
	case R_REG_COND_GT:
		if (v) {
			S = 1;
			Z = 0;
			O = 1;
		} else {
			S = 0;
			Z = 1;
			O = 0;
		}
		break;
	case R_REG_COND_LT:
		if (v) {
			S = 1;
			O = 0;
		} else {
			S = 1;
			O = 1;
		}
		break;
	case R_REG_COND_LE:
		if (v) {
			S = 0;
			Z = 1;
			O = 0;
		} else {
			S = 1;
			Z = 0;
			O = 1;
		}
		break;
	default:
		return false;
	}
	return true;
}

R_API bool r_reg_cond(RReg *r, int type) {
	R_RETURN_VAL_IF_FAIL (r, false);
	RRegFlags f = {0};
	r_reg_cond_retrieve (r, &f);
	return r_reg_cond_bits (r, type, &f);
}

R_API RRegFlags *r_reg_cond_retrieve(RReg *r, RRegFlags *f) {
	if (!f) {
		f = R_NEW0 (RRegFlags);
		if (!f) {
			return NULL;
		}
	}
	f->s = r_reg_cond_get_value (r, "sign"); // sign, negate flag, less than zero
	f->z = r_reg_cond_get_value (r, "zero"); // zero flag
	f->c = r_reg_cond_get_value (r, "carry"); // carry flag
	f->o = r_reg_cond_get_value (r, "overflow"); // overflow flag
	f->p = r_reg_cond_get_value (r, "parity"); // parity // intel only
	return f;
}

R_API void r_reg_cond_apply(RReg *r, RRegFlags *f) {
	R_RETURN_IF_FAIL (r && f);
	r_reg_cond_set (r, "sign", f->s);
	r_reg_cond_set (r, "zero", f->z);
	r_reg_cond_set (r, "carry", f->c);
	r_reg_cond_set (r, "overflow", f->o);
	r_reg_cond_set (r, "parity", f->p);
}
