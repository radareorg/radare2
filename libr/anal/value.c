/* radare - LGPL - Copyright 2010-2024 - pancake */

#include <r_anal.h>

R_API RAnalValue *r_anal_value_new(void) { //macro for this ?
	return R_NEW0 (RAnalValue);
}

R_API RAnalValue *r_anal_value_new_from_string(const char *str) {
	/* TODO */
	return NULL;
}

// mul*value+regbase+regidx+delta
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RAnalValue *val) {
	R_RETURN_VAL_IF_FAIL (anal && val, 0LL);
	ut64 num = val->base + (val->delta * (val->mul ? val->mul : 1));
	if (val->reg) {
		st64 n = (st64)r_reg_getv (anal->reg, val->reg);
		if (ST64_ADD_OVFCHK (num, n)) {
			num = UT64_MAX;
		} else {
			num += n;
		}
	}
	if (val->regdelta) {
		st64 n = (st64)r_reg_getv (anal->reg, val->regdelta);
		if (ST64_ADD_OVFCHK (num, n)) {
			num = UT64_MAX;
		} else {
			num += n;
		}
	}
	switch (val->memref) {
	case 1:
	case 2:
	case 4:
	case 8:
		// anal->bio ...
		R_LOG_INFO ("memref for to_ut64 is not supported");
		break;
	}
	return num;
}

R_API bool r_anal_value_set_ut64(RAnal *anal, RAnalValue *val, ut64 num) {
	R_RETURN_VAL_IF_FAIL (anal && val, false);
	if (val->memref) {
		if (R_LIKELY (anal->iob.io)) {
			ut8 data[8];
			ut64 addr = r_anal_value_to_ut64 (anal, val);
			r_mem_set_num (data, val->memref, num);
			anal->iob.write_at (anal->iob.io, addr, data, val->memref);
			return true;
		}
		R_LOG_ERROR ("No IO binded to r_anal");
		return false;
	}
	return (val->reg)
		? r_reg_setv (anal->reg, val->reg, num)
		: false;
}

R_API const char *r_anal_value_type_tostring(RAnalValue *value) {
	R_RETURN_VAL_IF_FAIL (value, NULL);
	switch (value->type) {
	case R_ANAL_VAL_REG: return "reg";
	case R_ANAL_VAL_MEM: return "mem";
	case R_ANAL_VAL_IMM: return "imm";
	}
	return "unk";
}

R_API char *r_anal_value_tostring(RAnalValue *value) {
	R_RETURN_VAL_IF_FAIL (value, NULL);
	char *out = NULL;
	if (value) {
		out = strdup ("");
		if (!value->base && !value->reg) {
			if (value->imm != -1LL) {
				out = r_str_appendf (out, "0x%"PFMT64x, value->imm);
			} else {
				out = r_str_append (out, "-1");
			}
		} else {
			if (value->memref) {
				switch (value->memref) {
				case 1: out = r_str_append (out, "(char)"); break;
				case 2: out = r_str_append (out, "(short)"); break;
				case 4: out = r_str_append (out, "(word)"); break;
				case 8: out = r_str_append (out, "(dword)"); break;
				}
				out = r_str_append (out, "[");
			}
			if (value->mul) {
				out = r_str_appendf (out, "%d*", value->mul);
			}
			if (value->reg) {
				out = r_str_appendf (out, "%s", value->reg);
			}
			if (value->regdelta) {
				out = r_str_appendf (out, "+%s", value->regdelta);
			}
			if (value->base != 0) {
				out = r_str_appendf (out, "0x%" PFMT64x, value->base);
			}
			if (value->delta > 0) {
				out = r_str_appendf (out, "+0x%" PFMT64x, value->delta);
			} else if (value->delta < 0) {
				out = r_str_appendf (out, "-0x%" PFMT64x, -value->delta);
			}
			if (value->memref) {
				out = r_str_append (out, "]");
			}
		}
	}
	return out;
}
