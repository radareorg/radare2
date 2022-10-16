/* radare - LGPL - Copyright 2010-2022 - pancake, condret */

#if 0
#include <r_arch.h>
#include <r_io.h>
#include <r_reg.h>

R_API RArchValue *r_arch_value_new(void) { //macro for this ?
	return R_NEW0 (RArchValue);
}

R_API RArchValue *r_arch_value_copy(RArchValue *ov) {
	r_return_val_if_fail (ov, NULL);

	RArchValue *v = R_NEW0 (RArchValue);
	if (!v) {
		return NULL;
	}

	*v = *ov;
	// pointers to reg and regdelta should be kept
	return v;
}

// TODO: move into .h as #define free
R_API void r_arch_value_free(RArchValue *value) {
	free (value);
}

// mul*value+regbase+regidx+delta
R_API ut64 r_arch_value_to_ut64(RArchValue *val, RReg *reg) {
	ut64 num;
	if (!val) {
		return 0LL;
	}
	num = val->base + (val->delta * (val->mul ? val->mul : 1));
	if (val->reg) {
		num += r_reg_get_value (reg, val->reg);
	}
	if (val->regdelta) {
		num += r_reg_get_value (reg, val->regdelta);
	}
	switch (val->memref) {
	case 1:
	case 2:
	case 4:
	case 8:
		//anal->bio ...
		R_LOG_INFO ("memref for to_ut64 is not supported");
		break;
	}
	return num;
}

R_API bool r_arch_value_set_ut64(RArchValue *val, RReg *reg, RIOBind *iob, ut64 num) {
	r_return_val_if_fail (val && (!!val->memref) == (!!iob) && reg, false);
	if (val->memref) {
		ut8 data[8];
		const ut64 addr = r_arch_value_to_ut64 (val, reg);
		r_mem_set_num (data, val->memref, num);
		iob->write_at (iob->io, addr, data, val->memref);
		return true;
	} else {
		if (val->reg) {
			r_reg_set_value (reg, val->reg, num);
		}
		return true;
	}
	return false;
}

R_API char *r_arch_value_to_string(RArchValue *value) {
	char *out = NULL;
	if (value) {
		out = r_str_new ("");
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
				out = r_str_appendf (out, "%s", value->reg->name);
			}
			if (value->regdelta) {
				out = r_str_appendf (out, "+%s", value->regdelta->name);
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
#endif
