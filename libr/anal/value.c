/* radare - LGPL - Copyright 2010-2020 - pancake */

#include <r_anal.h>

R_API RAnalValue *r_anal_value_new(void) { //macro for this ?
	return R_NEW0 (RAnalValue);
}

R_API RAnalValue *r_anal_value_new_from_string(const char *str) {
	/* TODO */
	return NULL;
}

R_API RAnalValue *r_anal_value_copy(RAnalValue *ov) {
	r_return_val_if_fail (ov, NULL);

	RAnalValue *v = R_NEW0 (RAnalValue);
	if (!v) {
		return NULL;
	}

	memcpy (v, ov, sizeof (RAnalValue));
	// reference to reg and regdelta should be kept
	return v;
}

// TODO: move into .h as #define free
R_API void r_anal_value_free(RAnalValue *value) {
	if (value) {
		r_unref (value->seg);
		r_unref (value->reg);
		r_unref (value->regdelta);
		free (value);
	}
#if 0
	ut64 pval = (ut64)(size_t)value;
	if (pval && pval != UT64_MAX) {
		/* TODO: free RRegItem objects? */
		free (value);
	}
#endif
}

// mul*value+regbase+regidx+delta
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RAnalValue *val) {
	ut64 num;
	if (!val) {
		return 0LL;
	}
	num = val->base + (val->delta * (val->mul ? val->mul : 1));
	if (val->reg) {
		num += r_reg_get_value (anal->reg, val->reg);
	}
	if (val->regdelta) {
		num += r_reg_get_value (anal->reg, val->regdelta);
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

R_API int r_anal_value_set_ut64(RAnal *anal, RAnalValue *val, ut64 num) {
	if (val->memref) {
		if (anal->iob.io) {
			ut8 data[8];
			ut64 addr = r_anal_value_to_ut64 (anal, val);
			r_mem_set_num (data, val->memref, num);
			anal->iob.write_at (anal->iob.io, addr, data, val->memref);
		} else {
			R_LOG_ERROR ("No IO binded to r_anal");
		}
	} else {
		if (val->reg) {
			r_reg_set_value (anal->reg, val->reg, num);
		}
	}
	return false;							//is this necessary
}

R_API char *r_anal_value_tostring(RAnalValue *value) {
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
