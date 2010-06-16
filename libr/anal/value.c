/* radare - LGPL - Copyright 2010 */
/*   pancake<nopcode.org> */

#include <r_anal.h>

R_API RAnalValue *r_anal_value_new() {
	RAnalValue *cond = R_NEW (RAnalValue);
	memset (cond, 0, sizeof (RAnalValue));
	return cond;
}

R_API RAnalValue *r_anal_value_new_from_string(const char *str) {
	/* TODO */
	return NULL;
}

// TODO: move into .h as #define free
R_API void r_anal_value_free(RAnalValue *value) {
	free (value);
}

R_API st64 r_anal_value_eval(RAnalValue *value) {
	/* OMFG TODO.. this is done by r_num_shit */
	// r_num_math (anal->num, ...);
#warning TODO r_anal_value_eval
	return 0LL;
}

R_API char *r_anal_value_to_string (RAnalValue *value) {
	char *out = r_str_new ("");
	if (value) {
		if (value->memref) {
			switch (value->memref) {
			case 1: out = r_str_concat (out, "(char)"); break;
			case 2: out = r_str_concat (out, "(short)"); break;
			case 4: out = r_str_concat (out, "(word)"); break;
			case 8: out = r_str_concat (out, "(dword)"); break;
			}
			out = r_str_concat (out, "[");
		}
		if (value->mul) out = r_str_concatf (out, "%d*", value->mul);
		if (value->reg) out = r_str_concatf (out, "%s", value->reg->name);
		if (value->regdelta) out = r_str_concatf (out, "+%s", value->regdelta->name);
		if (value->base!=0) out = r_str_concatf (out, "0x%"PFMT64x, value->base);
		if (value->delta>0) out = r_str_concatf (out, "+%d", value->delta);
		else if (value->delta<0) out = r_str_concatf (out, "%d", value->delta);
		if (value->memref) out = r_str_concat (out, "]");
	}
	return out;
}
