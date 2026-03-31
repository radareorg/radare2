/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_ANAL_PRIV_H
#define R2_ANAL_PRIV_H

#include "r_anal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_anal_priv_t {
	bool types_dirty;
	int types_loaded_bits;
	char *dir_prefix;
} RAnalPriv;

#define R_ANAL_PRIV(x) ((RAnalPriv*)(x)->priv)

R_IPI void r_anal_types_ensure_loaded(RAnal *anal);
R_IPI bool r_anal_var_is_default_argname(const char *name);
R_IPI bool r_anal_function_materialize_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr, int depth);

#ifdef __cplusplus
}
#endif

#endif
