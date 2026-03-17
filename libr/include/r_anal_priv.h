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
} RAnalPriv;

#define R_ANAL_PRIV(x) ((RAnalPriv*)(x)->priv)

R_IPI void r_anal_types_ensure_loaded(RAnal *anal);

#ifdef __cplusplus
}
#endif

#endif
