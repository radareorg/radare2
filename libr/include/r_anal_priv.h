/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_ANAL_PRIV_H
#define R2_ANAL_PRIV_H

#include "r_anal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_anal_priv_t {
	bool types_dirty;
} RAnalPriv;

#define R_ANAL_PRIV(x) ((RAnalPriv*)(x)->priv)

#ifdef __cplusplus
}
#endif

#endif
