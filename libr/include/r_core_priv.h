/* radare - LGPL - Copyright 2024 - pancake */

#include <r_core.h>

#ifndef R2_CORE_PRIV_H
#define R2_CORE_PRIV_H

#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
	int old_bits;
	char *old_arch;
} RCorePriv;

#ifdef __cplusplus
}
#endif

#endif
