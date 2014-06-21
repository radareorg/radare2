#ifndef DEF_SAFE_INT_H
#define DEF_SAFE_INT_H

/* radare - LGPL - Copyright 2009-2014 - Tosh */

#include "r_types.h"

int r_safe_addu64(ut64 *r, ut64 a, ut64 b);
int r_safe_addu32(ut32 *r, ut32 a, ut32 b);
int r_safe_addu16(ut16 *r, ut16 a, ut16 b);
int r_safe_mulu64(ut64 *r, ut64 a, ut64 b);
int r_safe_mulu32(ut32 *r, ut32 a, ut32 b);
int r_safe_mulu16(ut16 *r, ut16 a, ut16 b);
int r_safe_subu64(ut64 *r, ut64 a, ut64 b);
int r_safe_subu32(ut32 *r, ut32 a, ut32 b);
int r_safe_subu16(ut16 *r, ut16 a, ut16 b);

#endif /* DEF_SAFE_INT_H */
