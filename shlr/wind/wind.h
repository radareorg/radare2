// Copyright (c) 2014, The Lemon Man, All rights reserved.

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library.

#ifndef _WIND_H_
#define _WIND_H_

#include "kd.h"

typedef struct _wind_ctx_t wind_ctx_t;

// grep -e "^wind_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
int wind_get_cpus (wind_ctx_t *ctx);
int wind_set_cpu (wind_ctx_t *ctx, int cpu);
int wind_get_cpu (wind_ctx_t *ctx);
wind_ctx_t * wind_ctx_new (void *io_ptr);
void wind_ctx_free (wind_ctx_t *ctx);
int wind_wait_packet (wind_ctx_t *ctx, const ut32 type, kd_packet_t **p);
int wind_sync (wind_ctx_t *ctx);
int wind_read_ver (wind_ctx_t *ctx);
int wind_continue (wind_ctx_t *ctx);
int wind_write_reg (wind_ctx_t *ctx, ut8 *buf, int size);
int wind_read_reg (wind_ctx_t *ctx, ut8 *buf, int size);
int wind_bkpt (wind_ctx_t *ctx, const ut64 addr, const int set, const int hw, int *handle);
int wind_read_at (wind_ctx_t *ctx, ut8 *buf, const ut64 offset, const int count);
int wind_write_at (wind_ctx_t *ctx, ut8 *buf, const ut64 offset, const int count);
#endif
