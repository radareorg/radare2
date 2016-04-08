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

#include <stdint.h>
#include "kd.h"

typedef struct _WindCtx WindCtx;

typedef struct WindProc {
	ut32 uniqueid;
	ut64 vadroot;
	ut64 dir_base_table;
	ut64 peb;
	char name[17];
} WindProc;

// grep -e "^wind_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
ut64 wind_get_target_base (WindCtx *ctx);
ut32 wind_get_target (WindCtx *ctx);
bool wind_set_target (WindCtx *ctx, ut32 pid);
RList *wind_list_process (WindCtx *ctx);
int wind_get_cpus (WindCtx *ctx);
bool wind_set_cpu (WindCtx *ctx, int cpu);
int wind_get_cpu (WindCtx *ctx);
WindCtx * wind_ctx_new (void *io_ptr);
void wind_ctx_free (WindCtx *ctx);
int wind_wait_packet (WindCtx *ctx, const ut32 type, kd_packet_t **p);
int wind_sync (WindCtx *ctx);
bool wind_read_ver (WindCtx *ctx);
int wind_continue (WindCtx *ctx);
bool wind_write_reg (WindCtx *ctx, const uint8_t *buf, int size);
int wind_read_reg (WindCtx *ctx, uint8_t *buf, int size);
int wind_query_mem (WindCtx *ctx, const ut64 addr, int *address_space, int *flags);
int wind_bkpt (WindCtx *ctx, const ut64 addr, const int set, const int hw, int *handle);
int wind_read_at (WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int wind_read_at_phys (WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int wind_write_at (WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
int wind_write_at_phys (WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
bool wind_va_to_pa (WindCtx *ctx, ut64 va, ut64 *pa);
bool wind_break (WindCtx *ctx);
int wind_break_read(WindCtx *ctx);
#endif
