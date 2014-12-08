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
	uint32_t uniqueid;
	uint64_t vadroot;
	uint64_t dir_base_table;
	uint64_t peb;
	char name[17];
} WindProc;

// grep -e "^wind_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
uint64_t wind_get_target_base (WindCtx *ctx);
uint32_t wind_get_target (WindCtx *ctx);
int wind_set_target (WindCtx *ctx, uint32_t pid);
RList *wind_list_process (WindCtx *ctx);
int wind_get_cpus (WindCtx *ctx);
int wind_set_cpu (WindCtx *ctx, int cpu);
int wind_get_cpu (WindCtx *ctx);
WindCtx * wind_ctx_new (void *io_ptr);
void wind_ctx_free (WindCtx *ctx);
int wind_wait_packet (WindCtx *ctx, const uint32_t type, kd_packet_t **p);
int wind_sync (WindCtx *ctx);
int wind_read_ver (WindCtx *ctx);
int wind_continue (WindCtx *ctx);
int wind_write_reg (WindCtx *ctx, uint8_t *buf, int size);
int wind_read_reg (WindCtx *ctx, uint8_t *buf, int size);
int wind_query_mem (WindCtx *ctx, const uint64_t addr, int *address_space, int *flags);
int wind_bkpt (WindCtx *ctx, const uint64_t addr, const int set, const int hw, int *handle);
int wind_read_at (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count);
int wind_read_at_phys (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count);
int wind_write_at (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count);
int wind_write_at_phys (WindCtx *ctx, uint8_t *buf, const uint64_t offset, const int count);
int wind_va_to_pa (WindCtx *ctx, uint64_t va, uint64_t *pa);
#endif
