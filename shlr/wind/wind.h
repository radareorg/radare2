#ifndef _WIND_H_
#define _WIND_H_

#include "kd.h"

typedef struct wind_ctx_t {
	void *io_ptr;
	int seq_id;
	int syncd;
	int cpu_count;
	int cpu;
} wind_ctx_t;

// grep -e "^wind_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
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
