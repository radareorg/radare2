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

#ifndef _winkd_H_
#define _winkd_H_

#include <stdint.h>
#include <r_bind.h>
#include <r_th.h>
#include <r_list.h>
#include "kd.h"

typedef struct WindProc {
	ut64 eprocess;
	ut32 uniqueid;
	ut64 vadroot;
	ut64 dir_base_table;
	ut64 peb;
	char name[17];
} WindProc;

typedef struct WindThread {
	ut32 uniqueid;
	bool runnable;
	char status;
	ut64 ethread;
	ut64 entrypoint;
} WindThread;

typedef struct WindModule {
	char *name;
	ut64 addr;
	ut64 size;
} WindModule;

enum {
	K_PaeEnabled = 0x036,
	K_PsActiveProcessHead = 0x050,
	K_CmNtCSDVersion = 0x268,
};

enum {
	E_ActiveProcessLinks, // EPROCESS
	E_UniqueProcessId,    // EPROCESS
	E_Peb,                // EPROCESS
	E_ImageFileName,      // EPROCESS
	E_VadRoot,            // EPROCESS
	E_ThreadListHead,     // EPROCESS
	P_DirectoryTableBase, // PCB
	P_ImageBaseAddress,   // PEB
	P_ProcessParameters,  // PEB
	R_ImagePathName,      // RTL_USER_PROCESS_PARAMETERS
	ET_Tcb,               // ETHREAD
	ET_ThreadListEntry,   // ETHREAD
	ET_Win32StartAddress, // ETHREAD
	ET_Cid,               // ETHREAD
	C_UniqueThread,       // CLIENT_ID
	O_Max,
};

typedef struct {
	int build;
	int sp;
	int bits;
	int flags;
	int f[O_Max];
} Profile;

struct _WindCtx {
	io_desc_t *desc;
	uint32_t seq_id;
	int syncd;
	int cpu_count;
	int cpu;
	int pae;
	bool is_x64;
	Profile *os_profile;
	RList *plist_cache;
	RList *tlist_cache;
	ut64 dbg_addr;
	WindProc *target;
	RThreadLock *dontmix;
	RMutaBind *mb;
};

typedef struct _WindCtx WindCtx;

// grep -e "^winkd_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
int winkd_get_bits(WindCtx *ctx);
ut64 winkd_get_target_base(WindCtx *ctx);
ut32 winkd_get_target(WindCtx *ctx);
bool winkd_set_target(WindCtx *ctx, ut32 pid);
RList *winkd_list_process(WindCtx *ctx);
RList *winkd_list_threads(WindCtx *ctx);
RList *winkd_list_modules(WindCtx *ctx);
int winkd_get_cpus(WindCtx *ctx);
bool winkd_set_cpu(WindCtx *ctx, int cpu);
int winkd_get_cpu(WindCtx *ctx);
WindCtx * winkd_ctx_new(io_desc_t *desc);
void winkd_ctx_free(WindCtx **ctx);
int winkd_wait_packet(WindCtx *ctx, const ut32 type, kd_packet_t **p);
int winkd_sync(WindCtx *ctx);
bool winkd_read_ver(WindCtx *ctx);
int winkd_continue(WindCtx *ctx);
bool winkd_write_reg(WindCtx *ctx, const uint8_t *buf, int size);
int winkd_read_reg(WindCtx *ctx, uint8_t *buf, int size);
int winkd_query_mem(WindCtx *ctx, const ut64 addr, int *address_space, int *flags);
int winkd_bkpt(WindCtx *ctx, const ut64 addr, const int set, const int hw, int *handle);
int winkd_read_at(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int winkd_read_at_uva(WindCtx *ctx, uint8_t *buf, ut64 offset, int count);
int winkd_read_at_phys(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int winkd_write_at(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
int winkd_write_at_uva(WindCtx *ctx, const uint8_t *buf, ut64 offset, int count);
int winkd_write_at_phys(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
bool winkd_va_to_pa(WindCtx *ctx, ut64 va, ut64 *pa);
void winkd_break(void *ctx);
int winkd_break_read(WindCtx *ctx);
bool winkd_lock_enter(WindCtx *ctx);
bool winkd_lock_leave(WindCtx *ctx);
bool winkd_lock_tryenter(WindCtx *ctx);
#endif
