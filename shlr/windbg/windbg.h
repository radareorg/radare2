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

#ifndef _windbg_H_
#define _windbg_H_

#include <stdint.h>
#include "kd.h"

typedef struct _WindCtx WindCtx;

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

// grep -e "^windbg_" shlr/wind/wind.c | sed -e 's/ {$/;/' -e 's/^/int /'
int windbg_get_bits(WindCtx *ctx);
ut64 windbg_get_target_base(WindCtx *ctx);
ut32 windbg_get_target(WindCtx *ctx);
bool windbg_set_target(WindCtx *ctx, ut32 pid);
RList *windbg_list_process(WindCtx *ctx);
RList *windbg_list_threads(WindCtx *ctx);
RList *windbg_list_modules(WindCtx *ctx);
int windbg_get_cpus(WindCtx *ctx);
bool windbg_set_cpu(WindCtx *ctx, int cpu);
int windbg_get_cpu(WindCtx *ctx);
WindCtx * windbg_ctx_new(void *io_ptr);
void windbg_ctx_free(WindCtx **ctx);
int windbg_wait_packet(WindCtx *ctx, const ut32 type, kd_packet_t **p);
int windbg_sync(WindCtx *ctx);
bool windbg_read_ver(WindCtx *ctx);
int windbg_continue(WindCtx *ctx);
bool windbg_write_reg(WindCtx *ctx, const uint8_t *buf, int size);
int windbg_read_reg(WindCtx *ctx, uint8_t *buf, int size);
int windbg_query_mem(WindCtx *ctx, const ut64 addr, int *address_space, int *flags);
int windbg_bkpt(WindCtx *ctx, const ut64 addr, const int set, const int hw, int *handle);
int windbg_read_at(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int windbg_read_at_uva(WindCtx *ctx, uint8_t *buf, ut64 offset, int count);
int windbg_read_at_phys(WindCtx *ctx, uint8_t *buf, const ut64 offset, const int count);
int windbg_write_at(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
int windbg_write_at_uva(WindCtx *ctx, const uint8_t *buf, ut64 offset, int count);
int windbg_write_at_phys(WindCtx *ctx, const uint8_t *buf, const ut64 offset, const int count);
bool windbg_va_to_pa(WindCtx *ctx, ut64 va, ut64 *pa);
void windbg_break(void *ctx);
int windbg_break_read(WindCtx *ctx);
bool windbg_lock_enter(WindCtx *ctx);
bool windbg_lock_leave(WindCtx *ctx);
bool windbg_lock_tryenter(WindCtx *ctx);
#endif
