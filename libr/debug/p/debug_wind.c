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

#include <r_asm.h>
#include <r_debug.h>
#include <wind.h>
#include <kd.h>

static WindCtx *wctx = NULL;

static int r_debug_wind_step (RDebug *dbg) {
	return R_TRUE;
}

static int r_debug_wind_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	(void)type;
	int ret;

	ret = wind_read_reg(wctx, buf, size);
	if (!ret || size != ret)
		return -1;

	r_reg_set_bytes (dbg->reg, R_REG_TYPE_ALL, buf, ret);

	// Report as if no register has been written as we've already updated the arena here
	return 0;
}

static int r_debug_wind_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	(void)buf;
	(void)size;
	ut8 *arena;
	int arena_size;
	int ret;

	if (!dbg->reg)
		return R_FALSE;

	arena = r_reg_get_bytes (dbg->reg, R_REG_TYPE_ALL, &arena_size);
	if (!arena) {
		eprintf ("Could not retrieve the register arena!\n");
		return R_FALSE;
	}

	ret = wind_write_reg(wctx, arena, arena_size);

	free (arena);

	return ret;
}

static int r_debug_wind_continue(RDebug *dbg, int pid, int tid, int sig) {
	return wind_continue(wctx);
}

static int r_debug_wind_wait (RDebug *dbg, int pid) {
	kd_packet_t *pkt;
	kd_stc_64 *stc;

	for (;;) {
		int ret = wind_wait_packet (wctx, KD_PACKET_TYPE_STATE_CHANGE, &pkt);
		if (ret != KD_E_OK || !pkt)
			break;

		stc = (kd_stc_64 *)pkt->data;

		// Handle exceptions only
		if (stc->state == 0x3030) {
			wind_set_cpu (wctx, stc->cpu);
			free (pkt);
			dbg->reason = R_DBG_REASON_INT;
			break;
		} else wind_continue (wctx);
		free(pkt);
	}

	// TODO : Set the faulty process as target

	return R_TRUE;
}

static int r_debug_wind_attach (RDebug *dbg, int pid) {
	RIODesc *desc = dbg->iob.io->desc;

	if (!desc || !desc->plugin || !desc->plugin->name || !desc->data)
		return R_FALSE;

	if (strncmp(desc->plugin->name, "windbg", 6))
		return R_FALSE;

	if (dbg->arch != R_SYS_ARCH_X86)
		return R_FALSE;

	wctx = (WindCtx *)desc->data;

	if (!wctx)
		return R_FALSE;

	// Handshake
	if (!wind_sync(wctx)) {
		eprintf("Could not connect to windbg\n");
		wind_ctx_free(wctx);
		return R_FALSE;
	}

	if (!wind_read_ver(wctx)) {
		wind_ctx_free(wctx);
		return R_FALSE;
	}

	// Make r_debug_is_dead happy
	dbg->pid = 0;

	return R_TRUE;
}

static int r_debug_wind_detach (int pid) {
	return R_TRUE;
}

static char *r_debug_wind_reg_profile(RDebug *dbg) {
	if (dbg->arch != R_SYS_ARCH_X86)
		return NULL;

	if (dbg->bits == R_SYS_BITS_32)
#include "native/reg-w32.h"
	if (dbg->bits == R_SYS_BITS_64)
#include "native/reg-w64.h"

	return NULL;
}

static int r_debug_wind_breakpoint (RBreakpointItem *bp, int set, void *user) {
	int *tag;

	if (!bp)
		return R_FALSE;

	// Use a 32 bit word here to keep this compatible with 32 bit hosts
	tag = (int *)&bp->data;

	return wind_bkpt(wctx, bp->addr, set, bp->hw, tag);
}

static int r_debug_wind_init(RDebug *dbg) {
	return R_TRUE;
}

static RList *r_debug_wind_pids (int pid) {
	RList *ret, *pids;
	RListIter *it;
	WindProc *p;

	ret = r_list_newf (free);
	if (!ret)
		return NULL;

	pids = wind_list_process(wctx);
	if (!pids)
		return ret;

	r_list_foreach(pids, it, p) {
		RDebugPid *newpid = R_NEW0 (RDebugPid);
		newpid->path = strdup (p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = R_TRUE;
		r_list_append (ret, newpid);
	}

	// r_list_free (pids);

	return ret;
}

static int r_debug_wind_select (int pid, int tid) {
	int ret;
	uint32_t old;
	ut64 base;

	old = wind_get_target (wctx);

	ret = wind_set_target (wctx, pid);
	if (!ret)
		return R_FALSE;

	base = wind_get_target_base (wctx);
	if (!base) {
		wind_set_target (wctx, old);
		return R_FALSE;
	}

	eprintf ("Process base is 0x%"PFMT64x"\n", base);

	return R_TRUE;
}

struct r_debug_plugin_t r_debug_plugin_wind = {
	.name = "wind",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_X86,
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.pids = r_debug_wind_pids,
	.select = r_debug_wind_select,
	.step = r_debug_wind_step,
	.init = r_debug_wind_init,
	.cont = r_debug_wind_continue,
	.attach = &r_debug_wind_attach,
	.detach = &r_debug_wind_detach,
	.wait = &r_debug_wind_wait,
	.breakpoint = &r_debug_wind_breakpoint,
	.reg_read = &r_debug_wind_reg_read,
	.reg_write = &r_debug_wind_reg_write,
	.reg_profile = r_debug_wind_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_wind
};
#endif
