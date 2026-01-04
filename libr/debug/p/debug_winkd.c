// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3

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
#include <r_core.h>
#include <winkd.h>
#include <kd.h>

typedef struct plugin_data_t {
	WindCtx *wctx;
} PluginData;

static bool r_debug_winkd_step(RDebug *dbg) {
	return true;
}

static bool r_debug_winkd_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}

	int ret = winkd_read_reg (pd->wctx, buf, size);
	if (!ret || size != ret) {
		return false;
	}

	r_reg_read_regs (dbg->reg, buf, ret);
	// Report as if no register has been written as we've already updated the arena here
	return true;
}

static bool r_debug_winkd_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd || !dbg->reg) {
		return false;
	}
	int arena_size;
	ut8 *arena = r_reg_get_bytes (dbg->reg, R_REG_TYPE_ALL, &arena_size);
	if (!arena) {
		R_LOG_ERROR ("Could not retrieve the register arena");
		return false;
	}
	bool res = winkd_write_reg (pd->wctx, arena, arena_size);
	free (arena);
	return res;
}

static bool r_debug_winkd_continue(RDebug *dbg, int pid, int tid, int sig) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}
	return winkd_continue (pd->wctx);
}

static RDebugReasonType r_debug_winkd_wait(RDebug *dbg, int pid) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return 0;
	}
	RCore *core = dbg->coreb.core;

	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	kd_packet_t *pkt = NULL;
	kd_stc_64 *stc;
	winkd_lock_enter (pd->wctx);
	for (;;) {
		void *bed = r_cons_sleep_begin (core->cons);
		int ret = winkd_wait_packet (pd->wctx, KD_PACKET_TYPE_STATE_CHANGE64, &pkt);
		r_cons_sleep_end (core->cons, bed);
		if (ret != KD_E_OK || !pkt) {
			reason = R_DEBUG_REASON_ERROR;
			break;
		}
		stc = (kd_stc_64 *) pkt->data;
		dbg->reason.addr = stc->pc;
		dbg->reason.tid = stc->kthread;
		dbg->reason.signum = stc->state;
		winkd_set_cpu (pd->wctx, stc->cpu);
		if (stc->state == DbgKdExceptionStateChange) {
			dbg->reason.type = R_DEBUG_REASON_INT;
			reason = R_DEBUG_REASON_INT;
			break;
		} else if (stc->state == DbgKdLoadSymbolsStateChange) {
			dbg->reason.type = R_DEBUG_REASON_NEW_LIB;
			reason = R_DEBUG_REASON_NEW_LIB;
			break;
		}
		R_FREE (pkt);
	}
	winkd_lock_leave (pd->wctx);
	free (pkt);
	return reason;
}

static bool r_debug_winkd_attach(RDebug *dbg, int pid) {
	RIODesc *desc = dbg->iob.io->desc;

	if (!desc || !desc->plugin || !desc->plugin->meta.name || !desc->data) {
		return false;
	}
	if (!r_str_startswith (desc->plugin->meta.name, "winkd")) {
		return false;
	}
	if (dbg->arch && strcmp (dbg->arch, "x86")) {
		return false;
	}
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}

	pd->wctx = desc->data;
	pd->wctx->mb = &dbg->mb;

	// Handshake
	if (!winkd_sync (pd->wctx)) {
		R_LOG_ERROR ("Could not connect to winkd");
		winkd_ctx_free ((WindCtx **)&desc->data);
		return false;
	}
	if (!winkd_read_ver (pd->wctx)) {
		winkd_ctx_free ((WindCtx **)&desc->data);
		return false;
	}
	dbg->bits = winkd_get_bits (pd->wctx);
	// Make r_debug_is_dead happy
	dbg->pid = 0;
	return true;
}

static bool r_debug_winkd_detach(RDebug *dbg, int pid) {
	eprintf ("Detaching...\n");
	return true;
}

static char *r_debug_winkd_reg_profile(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg, NULL);
	if (dbg->arch && strcmp (dbg->arch, "x86")) {
		return NULL;
	}
	r_debug_winkd_attach (dbg, 0);
	if (R_SYS_BITS_CHECK (dbg->bits, 64)) {
#include "native/reg/windows-x64.h"
	} else if (R_SYS_BITS_CHECK (dbg->bits, 32)) {
#include "native/reg/windows-x86.h"
	}
	return NULL;
}

static int r_debug_winkd_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	RDebug *dbg = bp->user;
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd || !b) {
		return false;
	}
	// Use a 32 bit word here to keep this compatible with 32 bit hosts
	if (!b->data) {
		b->data = (char *)R_NEW0 (int);
		if (!b->data) {
			return 0;
		}
	}
	int *tag = (int *) b->data;
	return winkd_bkpt (pd->wctx, b->addr, set, b->hw, tag);
}

static bool r_debug_winkd_init(RDebug *dbg) {
	return true;
}

static RList *r_debug_winkd_pids(RDebug *dbg, int pid) {
	RListIter *it;
	WindProc *p;

	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return NULL;
	}

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *pids = winkd_list_process(pd->wctx);
	if (!pids) {
		return ret;
	}
	r_list_foreach (pids, it, p) {
		RDebugPid *newpid = R_NEW0 (RDebugPid);
		if (!newpid) {
			r_list_free (ret);
			return NULL;
		}
		newpid->path = strdup (p->name);
		newpid->pid = p->uniqueid;
		newpid->status = 's';
		newpid->runnable = true;
		r_list_append (ret, newpid);
	}
	// r_list_free (pids);
	return ret;
}

static bool r_debug_winkd_select(RDebug *dbg, int pid, int tid) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}

	ut32 old = winkd_get_target (pd->wctx);
	int ret = winkd_set_target (pd->wctx, pid);
	if (!ret) {
		return false;
	}
	ut64 base = winkd_get_target_base (pd->wctx);
	if (!base) {
		winkd_set_target (pd->wctx, old);
		return false;
	}
	eprintf ("Process base is 0x%"PFMT64x"\n", base);
	return true;
}

static RList *r_debug_winkd_threads(RDebug *dbg, int pid) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return NULL;
	}

	RListIter *it;
	WindThread *t;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *threads = winkd_list_threads (pd->wctx);
	if (!threads) {
		r_list_free (ret);
		return NULL;
	}

	r_list_foreach (threads, it, t) {
		RDebugPid *newpid = R_NEW0 (RDebugPid);
		if (!newpid) {
			r_list_free (ret);
			return NULL;
		}
		newpid->pid = t->uniqueid;
		newpid->status = t->status;
		newpid->runnable = t->runnable;
		r_list_append (ret, newpid);
	}

	return ret;
}

static RList *r_debug_winkd_modules(RDebug *dbg) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return NULL;
	}

	RListIter *it;
	WindModule *m;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *modules = winkd_list_modules (pd->wctx);
	if (!modules) {
		r_list_free (ret);
		return NULL;
	}

	r_list_foreach (modules, it, m) {
		RDebugMap *mod = R_NEW0 (RDebugMap);
		if (!mod) {
			r_list_free (modules);
			r_list_free (ret);
			return NULL;
		}
		mod->file = m->name;
		mod->size = m->size;
		mod->addr = m->addr;
		mod->addr_end = m->addr + m->size;
		r_list_append (ret, mod);
	}

	r_list_free (modules);
	return ret;
}

static bool init_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);
	ds->plugin_data = R_NEW0 (PluginData);
	return !!ds->plugin_data;
}

static bool fini_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);

	if (!ds->plugin_data) {
		return false;
	}

	R_FREE (ds->plugin_data);
	return true;
}

RDebugPlugin r_debug_plugin_winkd = {
	.meta = {
		.name = "winkd",
		.author = "The Lemon Man",
		.desc = "winkd debug plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.init_plugin = init_plugin,
	.fini_plugin = fini_plugin,
	.init_debugger = &r_debug_winkd_init,
	.step = &r_debug_winkd_step,
	.cont = &r_debug_winkd_continue,
	.attach = &r_debug_winkd_attach,
	.detach = &r_debug_winkd_detach,
	.pids = &r_debug_winkd_pids,
	.wait = &r_debug_winkd_wait,
	.select = &r_debug_winkd_select,
	.breakpoint = r_debug_winkd_breakpoint,
	.reg_read = &r_debug_winkd_reg_read,
	.reg_write = &r_debug_winkd_reg_write,
	.reg_profile = &r_debug_winkd_reg_profile,
	.threads = &r_debug_winkd_threads,
	.modules_get = &r_debug_winkd_modules
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_winkd,
	.version = R2_VERSION
};
#endif
