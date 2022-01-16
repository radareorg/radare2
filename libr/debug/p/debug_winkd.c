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
#include <winkd.h>
#include <kd.h>

static WindCtx *wctx = NULL;

static bool r_debug_winkd_step(RDebug *dbg) {
	return true;
}

static int r_debug_winkd_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int ret = winkd_read_reg(wctx, buf, size);
	if (!ret || size != ret) {
		return -1;
	}
	r_reg_read_regs (dbg->reg, buf, ret);
	// Report as if no register has been written as we've already updated the arena here
	return 0;
}

static int r_debug_winkd_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	if (!dbg->reg) {
		return false;
	}
	int arena_size;
	ut8 *arena = r_reg_get_bytes (dbg->reg, R_REG_TYPE_ALL, &arena_size);
	if (!arena) {
		eprintf ("Could not retrieve the register arena!\n");
		return false;
	}
	int ret = winkd_write_reg (wctx, arena, arena_size);
	free (arena);
	return ret;
}

static bool r_debug_winkd_continue(RDebug *dbg, int pid, int tid, int sig) {
	return winkd_continue (wctx);
}

static RDebugReasonType r_debug_winkd_wait(RDebug *dbg, int pid) {
	RDebugReasonType reason = R_DEBUG_REASON_UNKNOWN;
	kd_packet_t *pkt = NULL;
	kd_stc_64 *stc;
	winkd_lock_enter (wctx);
	for (;;) {
		void *bed = r_cons_sleep_begin ();
		int ret = winkd_wait_packet (wctx, KD_PACKET_TYPE_STATE_CHANGE64, &pkt);
		r_cons_sleep_end (bed);
		if (ret != KD_E_OK || !pkt) {
			reason = R_DEBUG_REASON_ERROR;
			break;
		}
		stc = (kd_stc_64 *) pkt->data;
		dbg->reason.addr = stc->pc;
		dbg->reason.tid = stc->kthread;
		dbg->reason.signum = stc->state;
		winkd_set_cpu (wctx, stc->cpu);
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
	winkd_lock_leave (wctx);
	free (pkt);
	return reason;
}

static bool r_debug_winkd_attach(RDebug *dbg, int pid) {
	RIODesc *desc = dbg->iob.io->desc;

	if (!desc || !desc->plugin || !desc->plugin->name || !desc->data) {
		return false;
	}
	if (strncmp (desc->plugin->name, "winkd", 6)) {
		return false;
	}
	if (dbg->arch && strcmp (dbg->arch, "x86")) {
		return false;
	}
	wctx = (WindCtx *)desc->data;

	// Handshake
	if (!winkd_sync (wctx)) {
		eprintf ("Could not connect to winkd\n");
		winkd_ctx_free ((WindCtx **)&desc->data);
		return false;
	}
	if (!winkd_read_ver (wctx)) {
		winkd_ctx_free ((WindCtx **)&desc->data);
		return false;
	}
	dbg->bits = winkd_get_bits (wctx);
	// Make r_debug_is_dead happy
	dbg->pid = 0;
	return true;
}

static bool r_debug_winkd_detach(RDebug *dbg, int pid) {
	eprintf ("Detaching...\n");
	return true;
}

static char *r_debug_winkd_reg_profile(RDebug *dbg) {
	r_return_val_if_fail (dbg, NULL);
	if (dbg->arch && strcmp (dbg->arch, "x86")) {
		return NULL;
	}
	r_debug_winkd_attach (dbg, 0);
	if (dbg->bits == R_SYS_BITS_32) {
#include "native/reg/windows-x86.h"
	} else if (dbg->bits == R_SYS_BITS_64) {
#include "native/reg/windows-x64.h"
	}
	return NULL;
}

static int r_debug_winkd_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	int *tag;
	if (!b) {
		return false;
	}
	// Use a 32 bit word here to keep this compatible with 32 bit hosts
	if (!b->data) {
		b->data = (char *)R_NEW0 (int);
		if (!b->data) {
			return 0;
		}
	}
	tag = (int *)b->data;
	return winkd_bkpt (wctx, b->addr, set, b->hw, tag);
}

static bool r_debug_winkd_init(RDebug *dbg) {
	return true;
}

static RList *r_debug_winkd_pids(RDebug *dbg, int pid) {
	RListIter *it;
	WindProc *p;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *pids = winkd_list_process(wctx);
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
	ut32 old = winkd_get_target (wctx);
	int ret = winkd_set_target (wctx, pid);
	if (!ret) {
		return false;
	}
	ut64 base = winkd_get_target_base (wctx);
	if (!base) {
		winkd_set_target (wctx, old);
		return false;
	}
	eprintf ("Process base is 0x%"PFMT64x"\n", base);
	return true;
}

static RList *r_debug_winkd_threads(RDebug *dbg, int pid) {
	RListIter *it;
	WindThread *t;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *threads = winkd_list_threads (wctx);
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
	RListIter *it;
	WindModule *m;

	RList *ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}

	RList *modules = winkd_list_modules (wctx);
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

RDebugPlugin r_debug_plugin_winkd = {
	.name = "winkd",
	.license = "LGPL3",
	.arch = "x86",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.init = &r_debug_winkd_init,
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
