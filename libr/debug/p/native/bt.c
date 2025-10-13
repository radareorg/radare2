/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_anal.h>

#include "bt/generic_x86.c"
#include "bt/generic_x64.c"
#include "bt/fuzzy_all.c"

typedef RList* (*RDebugFrameCallback)(RDebug *dbg, ut64 at);

static void prepend_current_pc(RDebug *dbg, RList *list) {
	R_RETURN_IF_FAIL (dbg);
	if (!list) {
		return;
	}
	ut64 addr = r_reg_getv (dbg->reg, "PC");
	if (addr != UT64_MAX) {
		RDebugFrame *frame = R_NEW0 (RDebugFrame);
		if (frame) {
			frame->addr = addr;
			frame->size = 0;
			frame->sp = r_reg_getv (dbg->reg, "SP");
			frame->bp = r_reg_getv (dbg->reg, "BP");
			r_list_prepend (list, frame);
		}
	}
}


#if HAVE_PTRACE
struct frames_proxy_args {
	RDebugFrameCallback cb;
	RDebug *dbg;
	ut64 at;
};

static void *backtrace_proxy(void *user) {
	struct frames_proxy_args *args = user;
	if (args->cb) {
		return args->cb (args->dbg, args->at);
	}
	return NULL;
}
#endif

static RList *r_debug_native_frames(RDebug *dbg, ut64 at) {
	RDebugFrameCallback cb = NULL;
	if (dbg->btalgo) {
		if (!strcmp (dbg->btalgo, "fuzzy")) {
			cb = backtrace_fuzzy;
		} else if (!strcmp (dbg->btalgo, "anal")) {
			if (R_SYS_BITS_CHECK (dbg->bits, 64)) {
				cb = backtrace_x86_64_anal;
			} else {
				cb = backtrace_x86_32_anal;
			}
		}
	}
	if (!cb) {
		if (R_SYS_BITS_CHECK (dbg->bits, 64)) {
			cb = backtrace_x86_64;
		} else {
			cb = backtrace_x86_32;
		}
	}

	RList *list;
	if (dbg->btalgo && !strcmp (dbg->btalgo, "trace")) {
		if (dbg->call_frames) {
			list = r_list_clone (dbg->call_frames, NULL);
		} else {
			list = r_list_newf (free);
		}
	} else {
#if HAVE_PTRACE
		struct frames_proxy_args args = { cb, dbg, at };
		list = r_debug_ptrace_func (dbg, backtrace_proxy, &args);
#else
		list = cb (dbg, at);
#endif
	}

	prepend_current_pc (dbg, list);
	return list;
}
