/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_anal.h>

#include "bt/generic-x86.c"
#include "bt/generic-x64.c"
#include "bt/fuzzy-all.c"

typedef RList* (*RDebugFrameCallback)(RDebug *dbg, ut64 at);

static void prepend_current_pc (RDebug *dbg, RList *list) {
	RDebugFrame *frame;
	const char *pcname;
	if (list) {
		pcname = r_reg_get_name (dbg->reg, R_REG_NAME_PC);
		if (pcname) {
			ut64 addr = r_reg_getv (dbg->reg, pcname);
			frame = R_NEW0 (RDebugFrame);
			frame->addr = addr;
			frame->size = 0;
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
			if (dbg->bits == R_SYS_BITS_64) {
				cb = backtrace_x86_64_anal;
			} else {
				cb = backtrace_x86_32_anal;
			}
		}
	}
	if (!cb) {
		if (dbg->bits == R_SYS_BITS_64) {
			cb = backtrace_x86_64;
		} else {
			cb = backtrace_x86_32;
		}
	}

	RList *list;
	if (dbg->btalgo && !strcmp (dbg->btalgo, "trace")) {
		list = r_list_clone (dbg->call_frames);
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
