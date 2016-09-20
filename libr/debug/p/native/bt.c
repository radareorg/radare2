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

static RList *r_debug_native_frames(RDebug *dbg, ut64 at) {
	RList *list;
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

	list = cb (dbg, at);
	prepend_current_pc (dbg, list);

	return list;
}
