#include <r_anal.h>

#define MAXBT 128

#include "bt/generic-x86.c"
#include "bt/generic-x64.c"
#include "bt/fuzzy-all.c"

typedef RList* (*RDebugFrameCallback)(RDebug *dbg, ut64 at);

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
	if (cb == NULL) {
		if (dbg->bits == R_SYS_BITS_64) {
			cb = backtrace_x86_64;
		} else {
			cb = backtrace_x86_32;
		}
	}
	return cb (dbg, at);
}
