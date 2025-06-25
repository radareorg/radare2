/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_debug.h>
#include <r_core.h>

static bool __rap_step(RDebug *dbg) {
	r_io_system (dbg->iob.io, "ds");
	return true;
}

static bool __rap_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	r_io_system (dbg->iob.io, "dr");
	return true;
}

static bool __rap_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	return false; // XXX Error check
}

static bool __rap_continue(RDebug *dbg, int pid, int tid, int sig) {
	r_io_system (dbg->iob.io, "dc");
	return true;
}

static RDebugReasonType __rap_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return true;
}

static bool __rap_attach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->meta.name) {
		if (!strcmp ("rap", d->plugin->meta.name)) {
			eprintf ("SUCCESS: rap attach with inferior rap rio worked\n");
		} else {
			R_LOG_ERROR ("Underlying IO descriptor is not a rap one");
		}
	}
	return true;
}

static bool __rap_detach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
//	close (pid);
	//XXX Maybe we should continue here?
	return true;
}

static char *__rap_reg_profile(RDebug *dbg) {
	RCons *cons = ((RCore*)dbg->coreb.core)->cons;
	char *out, *tf = r_file_temp ("rap.XXXXXX");
	int fd = r_cons_pipe_open (cons, tf, 1, 0);
	r_io_system (dbg->iob.io, "drp");
	r_cons_flush (cons);
	r_cons_pipe_close (cons, fd);
	out = r_file_slurp (tf, NULL);
	r_file_rm (tf);
	free (tf);
	return out;
}

static int __rap_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	//r_io_system (dbg->iob.io, "db");
	return false;
}

RDebugPlugin r_debug_plugin_rap = {
	.meta = {
		.name = "rap",
		.author = "pancake",
		.desc = "rap debug plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "any",
	.bits = R_SYS_BITS_PACK (32),
	.step = __rap_step,
	.cont = __rap_continue,
	.attach = &__rap_attach,
	.detach = &__rap_detach,
	.wait = &__rap_wait,
	.breakpoint = __rap_breakpoint,
	.reg_read = &__rap_reg_read,
	.reg_write = &__rap_reg_write,
	.reg_profile = (void *)__rap_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_rap,
	.version = R2_VERSION
};
#endif
