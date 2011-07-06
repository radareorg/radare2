/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_debug.h>

static int r_debug_rap_step(RDebug *dbg) {
	r_io_system (dbg->iob.io, "ds");
	return R_TRUE;
}

static int r_debug_rap_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	r_io_system (dbg->iob.io, "dr");
	return 0;
}

static int r_debug_rap_reg_write(int pid, int tid, int type, const ut8 *buf, int size) {
	return R_FALSE; // XXX Error check	
}

static int r_debug_rap_continue(RDebug *dbg, int pid, int tid, int sig) {
	r_io_system (dbg->iob.io, "dc");
	return R_TRUE;
}

static int r_debug_rap_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_rap_attach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
	RIODesc *d = dbg->iob.io->fd;
	if (d && d->plugin && d->plugin->name) {
		
		if (!strcmp ("rap", d->plugin->name)) {
			eprintf ("SUCCESS: rap attach with inferior rap rio worked\n");
		} else {
			eprintf ("ERROR: Underlaying IO descriptor is not a GDB one..\n");
		}
	}
	return R_TRUE;
}

static int r_debug_rap_detach(int pid) {
// XXX TODO PID must be a socket here !!1
//	close (pid);
	//XXX Maybe we should continue here?
	return R_TRUE;
}

static const char *r_debug_rap_reg_profile(RDebug *dbg) {
	r_io_system (dbg->iob.io, "drp");
	return NULL;
}

static int r_debug_rap_breakpoint (void *user, int type, ut64 addr, int hw, int rwx){
	//r_io_system (dbg->iob.io, "db");
	return R_FALSE;
}

struct r_debug_plugin_t r_debug_plugin_rap = {
	.name = "rap",
	/* TODO: Add support for more architectures here */
	.arch = 0xff,
	.bits = R_SYS_BITS_32,
	.init = NULL,
	.step = r_debug_rap_step,
	.cont = r_debug_rap_continue,
	.attach = &r_debug_rap_attach,
	.detach = &r_debug_rap_detach,
	.wait = &r_debug_rap_wait,
	.pids = NULL,
	.tids = NULL,
	.threads = NULL,
	.kill = NULL,
	.frames = NULL,
	.map_get = NULL,
	.breakpoint = &r_debug_rap_breakpoint,
	.reg_read = &r_debug_rap_reg_read,
	.reg_write = &r_debug_rap_reg_write,
	.reg_profile = (void *)r_debug_rap_reg_profile,
	//.bp_write = &r_debug_rap_bp_write,
	//.bp_read = &r_debug_rap_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_rap
};
#endif
