/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_debug.h>

struct bfvm_regs {
	ut32 pc;
	ut32 bp;
	ut32 sp;
};

static struct bfvm_regs r;

static int r_debug_bf_step(RDebug *dbg) {
eprintf ("BF STEP\n");
	r.pc++;
	return R_TRUE;
}


static int r_debug_bf_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	memcpy (buf, &r, sizeof (r));
	//r_io_system (dbg->iob.io, "dr");
	return sizeof (r);
}

static int r_debug_bf_reg_write(int pid, int tid, int type, const ut8 *buf, int size) {
	return R_FALSE; // XXX Error check	
}

static int r_debug_bf_continue(RDebug *dbg, int pid, int tid, int sig) {
	r_io_system (dbg->iob.io, "dc");
	return R_TRUE;
}

static int r_debug_bf_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_bf_attach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
	RIODesc *d = dbg->iob.io->fd;
	if (d && d->plugin && d->plugin->name) {
		if (!strcmp ("bf", d->plugin->name)) {
			eprintf ("SUCCESS: bf attach with inferior bf rio worked\n");
		} else {
			eprintf ("ERROR: Underlaying IO descriptor is not a GDB one..\n");
		}
	}
	return R_TRUE;
}

static int r_debug_bf_detach(int pid) {
// XXX TODO PID must be a socket here !!1
//	close (pid);
	//XXX Maybe we should continue here?
	return R_TRUE;
}

static char *r_debug_bf_reg_profile(RDebug *dbg) {
	return strdup (
	"=pc	pc\n"
	"=sp	sp\n"
	"=bp	bp\n"
	"gpr	pc	.32	0	0\n"
	"gpr	bp	.32	4	0\n"
	"gpr	sp	.32	8	0\n"
	);
}

static int r_debug_bf_breakpoint (void *user, int type, ut64 addr, int hw, int rwx){
	//r_io_system (dbg->iob.io, "db");
	return R_FALSE;
}

struct r_debug_plugin_t r_debug_plugin_bf = {
	.name = "bf",
	/* TODO: Add support for more architectures here */
	.arch = 0xff,
	.bits = R_SYS_BITS_32,
	.init = NULL,
	.step = r_debug_bf_step,
	.cont = r_debug_bf_continue,
	.attach = &r_debug_bf_attach,
	.detach = &r_debug_bf_detach,
	.wait = &r_debug_bf_wait,
	.pids = NULL,
	.tids = NULL,
	.threads = NULL,
	.kill = NULL,
	.frames = NULL,
	.map_get = NULL,
	.breakpoint = &r_debug_bf_breakpoint,
	.reg_read = &r_debug_bf_reg_read,
	.reg_write = &r_debug_bf_reg_write,
	.reg_profile = (void *)r_debug_bf_reg_profile,
	//.bp_write = &r_debug_bf_bp_write,
	//.bp_read = &r_debug_bf_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bf
};
#endif
