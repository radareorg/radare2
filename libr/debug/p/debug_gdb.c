/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_debug.h>
#include "libgdbwrap/include/gdbwrapper.h"

/* XXX: hacky copypasta from io/p/io_gdb */
typedef struct {
        RSocket *fd;
        gdbwrap_t *desc;
} RIOGdb;
#define RIOGDB_FD(x) (((RIOGdb*)(x))->fd)
#define RIOGDB_DESC(x) (((RIOGdb*)(x->data))->desc)
#define RIOGDB_IS_VALID(x) (x && x->plugin==&r_io_plugin_gdb && x->data)
#define NUM_REGS 28

/* TODO: The IO stuff must be communicated with the r_dbg */
/* a transplant sometimes requires to change the IO */
/* so, for here, we need r_io_plugin_gdb */
/* TODO: rename to gdbwrap? */
static gdbwrap_t *desc = NULL;

static int r_debug_gdb_step(RDebug *dbg) {
	gdbwrap_stepi (desc);
	return R_TRUE;
}

static int r_debug_gdb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	ut8 *p = gdbwrap_readgenreg (desc);
	memcpy (buf, p, size);
	return size;
}

static int r_debug_gdb_reg_write(int pid, int tid, int type, const ut8 *buf, int size) {
	/* TODO */
	return R_TRUE;
}

static int r_debug_gdb_continue(RDebug *dbg, int pid, int tid, int sig) {
	gdbwrap_continue (desc);
	return R_TRUE;
}

static int r_debug_gdb_wait(int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_gdb_attach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
	RIODesc *d = dbg->iob.io->fd;
	if (d && d->plugin && d->plugin->name) {
		if (!strcmp ("gdb", d->plugin->name)) {
			RIOGdb *g = d->data;
			desc = g->desc;
			//desc = gdbwrap_init (pid , 9, 4); //Only x86
			eprintf ("SUCCESS: gdb attach with inferior gdb rio worked\n");
		} else {
			eprintf ("ERROR: Underlaying IO descriptor is not a GDB one..\n");
		}
	}
	return R_TRUE;
}

static int r_debug_gdb_detach(int pid) {
// XXX TODO PID must be a socket here !!1
//	close (pid);
	return R_TRUE;
}

static const char *r_debug_gdb_reg_profile(RDebug *dbg) {
	switch (dbg->arch) {
	case R_SYS_ARCH_X86:
		return strdup (
		"=pc	eip\n"
		"gpr	eip	.32	0	0\n"
		"gpr	eax	.32	8	0\n"
		);
	case R_SYS_ARCH_ARM:
		return strdup (
		"=pc	r15\n"
		"gpr	eip	.32	0	0\n"
		"gpr	eax	.32	8	0\n"
		);
	case R_SYS_ARCH_SH:
		return strdup (
		"=pc	r15\n"
		"gpr	eip	.32	0	0\n"
		"gpr	eax	.32	8	0\n"
		);
	}
	return NULL;
}

struct r_debug_plugin_t r_dbg_plugin_gdb = {
	.name = "gdb",
	/* TODO: Add support for more architectures here */
	.arch = R_SYS_ARCH_X86 | R_SYS_ARCH_ARM | R_SYS_ARCH_SH,
	.bits = R_SYS_BITS_32,
	.init = NULL,
	.step = r_debug_gdb_step,
	.cont = r_debug_gdb_continue,
	.attach = &r_debug_gdb_attach,
	.detach = &r_debug_gdb_detach,
	.wait = &r_debug_gdb_wait,
	.pids = NULL,
	.tids = NULL,
	.threads = NULL,
	.kill = NULL,
	.frames = NULL,
	.map_get = NULL,
	.breakpoint = NULL,
	.reg_read = &r_debug_gdb_reg_read,
	.reg_write = &r_debug_gdb_reg_write,
	.reg_profile = (void *)r_debug_gdb_reg_profile,
	//.bp_write = &r_debug_gdb_bp_write,
	//.bp_read = &r_debug_gdb_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_gdb
};
#endif
