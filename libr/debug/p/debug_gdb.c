/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_debug.h>
#include "libgdbwrap/include/gdbwrapper.h"
#include "libgdbwrap/gdbwrapper.c"

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

#define REGSIZE_X86 64
static int r_debug_gdb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	int i;
	// XXX: This is really broken. it only works for 32bit boxes and its hardcoded!
	// TODO: allow gdbwrap to read regs on own buffer
	ut8 *p = gdbwrap_readgenreg (desc);
	desc->reg_size = 4;
	for (i=0; i<(REGSIZE_X86/4); i++) {
		ut32 p = (ut32)gdbwrap_getreg (desc, i);
	//	eprintf ("%i %i %llx\n", i, i*4, p);
		memcpy (buf+(i*4), &p, sizeof (ut32));
	}
	return REGSIZE_X86;
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
	int arch = dbg->arch;
	switch (arch) {
	case R_SYS_ARCH_X86:
	case R_SYS_ARCH_ARM:
	case R_SYS_ARCH_SH:
		break;
	default:
		arch = R_SYS_ARCH;
		break;
	}
	switch (arch) {
	case R_SYS_ARCH_X86:
		return strdup (
		"=pc	eip\n"
		"=sp	esp\n"
		"=bp	ebp\n"
		"=a0	eax\n"
		"=a1	ebx\n"
		"=a2	ecx\n"
		"=a3	edi\n"
		"gpr	eax	.32	0	0\n"
		"gpr	ecx	.32	4	0\n"
		"gpr	edx	.32	8	0\n"
		"gpr	ebx	.32	12	0\n"
		"gpr	esp	.32	16	0\n"
		"gpr	ebp	.32	20	0\n"
		"gpr	esi	.32	24	0\n"
		"gpr	edi	.32	28	0\n"
		"gpr	eip	.32	32	0\n"
		"gpr	eflags	.32	36	0\n"
		"seg	cs	.32	40	0\n"
		"seg	ss	.32	44	0\n"
		"seg	ds	.32	48	0\n"
		"seg	es	.32	52	0\n"
		"seg	fs	.32	56	0\n"
		"seg	gs	.32	60	0\n"
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

struct r_debug_plugin_t r_debug_plugin_gdb = {
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
