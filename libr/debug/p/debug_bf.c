/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_asm.h>
#include <r_debug.h>
#include "bfvm.h"
#include "bfvm.c"

typedef struct {
        int fd;
        ut8 *buf;
        ut32 size;
        BfvmCPU *bfvm;
} RIOBfdbg;

struct bfvm_regs {
	ut32 pc;
	ut32 bp;
	ut32 sp;
};

static struct bfvm_regs r;

static int is_io_bf(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->fd;
	if (d && d->plugin && d->plugin->name)
		if (!strcmp ("bfdbg", d->plugin->name))
			return R_TRUE;
	return R_FALSE;
}

static int r_debug_bf_step(RDebug *dbg) {
	RIOBfdbg *o = dbg->iob.io->fd->data;
	bfvm_step (o->bfvm, 0);
	return R_TRUE;
}

static int r_debug_bf_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	RIOBfdbg *o;
	if (!is_io_bf (dbg))
		return 0;
	if (!dbg || !(dbg->iob.io) || !(dbg->iob.io->fd) || !(dbg->iob.io->fd->data))
		return 0;
	o = dbg->iob.io->fd->data;
	r.pc = o->bfvm->eip;
	r.bp = o->bfvm->ptr;
	r.sp = o->bfvm->esp;
	memcpy (buf, &r, sizeof (r));
	//r_io_system (dbg->iob.io, "dr");
	return sizeof (r);
}

static int r_debug_bf_reg_write(int pid, int tid, int type, const ut8 *buf, int size) {
	memcpy (&r, buf, sizeof (r));
	// TODO: set vm regs from internal struct
	return R_FALSE; // XXX Error check	
}

static int r_debug_bf_continue(RDebug *dbg, int pid, int tid, int sig) {
	// bfvm_continue (bfvm);
	return R_TRUE;
}

static int r_debug_bf_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_bf_attach(RDebug *dbg, int pid) {
	return is_io_bf (dbg);
}

static int r_debug_bf_detach(int pid) {
	// reset vm?
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

static int r_debug_bf_breakpoint (void *user, int type, ut64 addr, int hw, int rwx) {
	//r_io_system (dbg->iob.io, "db");
	return R_FALSE;
}

struct r_debug_plugin_t r_debug_plugin_bf = {
	.name = "bf",
	/* TODO: Add support for more architectures here */
	.arch = R_ASM_ARCH_BF,
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
	.map_get = NULL, // TODO ?
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
