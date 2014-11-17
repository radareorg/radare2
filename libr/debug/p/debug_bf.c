/* radare - LGPL - Copyright 2011-2014 - pancake */

#include <r_asm.h>
#include <r_debug.h>
#undef R_API
#define R_API static inline
#include "bfvm.c"

typedef struct {
        int desc;
        ut8 *buf;
        ut32 size;
        BfvmCPU *bfvm;
} RIOBdescbg;

struct bfvm_regs {
	ut32 pc;
	ut32 ptr;
	ut32 sp;
	ut32 scr;
	ut32 scri;
	ut32 inp;
	ut32 inpi;
	ut32 mem;
	ut32 memi;
};

static struct bfvm_regs r;

static int is_io_bf(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name)
		if (!strcmp ("bdescbg", d->plugin->name))
			return R_TRUE;
	return R_FALSE;
}

static int r_debug_bf_step_over(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	int op, oop = 0;
	for (;;) {
		op = bfvm_op (o->bfvm);
		if (oop != 0 && op != oop)
			break;
		if (bfvm_in_trap (o->bfvm))
			break;
		bfvm_step (o->bfvm, 0);
		oop = op;
	}
	return R_TRUE;
}

static int r_debug_bf_step(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_step (o->bfvm, 0);
	return R_TRUE;
}

static int r_debug_bf_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	RIOBdescbg *o;
	if (!dbg)
		return R_FALSE;
	if (!is_io_bf (dbg))
		return 0;
	if (!(dbg->iob.io) || !(dbg->iob.io->desc) || !(dbg->iob.io->desc->data))
		return 0;
	o = dbg->iob.io->desc->data;
	r.pc = o->bfvm->eip;
	r.ptr = o->bfvm->ptr;
	r.sp = o->bfvm->esp;
	r.scr = o->bfvm->screen;
	r.scri = o->bfvm->screen_idx;
	r.inp = o->bfvm->input;
	r.inpi = o->bfvm->input_idx;
	r.mem = o->bfvm->base;
	r.memi = o->bfvm->ptr;
	memcpy (buf, &r, sizeof (r));
	//r_io_system (dbg->iob.io, "dr");
	return sizeof (r);
}

static int r_debug_bf_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	RIOBdescbg *o;
	if (!dbg)
		return R_FALSE;
	if (!is_io_bf (dbg))
		return 0;
	if (!(dbg->iob.io) || !(dbg->iob.io->desc) || !(dbg->iob.io->desc->data))
		return 0;
	o = dbg->iob.io->desc->data;
	memcpy (&r, buf, sizeof (r));
	o->bfvm->eip = r.pc;
	o->bfvm->ptr = r.ptr; // dup
	o->bfvm->esp = r.sp;
	o->bfvm->screen = r.scr;
	o->bfvm->screen_idx = r.scri;
	o->bfvm->input = r.inp;
	o->bfvm->input_idx = r.inpi;
	o->bfvm->base = r.mem;
	o->bfvm->ptr = r.memi; // dup
	return R_TRUE;
}

static int r_debug_bf_continue(RDebug *dbg, int pid, int tid, int sig) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_cont (o->bfvm, UT64_MAX);
	return R_TRUE;
}

static int r_debug_bf_continue_syscall(RDebug *dbg, int pid, int num) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_contsc (o->bfvm);
	return R_TRUE;
}

static int r_debug_bf_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_bf_attach(RDebug *dbg, int pid) {
	if (!is_io_bf (dbg))
		return R_FALSE;
#if 0
	RIOBdescbg *o;
	o = dbg->iob.io->desc->data;
eprintf ("base = %llx\n", o->bfvm->base);
eprintf ("screen = %llx\n", o->bfvm->screen);
eprintf ("input = %llx\n", o->bfvm->input);
#endif
	return R_TRUE;
}

static int r_debug_bf_detach(int pid) {
	// reset vm?
	return R_TRUE;
}

static char *r_debug_bf_reg_profile(RDebug *dbg) {
	return strdup (
	"=pc	pc\n"
	"=sp	esp\n"
	"=bp	ptr\n"
	"gpr	pc	.32	0	0\n"
	"gpr	ptr	.32	4	0\n"
	"gpr	esp	.32	8	0\n"
	"gpr	scr	.32	12	0\n"
	"gpr	scri	.32	16	0\n"
	"gpr	inp	.32	20	0\n"
	"gpr	inpi	.32	24	0\n"
	"gpr	mem	.32	28	0\n"
	"gpr	memi	.32	32	0\n"
	);
}

static int r_debug_bf_breakpoint (RBreakpointItem *bp, int set, void *user) {
	//r_io_system (dbg->iob.io, "db");
	return R_FALSE;
}

static int r_debug_bf_kill(RDebug *dbg, int pid, int tid, int sig) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_reset (o->bfvm);
	return R_TRUE;
}

static RList *r_debug_native_map_get(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	RList *list = r_list_new ();
	list->free = (RListFree)r_debug_map_free;
	r_list_append (list, r_debug_map_new (
		"code", 0, 4096, 6, 0));
	r_list_append (list, r_debug_map_new (
		"memory", c->base, c->base+c->size, 6, 0));
	r_list_append (list, r_debug_map_new (
		"screen", c->screen, c->screen+c->screen_size, 6, 0));
	r_list_append (list, r_debug_map_new (
		"input", c->input, c->input+c->input_size, 6, 0));
	return list;
}

static int r_debug_bf_stop(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	c->breaked = R_TRUE;
	return R_TRUE;
}

RDebugPlugin r_debug_plugin_bf = {
	.name = "bf",
	.license = "LGPL3",
	/* TODO: Add support for more architectures here */
	.arch = R_ASM_ARCH_BF,
	.bits = R_SYS_BITS_32,
	.init = NULL,
	.step = r_debug_bf_step,
	.step_over = r_debug_bf_step_over,
	.cont = r_debug_bf_continue,
	.contsc = r_debug_bf_continue_syscall,
	.attach = &r_debug_bf_attach,
	.detach = &r_debug_bf_detach,
	.wait = &r_debug_bf_wait,
	.pids = NULL,
	.stop = r_debug_bf_stop,
	.tids = NULL,
	.threads = NULL,
	.kill = r_debug_bf_kill,
	.frames = NULL,
	.breakpoint = &r_debug_bf_breakpoint,
	.reg_read = &r_debug_bf_reg_read,
	.reg_write = &r_debug_bf_reg_write,
	.reg_profile = r_debug_bf_reg_profile,
	.map_get = r_debug_native_map_get,
//	.breakpoint = r_debug_native_bp,
	//.ptr_write = &r_debug_bf_ptr_write,
	//.ptr_read = &r_debug_bf_ptr_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bf
};
#endif
