/* radare - LGPL - Copyright 2011-2024 - pancake */

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

typedef struct plugin_data_t {
	struct bfvm_regs r;
} PluginData;

static bool is_io_bf(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->meta.name) {
		if (!strcmp ("bfdbg", d->plugin->meta.name)) {
			return true;
		}
	}
	R_LOG_ERROR ("the iodesc data is not brainfuck friendly");
	return false;
}

static bool r_debug_bf_step_over(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	int op, oop = 0;
	for (;;) {
		op = bfvm_op (o->bfvm);
		if (oop != 0 && op != oop) {
			break;
		}
		if (bfvm_in_trap (o->bfvm)) {
			break;
		}
		bfvm_step (o->bfvm, 0);
		oop = op;
	}
	return true;
}

static bool r_debug_bf_step(RDebug *dbg) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_step (o->bfvm, 0);
	return true;
}

static bool r_debug_bf_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	R_RETURN_VAL_IF_FAIL (dbg && buf && size > 0, -1);
	if (!is_io_bf (dbg)) {
		return false;
	}
	if (!(dbg->iob.io) || !(dbg->iob.io->desc) || !(dbg->iob.io->desc->data)) {
		return false;
	}
	RIOBdescbg *o = dbg->iob.io->desc->data;
	if (o && dbg->current) {
		PluginData *pd = dbg->current->plugin_data;
		pd->r.pc = o->bfvm->eip;
		pd->r.ptr = o->bfvm->ptr;
		pd->r.sp = o->bfvm->esp;
		pd->r.scr = o->bfvm->screen;
		pd->r.scri = o->bfvm->screen_idx;
		pd->r.inp = o->bfvm->input;
		pd->r.inpi = o->bfvm->input_idx;
		pd->r.mem = o->bfvm->base;
		pd->r.memi = o->bfvm->ptr;
		memcpy (buf, &pd->r, sizeof (pd->r));
	}
	//r_io_system (dbg->iob.io, "dr");
	return true; // sizeof (r);
}

static bool r_debug_bf_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	R_RETURN_VAL_IF_FAIL (dbg, false);
	if (!is_io_bf (dbg)) {
		return 0;
	}
	if (!(dbg->iob.io) || !(dbg->iob.io->desc) || !(dbg->iob.io->desc->data)) {
		return 0;
	}
	RIOBdescbg *o = dbg->iob.io->desc->data;
	if (o && dbg->current) {
		PluginData *pd = dbg->current->plugin_data;
		memcpy (&pd->r, buf, sizeof (pd->r));
		o->bfvm->eip = pd->r.pc;
		o->bfvm->ptr = pd->r.ptr; // dup
		o->bfvm->esp = pd->r.sp;
		o->bfvm->screen = pd->r.scr;
		o->bfvm->screen_idx = pd->r.scri;
		o->bfvm->input = pd->r.inp;
		o->bfvm->input_idx = pd->r.inpi;
		o->bfvm->base = pd->r.mem;
		o->bfvm->ptr = pd->r.memi; // dup
	}
	return true;
}

static bool r_debug_bf_continue(RDebug *dbg, int pid, int tid, int sig) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_cont (o->bfvm, UT64_MAX);
	return true;
}

static bool r_debug_bf_continue_syscall(RDebug *dbg, int pid, int num) {
	RIOBdescbg *o = dbg->iob.io->desc->data;
	bfvm_contsc (o->bfvm);
	return true;
}

static RDebugReasonType r_debug_bf_wait(RDebug *dbg, int pid) {
	return R_DEBUG_REASON_NONE;
}

static bool r_debug_bf_attach(RDebug *dbg, int pid) {
	if (!is_io_bf (dbg)) {
		return false;
	}
	return true;
}

static bool r_debug_bf_detach(RDebug *dbg, int pid) {
	// reset vm?
	return true;
}

static char *r_debug_bf_reg_profile(RDebug *dbg) {
	return strdup (
	"=PC	pc\n"
	"=SP	esp\n"
	"=BP	ptr\n"
	"=A0	mem\n"
	"gpr	pc	.32	0	0\n"
	"gpr	ptr	.32	4	0\n"
	"gpr	esp	.32	8	0\n"
	"gpr	scr	.32	12	0\n"
	"gpr	scri	.32	16	0\n"
	"gpr	inp	.32	20	0\n"
	"gpr	inpi	.32	24	0\n"
	"gpr	mem	.32	28	0\n"
	"gpr	memi	.32	32	0\n"
	"gpr	brk	.32	36	0\n"
	"gpr	kbd	.32	40	0\n"
	);
}

static int r_debug_bf_breakpoint(struct r_bp_t *bp, RBreakpointItem *b, bool set) {
	//r_io_system (dbg->iob.io, "db");
	return false;
}

static bool r_debug_bf_kill(RDebug *dbg, int pid, int tid, int sig) {
	if (!is_io_bf (dbg)) {
		return false;
	}
	RIOBdescbg *o = dbg->iob.io->desc->data;
	if (o) {
		bfvm_reset (o->bfvm);
	}
	return true;
}

static RList *r_debug_native_map_get(RDebug *dbg) {
	if (!is_io_bf (dbg)) {
		return false;
	}
	RIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	RList *list = r_list_newf ((RListFree)r_debug_map_free);
	if (!list) {
		return NULL;
	}
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

static bool r_debug_bf_stop(RDebug *dbg) {
	if (!is_io_bf (dbg)) {
		return false;
	}
	RIOBdescbg *o = dbg->iob.io->desc->data;
	BfvmCPU *c = o->bfvm;
	c->breaked = true;
	return true;
}

static bool init_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);

	ds->plugin_data = R_NEW0 (PluginData);
	return !!ds->plugin_data;
}

static bool fini_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);

	if (!ds->plugin_data) {
		return false;
	}

	R_FREE (ds->plugin_data);
	return true;
}

RDebugPlugin r_debug_plugin_bf = {
	.meta = {
		.name = "bf",
		.author = "pancake",
		.desc = "BF debug plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "bf",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.init_plugin = init_plugin,
	.fini_plugin = fini_plugin,
	.step = r_debug_bf_step,
	.step_over = r_debug_bf_step_over,
	.cont = r_debug_bf_continue,
	.contsc = r_debug_bf_continue_syscall,
	.attach = &r_debug_bf_attach,
	.detach = &r_debug_bf_detach,
	.wait = &r_debug_bf_wait,
	.stop = r_debug_bf_stop,
	.kill = r_debug_bf_kill,
	.breakpoint = &r_debug_bf_breakpoint,
	.reg_read = &r_debug_bf_reg_read,
	.reg_write = &r_debug_bf_reg_write,
	.reg_profile = r_debug_bf_reg_profile,
	.map_get = r_debug_native_map_get,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bf,
	.version = R2_VERSION
};
#endif
