/* radare - LGPL - Copyright 2013 pancake <pancake@nopcode.org> */
// r2 -Desil ls

#include <r_asm.h>
#include <r_debug.h>

static int is_io_esil(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name)
		if (!strcmp ("esil", d->plugin->name))
			return R_TRUE;
	return R_FALSE;
}

static int r_debug_esil_step_over(RDebug *dbg) {
	eprintf ("TODO: ESIL STEP OVER\n");
	return R_TRUE;
}

static int r_debug_esil_step(RDebug *dbg) {
	int oplen;
	ut8 buf[64];
	ut64 pc = 0LL; // getreg("pc")
	RAnalOp op;

	pc = r_debug_reg_get (dbg, "pc");
/// XXX. hack to trick vaddr issue
//pc = 0x100001478;
//pc = r_io_section_vaddr_to_offset (dbg->iob.io, pc);
memset (buf, 0, sizeof (buf));
	dbg->iob.read_at (dbg->iob.io, pc, buf, 64);
eprintf ("READ 0x%08"PFMT64x" %02x %02x %02x\n", pc, buf[0], buf[1], buf[2]);
	oplen = r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
	if (oplen>0) {
		if (*R_STRBUF_SAFEGET (&op.esil)) {
			eprintf ("ESIL: %s\n", R_STRBUF_SAFEGET (&op.esil));
		}
	}
	eprintf ("TODO: ESIL STEP\n");
	return R_TRUE;
}

static int r_debug_esil_init(RDebug *dbg) {
	dbg->tid = dbg->pid = 1;
	eprintf ("TODO: ESIL INIT\n");
	return R_TRUE;
}

static int r_debug_esil_continue(RDebug *dbg, int pid, int tid, int sig) {
	eprintf ("ESIL continue\n");
	return R_TRUE;
}

static int r_debug_esil_continue_syscall(RDebug *dbg, int pid, int num) {
	eprintf ("ESIL continue until syscall\n");
	return R_TRUE;
}

static int r_debug_esil_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_esil_attach(RDebug *dbg, int pid) {
	eprintf ("OK attach\n");
	return R_TRUE;
	if (!is_io_esil (dbg))
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

static int r_debug_esil_detach(int pid) {
	// reset vm?
	return R_TRUE;
}

static char *r_debug_esil_reg_profile(RDebug *dbg) {
	eprintf ("TODO: esil %s\n", r_sys_arch_str (dbg->arch));
	return strdup (
	"=pc	pc\n"
	"=sp	esp\n"
	"=bp	ptr\n"
	"gpr	rax	.32	0	0\n"
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

static int r_debug_esil_breakpoint (RBreakpointItem *bp, int set, void *user) {
	//r_io_system (dbg->iob.io, "db");
	return R_FALSE;
}

static int r_debug_esil_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: ESIL reset
	return R_TRUE;
}

static int r_debug_esil_stop(RDebug *dbg) {
	eprintf ("ESIL: stop\n");
	return R_TRUE;
}

RDebugPlugin r_debug_plugin_esil = {
	.name = "esil",
	.license = "LGPL3",
	/* TODO: Add support for more architectures here */
	.arch = R_ASM_ARCH_BF,
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.init = r_debug_esil_init,
	.step = r_debug_esil_step,
	.step_over = r_debug_esil_step_over,
	.cont = r_debug_esil_continue,
	.contsc = r_debug_esil_continue_syscall,
	.attach = &r_debug_esil_attach,
	.detach = &r_debug_esil_detach,
	.wait = &r_debug_esil_wait,
	.pids = NULL,
	.stop = r_debug_esil_stop,
	.tids = NULL,
	.threads = NULL,
	.kill = r_debug_esil_kill,
	.frames = NULL,
	.breakpoint = &r_debug_esil_breakpoint,
	.reg_read = NULL, // &r_debug_esil_reg_read,
	.reg_write = NULL, //&r_debug_esil_reg_write,
	.reg_profile = r_debug_esil_reg_profile,
	.map_get = NULL, //r_debug_native_map_get,
//	.breakpoint = r_debug_native_bp,
	//.ptr_write = &r_debug_esil_ptr_write,
	//.ptr_read = &r_debug_esil_ptr_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_esil
};
#endif
