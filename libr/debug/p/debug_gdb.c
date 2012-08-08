/* radare - LGPL - Copyright 2009-2012 - pancake */

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

#define UNKNOWN -1
#define UNSUPPORTED 0
#define SUPPORTED 1

/* TODO: The IO stuff must be communicated with the r_dbg */
/* a transplant sometimes requires to change the IO */
/* so, for here, we need r_io_plugin_gdb */
/* TODO: rename to gdbwrap? */
static gdbwrap_t *desc = NULL;
static int support_sw_bp = UNKNOWN; 
static int support_hw_bp = UNKNOWN;

static int r_debug_gdb_step(RDebug *dbg) {
	gdbwrap_stepi (desc);
	return R_TRUE;
}

static int r_debug_gdb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	gdbwrap_readgenreg (desc);
	if (!desc)
		return R_FALSE;
	gdbwrap_getreg_buffer (desc, buf, desc->reg_size*desc->num_registers);
	return desc->num_registers*desc->reg_size;
}

static int r_debug_gdb_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	gdbwrap_setreg_buffer (desc, buf, desc->reg_size*desc->num_registers);
	gdbwrap_shipallreg (desc);
	return R_TRUE; // XXX Error check	
}

static int r_debug_gdb_continue(RDebug *dbg, int pid, int tid, int sig) {
	gdbwrap_continue (desc);
	return R_TRUE;
}

static int r_debug_gdb_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}

static int r_debug_gdb_attach(RDebug *dbg, int pid) {
// XXX TODO PID must be a socket here !!1
	RIODesc *d = dbg->iob.io->fd;
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("gdb", d->plugin->name)) {
			RIOGdb *g = d->data;
			support_sw_bp = UNKNOWN;
			support_hw_bp = UNKNOWN;
			if (( desc = g->desc ))
			switch (dbg->arch) {
			case R_SYS_ARCH_X86:
				//TODO Support x86_64
				//9 32bit regs for x86
				desc->num_registers = 9;
				desc->reg_size = 4;
				break;
			case R_SYS_ARCH_SH:
				//28 32bit regs for sh4
				desc->num_registers = 28;
				desc->reg_size = 4;
				break;
			case R_SYS_ARCH_ARM:
				//TODO Check ARM stubs and fill in
				desc->num_registers = 25;
				desc->reg_size = 4;
				break;
			}
			//eprintf ("SUCCESS: gdb attach with inferior gdb rio worked\n");
		} else {
			eprintf ("ERROR: Underlaying IO descriptor is not a GDB one..\n");
		}
	}
	return R_TRUE;
}

static int r_debug_gdb_detach(int pid) {
// XXX TODO PID must be a socket here !!1
//	close (pid);
	//XXX Maybe we should continue here?
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
		arch = r_sys_arch_id (R_SYS_ARCH);
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
			"=sp	r14\n" // XXX
			"=a0	r0\n"
			"=a1	r1\n"
			"=a2	r2\n"
			"=a3	r3\n"
			"gpr	lr	.32	56	0\n" // r14
			"gpr	pc	.32	60	0\n" // r15
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	f0	.32	64	0\n"
			"gpr	f1	.32	68	0\n"
			"gpr	f2	.32	72	0\n"
			"gpr	f3	.32	76	0\n"
			"gpr	f4	.32	80	0\n"
			"gpr	f5	.32	84	0\n"
			"gpr	f6	.32	88	0\n"
			"gpr	f7	.32	92	0\n"
			"gpr	fps	.32	96	0\n"
			"gpr	cpsr	.32	100	0\n"
		);
	case R_SYS_ARCH_SH:
		return strdup (
			"=pc    pc\n"
			"=sp    r15\n"
			"=bp    r14\n"
			"gpr	r0	.32	0	0\n"
			"gpr	r1	.32	4	0\n"
			"gpr	r2	.32	8	0\n"
			"gpr	r3	.32	12	0\n"
			"gpr	r4	.32	16	0\n"
			"gpr	r5	.32	20	0\n"
			"gpr	r6	.32	24	0\n"
			"gpr	r7	.32	28	0\n"
			"gpr	r8	.32	32	0\n"
			"gpr	r9	.32	36	0\n"
			"gpr	r10	.32	40	0\n"
			"gpr	r11	.32	44	0\n"
			"gpr	r12	.32	48	0\n"
			"gpr	r13	.32	52	0\n"
			"gpr	r14	.32	56	0\n"
			"gpr	r15	.32	60	0\n"
			"gpr	pc	.32	64	0\n"
			"gpr	pr	.32	68	0\n"
			"gpr	sr	.32	72	0\n"
			"gpr	gbr	.32	76	0\n"
			"gpr	mach	.32	80	0\n"
			"gpr	macl	.32	84	0\n"
		);
	}
	return NULL;
}

static int r_debug_gdb_breakpoint (void *user, int type, ut64 addr, int hw, int rwx){
	if (hw && support_hw_bp!=UNSUPPORTED) {
		//TODO Implement gdb hw breakpoint
		support_hw_bp = UNSUPPORTED;
		return R_FALSE;
	}

	if (!hw && support_sw_bp!=UNSUPPORTED){
		if(!type && gdbwrap_simplesetbp(desc,addr)){
			support_sw_bp = SUPPORTED;
			return R_TRUE;
		} else if (type) {
			gdbwrap_simpledelbp(desc,addr);
			return R_TRUE;
		} else {
			support_sw_bp = UNSUPPORTED;
			return R_FALSE;
		}
		return support_sw_bp;
	}
	return R_FALSE;
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
	.breakpoint = &r_debug_gdb_breakpoint,
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
