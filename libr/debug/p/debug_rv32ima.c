/* radare - LGPL - Copyright 2023 pancake */
// r2 -a riscv -b 32 -Drv32ima -
// wx b700000037a10000b711000037803e001300000013000000130000001300000013000000e39420fe
// ds / drp / pd

#include <r_asm.h>
#include <r_debug.h>

static const uint32_t ram_amt = 64 * 1024 * 1024;

#define MINIRV32_RAM_IMAGE_OFFSET 0
#define MINIRV32WARN(x...) printf((x));
#define MINIRV32_DECORATE static
#define MINI_RV32_RAM_SIZE ram_amt
#define MINIRV32_IMPLEMENTATION
#if 0
#define MINIRV32_POSTEXEC(pc, ir, retval) { if (retval > 0) { if (fail_on_all_faults) { printf ("FAULT\n"); return 3; } else { retval = HandleException( ir, retval ); } } }
#define MINIRV32_HANDLE_MEM_STORE_CONTROL( addy, val ) if (HandleControlStore(addy, val)) return val;
#define MINIRV32_HANDLE_MEM_LOAD_CONTROL( addy, rval ) rval = HandleControlLoad( addy);
#define MINIRV32_OTHERCSR_WRITE(csrno, value) HandleOtherCSRWrite (image, csrno, value);
#define MINIRV32_OTHERCSR_READ(csrno, value) value = HandleOtherCSRRead (image, csrno);
#endif
#include "./mini-rv32ima.h"

typedef struct plugin_data_t {
	int elapsed;
	struct MiniRV32IMAState rv32state;
} PluginData;

#if 0
static bool is_io_rv32ima(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name)
		if (!strcmp ("rv32ima", d->plugin->name))
			return true;
	return false;
}
#endif

static bool __rv32ima_step(RDebug *dbg) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}

	ut8 buf[0xffff];

	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	ut64 pc = r_debug_reg_get (dbg, "PC");
	// eprintf ("PC = 0x%" PFMT64x "\n", pc);
/// XXX. hack to trick vaddr issue
//pc = 0x100001478;
	//memset (buf, 0, sizeof (buf));
	// dbg->iob.read_at (dbg->iob.io, pc, buf, sizeof (buf));
	dbg->iob.read_at (dbg->iob.io, 0, buf, sizeof (buf));
	// eprintf ("READ 0x%08"PFMT64x" %02x %02x %02x\n", pc, buf[0], buf[1], buf[2]);
	pd->elapsed += 1;
	// uint32_t vProcAddress = pc;
	pd->rv32state.pc = pc;
	MiniRV32IMAStep( &pd->rv32state, buf, pc, pd->elapsed, 1);
	// eprintf ("POST PC 0x%"PFMT64x"\n", pd->rv32state.pc);
// int32_t MiniRV32IMAStep( &pd->rv32state, buf, uint32_t vProcAddress, uint32_t elapsedUs, int count );
	return true;
}

static bool __rv32ima_init(RDebug *dbg) {
	dbg->swstep = false;
	dbg->tid = dbg->pid = 1;
	// aeim
	// aei
	return true;
}

static bool __rv32ima_continue(RDebug *dbg, int pid, int tid, int sig) {
	R_LOG_TODO ("continue");
	return true;
}

static bool __rv32ima_continue_syscall(RDebug *dbg, int pid, int num) {
	R_LOG_TODO ("rv32ima continue until syscall");
	return true;
}

static RDebugReasonType __rv32ima_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_DEBUG_REASON_NONE;
}

static bool __rv32ima_attach(RDebug *dbg, int pid) {
	dbg->swstep = false;
	eprintf ("OK attach\n");
	return true;
#if 0
	if (!is_io_rv32ima (dbg))
		return false;
#endif
#if 0
	RIOBdescbg *o;
	o = dbg->iob.io->desc->data;
	eprintf ("base = %llx\n", o->bfvm->base);
	eprintf ("screen = %llx\n", o->bfvm->screen);
	eprintf ("input = %llx\n", o->bfvm->input);
#endif
	return true;
}

static bool __rv32ima_detach(RDebug *dbg, int pid) {
	// reset vm?
	return true;
}

static char *__rv32ima_reg_profile(RDebug *dbg) {
	const char *p = "=PC	pc\n"
		"=A0	a0\n"
		"=A1	a1\n"
		"=A2	a2\n"
		"=A3	a3\n"
		"=A4	a4\n"
		"=A5	a5\n"
		"=A6	a6\n"
		"=A7	a7\n"
		"=R0	a0\n"
		"=R1	a1\n"
		"=SP	sp\n" // ABI: stack pointer
		"=LR	ra\n" // ABI: return address
		"=BP	s0\n" // ABI: frame pointer
		"=SN	a7\n" // ABI: syscall numer
		"gpr	pc	.32	0	0\n"
		// RV32I regs (ABI names)
		// From user-Level ISA Specification, section 2.1
		// "zero" has been left out as it ignores writes and always reads as zero
		"gpr	ra	.32	4	0\n" // =x1
		"gpr	sp	.32	8	0\n" // =x2
		"gpr	gp	.32	12	0\n" // =x3
		"gpr	tp	.32	16	0\n" // =x4
		"gpr	t0	.32	20	0\n" // =x5
		"gpr	t1	.32	24	0\n" // =x6
		"gpr	t2	.32	28	0\n" // =x7
		"gpr	s0	.32	32	0\n" // =x8
		"gpr	s1	.32	36	0\n" // =x9
		"gpr	a0	.32	40	0\n" // =x10
		"gpr	a1	.32	44	0\n" // =x11
		"gpr	a2	.32	48	0\n" // =x12
		"gpr	a3	.32	52	0\n" // =x13
		"gpr	a4	.32	56	0\n" // =x14
		"gpr	a5	.32	60	0\n" // =x15
		"gpr	a6	.32	64	0\n" // =x16
		"gpr	a7	.32	68	0\n" // =x17
		"gpr	s2	.32	72	0\n" // =x18
		"gpr	s3	.32	76	0\n" // =x19
		"gpr	s4	.32	80	0\n" // =x20
		"gpr	s5	.32	84	0\n" // =x21
		"gpr	s6	.32	88	0\n" // =x22
		"gpr	s7	.32	92	0\n" // =x23
		"gpr	s8	.32	96	0\n" // =x24
		"gpr	s9	.32	100	0\n" // =x25
		"gpr	s10	.32	104	0\n" // =x26
		"gpr	s11	.32	108	0\n" // =x27
		"gpr	t3	.32	112	0\n" // =x28
		"gpr	t4	.32	116	0\n" // =x29
		"gpr	t5	.32	120	0\n" // =x30
		"gpr	t6	.32	124	0\n" // =x31
#if 0
		// RV32F/D regs (ABI names)
		// From user-Level ISA Specification, section 8.1 and 9.1
		"flg	nx	.1	3072	0\n"
		"flg	uf	.1	3073	0\n"
		"flg	of	.1	3074	0\n"
		"flg	dz	.1	3075	0\n"
		"flg	nv	.1	3076	0\n"
		"flg	frm	.3	3077	0\n"
#endif
				 ;
	return strdup (p);
}

static int __rv32ima_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	//r_io_system (dbg->iob.io, "db");
	return false;
}

static bool __rv32ima_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: ESIL reset
	return true;
}

static bool __rv32ima_stop(RDebug *dbg) {
	eprintf ("ESIL: stop\n");
	return true;
}

// static bool __reg_write(RDebug *dbg, int type, ut8 *buf, int size) {
static bool __reg_write(RDebug *dbg, int type, const ut8* buf, int size) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}
	if (type != R_REG_TYPE_GPR || size < 4) {
		return false;
	}
	int sz = 128; // sizeof (pd->rv32state.regs);
	/* do nothing */
	ut8 *bytes = r_reg_get_bytes (dbg->reg, type, &sz);
	sz = sizeof (pd->rv32state.regs);
	memcpy (&(pd->rv32state.pc), buf, 4);
	memcpy (&(pd->rv32state.regs), buf + 4, R_MIN (size, sz));
	// memcpy (buf, &pd->rv32state.regs, R_MIN (size, sz));
	free (bytes);
	return true;
}

static bool __reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}
	if (type != R_REG_TYPE_GPR || size < 1) {
		return false;
	}
	dbg->swstep = false;
	int sz = sizeof (pd->rv32state.regs);
	/* do nothing */
	ut8 *bytes = r_reg_get_bytes (dbg->reg, type, &sz);
	memcpy (buf, &pd->rv32state.pc, 4);
	memcpy (buf + 4, &pd->rv32state.regs, R_MIN (size, sz));
	free (bytes);
	return true;
}

static bool init_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	r_return_val_if_fail (dbg && ds && !ds->plugin_data, false);

	ds->plugin_data = R_NEW0 (PluginData);
	return !!ds->plugin_data;
}

static bool fini_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	r_return_val_if_fail (dbg && ds && ds->plugin_data, false);

	R_FREE (ds->plugin_data);
	return true;
}

RDebugPlugin r_debug_plugin_rv32ima = {
	.meta = {
		.name = "rv32ima",
		.author = "pancake",
		.desc = "experimental riscv32ima emulator",
		.license = "MIT",
	},
	.arch = "riscv",
	.bits = R_SYS_BITS_32,
	.init_plugin = init_plugin,
	.fini_plugin = fini_plugin,
	.init_debugger = __rv32ima_init,
	.step = __rv32ima_step,
	.cont = __rv32ima_continue,
	.contsc = __rv32ima_continue_syscall,
	.attach = __rv32ima_attach,
	.detach = __rv32ima_detach,
	.wait = __rv32ima_wait,
	.stop = __rv32ima_stop,
	.kill = __rv32ima_kill,
	.breakpoint = __rv32ima_breakpoint,
 	.reg_profile = __rv32ima_reg_profile,
	.reg_read = __reg_read,
	.reg_write = __reg_write,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_rv32ima,
	.version = R2_VERSION
};
#endif

