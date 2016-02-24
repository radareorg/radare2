/* radare - LGPL - Copyright 2009-2016 - pancake, defragger */

#include <r_asm.h>
#include <r_debug.h>

static int r_debug_bochs_breakpoint (RBreakpointItem *bp, int set, void *user) {
	return false;
}

static int r_debug_bochs_step(RDebug *dbg) {
	return true;
}

static int r_debug_bochs_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	return -1;
}

static int r_debug_bochs_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	return -1;
}

static RList *r_debug_bochs_map_get(RDebug* dbg) { //TODO
	//TODO
	return NULL;
}

static int r_debug_bochs_continue(RDebug *dbg, int pid, int tid, int sig) {
	return true;
}

static int r_debug_bochs_wait(RDebug *dbg, int pid) {
	return true;
}

static int r_debug_bochs_attach(RDebug *dbg, int pid) {
	return true;
}

static int r_debug_bochs_detach(RDebug *dbg, int pid) {
	return true;
}

static const char *r_debug_bochs_reg_profile(RDebug *dbg) {
	int bits = dbg->anal->bits;
	if (bits == 16 || bits == 32) {
			return strdup (
				"=PC	eip\n"
				"=SP	esp\n"
				"=BP	ebp\n"
				"=A0	eax\n"
				"=A1	ebx\n"
				"=A2	ecx\n"
				"=A3	edi\n"
				"=SN	oeax\n"
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
				"gpr	st0	.80	64	0\n"
				"gpr	st1	.80	74	0\n"
				"gpr	st2	.80	84	0\n"
				"gpr	st3	.80	94	0\n"
				"gpr	st4	.80	104	0\n"
				"gpr	st5	.80	114	0\n"
				"gpr	st6	.80	124	0\n"
				"gpr	st7	.80	134	0\n"
				"gpr	fctrl	.32	144	0\n"
				"gpr	fstat	.32	148	0\n"
				"gpr	ftag	.32	152	0\n"
				"gpr	fiseg	.32	156	0\n"
				"gpr	fioff	.32	160	0\n"
				"gpr	foseg	.32	164	0\n"
				"gpr	fooff	.32	168	0\n"
				"gpr	fop	.32	172	0\n"
				);
	} else if (dbg->anal->bits == 64) {
			return strdup (
				"=PC	rip\n"
				"=SP	rsp\n"
				"=BP	rbp\n"
				"=A0	rax\n"
				"=A1	rbx\n"
				"=A2	rcx\n"
				"=A3	rdx\n"
				"=SN	orax\n"
				"gpr	fake	.64	795	0\n"
				"gpr	rax	.64	0	0\n"
				"gpr	rbx	.64	8	0\n"
				"gpr	rcx	.64	16	0\n"
				"gpr	rdx	.64	24	0\n"
				"gpr	rsi	.64	32	0\n"
				"gpr	rdi	.64	40	0\n"
				"gpr	rbp	.64	48	0\n"
				"gpr	rsp	.64	56	0\n"
				"gpr	r8	.64	64	0\n"
				"gpr	r9	.64	72	0\n"
				"gpr	r10	.64	80	0\n"
				"gpr	r11	.64	88	0\n"
				"gpr	r12	.64	96	0\n"
				"gpr	r13	.64	104	0\n"
				"gpr	r14	.64	112	0\n"
				"gpr	r15	.64	120	0\n"
				"gpr	rip	.64	128	0\n"
				"gpr	eflags	.32	136	0\n"
				"seg	cs	.32	140	0\n"
				"seg	ss	.32	144	0\n"
				"seg	ds	.32	148	0\n"
				"seg	es	.32	152	0\n"
				"seg	fs	.32	156	0\n"
				"seg	gs	.32	160	0\n"
				"gpr	st0	.80	164	0\n"
				"gpr	st1	.80	174	0\n"
				"gpr	st2	.80	184	0\n"
				"gpr	st3	.80	194	0\n"
				"gpr	st4	.80	204	0\n"
				"gpr	st5	.80	214	0\n"
				"gpr	st6	.80	224	0\n"
				"gpr	st7	.80	234	0\n"
				"gpr	fctrl	.32	244	0\n"
				"gpr	fstat	.32	248	0\n"
				"gpr	ftag	.32	252	0\n"
				"gpr	fiseg	.32	256	0\n"
				"gpr	fioff	.32	260	0\n"
				"gpr	foseg	.32	264	0\n"
				"gpr	fooff	.32	268	0\n"
				"gpr	fop	.32	272	0\n"
			);
	} else {
			return strdup (
			"=PC	eip\n"
			"=SP	esp\n"
			"=BP	ebp\n"
			"=A0	eax\n"
			"=A1	ebx\n"
			"=A2	ecx\n"
			"=A3	edi\n"
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
	}
	return NULL;
}


struct r_debug_plugin_t r_debug_plugin_bochs = {
	.name = "bochs",
	/* TODO: Add support for more architectures here */
	.license = "LGPL3",
	.arch = "x86",
	.bits = R_SYS_BITS_16 | R_SYS_BITS_32 | R_SYS_BITS_64,
	.step = r_debug_bochs_step,
	.cont = r_debug_bochs_continue,
	.attach = &r_debug_bochs_attach,
	.detach = &r_debug_bochs_detach,
	.canstep = 1,
	.wait = &r_debug_bochs_wait,
	.map_get = r_debug_bochs_map_get,
	.breakpoint = &r_debug_bochs_breakpoint,
	.reg_read = &r_debug_bochs_reg_read,
	.reg_write = &r_debug_bochs_reg_write,
	.reg_profile = (void *)r_debug_bochs_reg_profile,
	//.bp_write = &r_debug_gdb_bp_write,
	//.bp_read = &r_debug_gdb_bp_read,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bochs,
	.version = R2_VERSION
};
#endif
