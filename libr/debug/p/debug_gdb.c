/* radare - LGPL - Copyright 2009-2014 - pancake, defragger */

#include <r_asm.h>
#include <r_debug.h>
#include <libgdbr.h>

typedef struct {
	libgdbr_t desc;
} RIOGdb;

#define UNKNOWN -1
#define UNSUPPORTED 0
#define SUPPORTED 1

static libgdbr_t *desc = NULL;
static int support_sw_bp = UNKNOWN; 
static int support_hw_bp = UNKNOWN;


static int r_debug_gdb_step(RDebug *dbg) {
	gdbr_step(desc, -1); // TODO handle thread specific step?
	return R_TRUE;
}


static int r_debug_gdb_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	gdbr_read_registers(desc);
	memcpy(buf, desc->data, desc->data_len);
	return desc->data_len;
}


static RList *r_debug_gdb_map_get(RDebug* dbg) { //TODO
	//TODO
	return NULL;
}


static int r_debug_gdb_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	//gdbr_write_bin_registers(desc, buf); //TODO...
	return R_TRUE;
}


static int r_debug_gdb_continue(RDebug *dbg, int pid, int tid, int sig) {
	gdbr_continue(desc, -1);
	return R_TRUE;
}


static int r_debug_gdb_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_TRUE;
}



static int r_debug_gdb_attach(RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("gdb", d->plugin->name)) {
			RIOGdb *g = d->data;
			support_sw_bp = UNKNOWN;
			support_hw_bp = UNKNOWN;
			if (( desc = &g->desc ))
			switch (dbg->arch) {
			case R_SYS_ARCH_X86:
				if ( dbg->bits == R_SYS_BITS_32) {
					gdbr_set_architecture(&g->desc, X86_32);
				} else {
					gdbr_set_architecture(&g->desc, X86_64);
				}
				break;
			case R_SYS_ARCH_SH:
				// TODO
				break;
			case R_SYS_ARCH_ARM:
				// TODO
				break;
			}
		} else {
			eprintf ("ERROR: Underlaying IO descriptor is not a GDB one..\n");
		}
	}
	return R_TRUE;
}


static int r_debug_gdb_detach(int pid) {
	gdbr_disconnect(desc);
	return R_TRUE;
}


static const char *r_debug_gdb_reg_profile(RDebug *dbg) {
	int arch = dbg->arch;
	switch (arch) {
	case R_SYS_ARCH_X86:
		if ( dbg->bits == R_SYS_BITS_32) {
			return strdup (
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
				"gpr	xmm0	.128	176	0\n"
				"gpr	xmm1	.128	192	0\n"
				"gpr	xmm2	.128	208	0\n"
				"gpr	xmm3	.128	224	0\n"
				"gpr	xmm4	.128	240	0\n"
				"gpr	xmm5	.128	256	0\n"
				"gpr	xmm6	.128	272	0\n"
				"gpr	xmm7	.128	288	0\n"
				"gpr	mxcsr	.32	304	0\n"
				);
		} 
		else if ( dbg->bits == R_SYS_BITS_64) {
			return strdup (
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
				"gpr	xmm0	.128	276	0\n"
				"gpr	xmm1	.128	292	0\n"
				"gpr	xmm2	.128	308	0\n"
				"gpr	xmm3	.128	324	0\n"
				"gpr	xmm4	.128	340	0\n"
				"gpr	xmm5	.128	356	0\n"
				"gpr	xmm6	.128	372	0\n"
				"gpr	xmm7	.128	388	0\n"
				"gpr	xmm8	.128	404	0\n"
				"gpr	xmm9	.128	420	0\n"
				"gpr	xmm10	.128	436	0\n"
				"gpr	xmm11	.128	452	0\n"
				"gpr	xmm12	.128	468	0\n"
				"gpr	xmm13	.128	484	0\n"
				"gpr	xmm14	.128	500	0\n"
				"gpr	xmm15	.128	516	0\n"
				"gpr	mxcsr	.32	532	0\n"
					);
		}
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
		if (dbg->bits == R_SYS_BITS_32) {
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
		} else if (dbg->bits == R_SYS_BITS_64) {
			return strdup (
			"=pc	pc\n"
			"=sp	sp\n"
			"=a0	r0\n"
			"=a1	r1\n"
			"=a2	r2\n"
			"=a3	r3\n"
			"gpr	x0	.8	0	0\n"
			"gpr	x1	.8	8	0\n"
			"gpr	x2	.8	16	0\n"
			"gpr	x3	.8	24	0\n"
			"gpr	x4	.8	32	0\n"
			"gpr	x5	.8	40	0\n"
			"gpr	x6	.8	48	0\n"
			"gpr	x7	.8	56	0\n"
			"gpr	x8	.8	64	0\n"
			"gpr	x9	.8	72	0\n"
			"gpr	x10	.8	80	0\n"
			"gpr	x11	.8	88	0\n"
			"gpr	x12	.8	96	0\n"
			"gpr	x13	.8	104	0\n"
			"gpr	x14	.8	112	0\n"
			"gpr	x15	.8	120	0\n"
			"gpr	x16	.8	128	0\n"
			"gpr	x17	.8	136	0\n"
			"gpr	x18	.8	144	0\n"
			"gpr	x19	.8	152	0\n"
			"gpr	x20	.8	160	0\n"
			"gpr	x21	.8	168	0\n"
			"gpr	x22	.8	176	0\n"
			"gpr	x23	.8	184	0\n"
			"gpr	x24	.8	192	0\n"
			"gpr	x25	.8	200	0\n"
			"gpr	x26	.8	208	0\n"
			"gpr	x27	.8	216	0\n"
			"gpr	x28	.8	224	0\n"
			"gpr	x29	.8	232	0\n"
			"gpr	x30	.8	240	0\n"
			"gpr	sp	.8	248	0\n"
			"gpr	pc	.8	256	0\n"
			"gpr	cpsr	.4	264	0\n"
			"gpr	v0	.16	268	0\n"
			"gpr	v1	.16	284	0\n"
			"gpr	v2	.16	300	0\n"
			"gpr	v3	.16	316	0\n"
			"gpr	v4	.16	332	0\n"
			"gpr	v5	.16	348	0\n"
			"gpr	v6	.16	364	0\n"
			"gpr	v7	.16	380	0\n"
			"gpr	v8	.16	396	0\n"
			"gpr	v9	.16	412	0\n"
			"gpr	v10	.16	428	0\n"
			"gpr	v11	.16	444	0\n"
			"gpr	v12	.16	460	0\n"
			"gpr	v13	.16	476	0\n"
			"gpr	v14	.16	492	0\n"
			"gpr	v15	.16	508	0\n"
			"gpr	v16	.16	524	0\n"
			"gpr	v17	.16	540	0\n"
			"gpr	v18	.16	556	0\n"
			"gpr	v19	.16	572	0\n"
			"gpr	v20	.16	588	0\n"
			"gpr	v21	.16	604	0\n"
			"gpr	v22	.16	620	0\n"
			"gpr	v23	.16	636	0\n"
			"gpr	v24	.16	652	0\n"
			"gpr	v25	.16	668	0\n"
			"gpr	v26	.16	684	0\n"
			"gpr	v27	.16	700	0\n"
			"gpr	v28	.16	716	0\n"
			"gpr	v29	.16	732	0\n"
			"gpr	v30	.16	748	0\n"
			"gpr	v31	.16	764	0\n"
			"gpr	fpsr	.4	780	0\n"
			"gpr	fpcr	.4	784	0\n"
			);
		}
		return NULL;
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
	// TODO
	return R_FALSE;
}


struct r_debug_plugin_t r_debug_plugin_gdb = {
	.name = "gdb",
	/* TODO: Add support for more architectures here */
	.arch = R_SYS_ARCH_X86 | R_SYS_ARCH_ARM | R_SYS_ARCH_SH,
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
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
	.map_get = r_debug_gdb_map_get,
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
