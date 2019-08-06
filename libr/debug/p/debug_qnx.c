/* radare - LGPL - Copyright 2009-2016 - pancake, defragger, madprogrammer */

#include <r_asm.h>
#include <r_debug.h>
#include <libqnxr.h>

/* HACK_FOR_PLUGIN_LINKAGE */
R_API RDebugPid *__r_debug_pid_new(const char *path, int pid, char status, ut64 pc) {
	RDebugPid *p = R_NEW0 (RDebugPid);
	if (!p) {
		return NULL;
	}
	p->path = strdup (path);
	p->pid = pid;
	p->status = status;
	p->runnable = true;
	p->pc = pc;
	return p;
}
R_API void *__r_debug_pid_free(RDebugPid *pid) {
	free (pid->path);
	free (pid);
	return NULL;
}
/* ------------------- */

typedef struct {
	libqnxr_t desc;
} RIOQnx;

static libqnxr_t *desc = NULL;
static ut8 *reg_buf = NULL;
static int buf_size = 0;

static void pidlist_cb (void *ctx, pid_t pid, char *name) {
	RList *list = ctx;
	r_list_append (list, __r_debug_pid_new (name, pid, 's', 0));
}

static int r_debug_qnx_select (RDebug *dbg, int pid, int tid) {
	return qnxr_select (desc, pid, tid);
}

static RList *r_debug_qnx_tids (RDebug *dbg, int pid) {
	eprintf ("%s: TODO: Threads\n", __func__);
	return NULL;
}


static RList *r_debug_qnx_pids (RDebug *dbg, int pid) {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = (RListFree)&__r_debug_pid_free;

	/* TODO */
	if (pid) {
		r_list_append (list, __r_debug_pid_new ("(current)", pid, 's', 0));
	} else {
		qnxr_pidlist (desc, list, &pidlist_cb);
	}

	return list;
}

static int r_debug_qnx_reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	int copy_size;
	int buflen = 0;
	if (!desc) {
		return -1;
	}
	int len = qnxr_read_registers (desc);
	if (len <= 0) {
		return -1;
	}
	// read the len of the current area
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	if (size < len) {
		eprintf ("r_debug_qnx_reg_read: small buffer %d vs %d\n",
			 (int)size, (int)len);
	}
	copy_size = R_MIN (len, size);
	buflen = R_MAX (len, buflen);
	if (reg_buf) {
		if (buf_size < copy_size) {
			ut8 *new_buf = realloc (reg_buf, copy_size);
			if (!new_buf) {
				return -1;
			}
			reg_buf = new_buf;
			buflen = copy_size;
			buf_size = len;
		}
	} else {
		reg_buf = calloc (buflen, 1);
		if (!reg_buf) {
			return -1;
		}
		buf_size = buflen;
	}
	memset ((void *)(volatile void *) buf, 0, size);
	memcpy ((void *)(volatile void *) buf, desc->recv.data, copy_size);
	memset ((void *)(volatile void *) reg_buf, 0, buflen);
	memcpy ((void *)(volatile void *) reg_buf, desc->recv.data, copy_size);

	return len;
}

static RList *r_debug_qnx_map_get (RDebug *dbg) {
	return NULL;
}

static int r_debug_qnx_reg_write (RDebug *dbg, int type, const ut8 *buf, int size) {
	int buflen = 0;
	int bits = dbg->anal->bits;
	const char *pcname = r_reg_get_name (dbg->anal->reg, R_REG_NAME_PC);
	RRegItem *reg = r_reg_get (dbg->anal->reg, pcname, 0);
	if (!reg_buf) {
		// we cannot write registers before we once read them
		return -1;
	}
	if (reg) {
		if (dbg->anal->bits != reg->size) {
			bits = reg->size;
		}
	}
	free (r_reg_get_bytes (dbg->reg, type, &buflen));
	// some implementations of the gdb protocol are acting weird.
	// so winedbg is not able to write registers through the <G> packet
	// and also it does not return the whole gdb register profile after
	// calling <g>
	// so this workaround resizes the small register profile buffer
	// to the whole set and fills the rest with 0
	if (buf_size < buflen) {
		ut8 *new_buf = realloc (reg_buf, buflen * sizeof (ut8));
		if (!new_buf) {
			return -1;
		}
		reg_buf = new_buf;
		memset (new_buf + buf_size, 0, buflen - buf_size);
	}

	RRegItem *current = NULL;
	for (;;) {
		current = r_reg_next_diff (dbg->reg, type, reg_buf, buflen, current, bits);
		if (!current) {
			break;
		}
		ut64 val = r_reg_get_value (dbg->reg, current);
		int bytes = bits / 8;
		qnxr_write_reg (desc, current->name, (char *)&val, bytes);
	}
	return true;
}

static int r_debug_qnx_continue (RDebug *dbg, int pid, int tid, int sig) {
	qnxr_continue (desc, -1);
	return true;
}

static int r_debug_qnx_step (RDebug *dbg) {
	qnxr_step (desc, -1);
	return true;
}

static int r_debug_qnx_wait (RDebug *dbg, int pid) {
	ptid_t ptid = qnxr_wait (desc, pid);
	if (!ptid_equal (ptid, null_ptid)) {
		dbg->reason.signum = desc->signal;
		return desc->notify_type;
	}
	return 0;
}

static int r_debug_qnx_stop (RDebug *dbg) {
	qnxr_stop (desc);
	return true;
}

static int r_debug_qnx_attach (RDebug *dbg, int pid) {
	RIODesc *d = dbg->iob.io->desc;
	dbg->swstep = false;

	if (d && d->plugin && d->plugin->name && d->data) {
		if (!strcmp ("qnx", d->plugin->name)) {
			RIOQnx *g = d->data;
			int arch = r_sys_arch_id (dbg->arch);
			int bits = dbg->anal->bits;
			if ((desc = &g->desc)) {
				switch (arch) {
				case R_SYS_ARCH_X86:
					if (bits == 16 || bits == 32) {
						qnxr_set_architecture (&g->desc, X86_32);
					} else {
						eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
						return false;
					}
					break;
				case R_SYS_ARCH_ARM:
					if (bits == 16 || bits == 32) {
						qnxr_set_architecture (&g->desc, ARM_32);
					} else {
						eprintf ("Not supported register %s %d profile\n", dbg->arch, bits);
						return false;
					}
					break;
				}
			}
			if (pid) {
				qnxr_attach (desc, pid);
			}
		} else {
			eprintf ("%s: error: underlying IO descriptor isn't a QNX one\n", __func__);
			return false;
		}
	}

	dbg->pid = 0;
	return true;
}

static int r_debug_qnx_detach (RDebug *dbg, int pid) {
	qnxr_disconnect (desc);
	free (reg_buf);
	return true;
}

static const char *r_debug_qnx_reg_profile (RDebug *dbg) {
	int arch = r_sys_arch_id (dbg->arch);
	int bits = dbg->anal->bits;
	switch (arch) {
	case R_SYS_ARCH_X86:
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
#if 0
			"seg	ds	.32	48	0\n"
			"seg	es	.32	52	0\n"
			"seg	fs	.32	56	0\n"
			"seg	gs	.32	60	0\n"
#endif
			);
	case R_SYS_ARCH_ARM:
		if (bits == 32) {
			return strdup (
				"=PC	r15\n"
				"=SP	r14\n" // XXX
				"=A0	r0\n"
				"=A1	r1\n"
				"=A2	r2\n"
				"=A3	r3\n"
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
				"gpr	sp	.32	52	0\n" // r13
				"gpr	lr	.32	56	0\n" // r14
				"gpr	pc	.32	60	0\n" // r15
				"gpr	r13	.32	52	0\n"
				"gpr	r14	.32	56	0\n"
				"gpr	r15	.32	60	0\n"
				"gpr	cpsr	.96	64	0\n"
				"mmx	d0	.64	68	0\n" // neon
				"mmx	d1	.64	76	0\n" // neon
				"mmx	d2	.64	84	0\n" // neon
				"mmx	d3	.64	92	0\n" // neon
				"mmx	d4	.64	100	0\n" // neon
				"mmx	d5	.64	108	0\n" // neon
				"mmx	d6	.64	116	0\n" // neon
				"mmx	d7	.64	124	0\n" // neon
				"mmx	d8	.64	132	0\n" // neon
				"mmx	d9	.64	140	0\n" // neon
				"mmx	d10	.64	148	0\n" // neon
				"mmx	d11	.64	156	0\n" // neon
				"mmx	d12	.64	164	0\n" // neon
				"mmx	d13	.64	172	0\n" // neon
				"mmx	d14	.64	180	0\n" // neon
				"mmx	d15	.64	188	0\n" // neon
				"mmx	d16	.64	196	0\n" // neon
				"mmx	d17	.64	204	0\n" // neon
				"mmx	d18	.64	212	0\n" // neon
				"mmx	d19	.64	220	0\n" // neon
				"mmx	d20	.64	228	0\n" // neon
				"mmx	d21	.64	236	0\n" // neon
				"mmx	d22	.64	244	0\n" // neon
				"mmx	d23	.64	252	0\n" // neon
				"mmx	d24	.64	260	0\n" // neon
				"mmx	d25	.64	268	0\n" // neon
				"mmx	d26	.64	276	0\n" // neon
				"mmx	d27	.64	284	0\n" // neon
				"mmx	d28	.64	292	0\n" // neon
				"mmx	d29	.64	300	0\n" // neon
				"mmx	d30	.64	308	0\n" // neon
				"mmx	d31	.64	316	0\n" // neon
				"mmx	fpscr	.32	324	0\n" // neon
			);
		}
	}
	return NULL;
}

static int r_debug_qnx_breakpoint (RBreakpoint *bp, RBreakpointItem *b, bool set) {
	if (!b) {
		return false;
	}
	int ret = set
		? b->hw
			? qnxr_set_hwbp (desc, b->addr, "")
			: qnxr_set_bp (desc, b->addr, "")
		: b->hw
			? qnxr_remove_hwbp (desc, b->addr)
			: qnxr_remove_bp (desc, b->addr);
	return !ret;
}

RDebugPlugin r_debug_plugin_qnx = {
	.name = "qnx",
	.license = "LGPL3",
	.arch = "x86,arm",
	.bits = R_SYS_BITS_32,
	.step = r_debug_qnx_step,
	.cont = r_debug_qnx_continue,
	.attach = &r_debug_qnx_attach,
	.detach = &r_debug_qnx_detach,
	.pids = &r_debug_qnx_pids,
	.tids = &r_debug_qnx_tids,
	.select = &r_debug_qnx_select,
	.stop = &r_debug_qnx_stop,
	.canstep = 1,
	.wait = &r_debug_qnx_wait,
	.map_get = r_debug_qnx_map_get,
	.breakpoint = r_debug_qnx_breakpoint,
	.reg_read = &r_debug_qnx_reg_read,
	.reg_write = &r_debug_qnx_reg_write,
	.reg_profile = (void *)r_debug_qnx_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_qnx,
	.version = R2_VERSION};
#endif
