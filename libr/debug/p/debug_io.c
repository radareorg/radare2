/* radare - LGPL - Copyright 2016 pancake */

#include <r_io.h>
#include <r_asm.h>
#include <r_debug.h>

static int __io_step(RDebug *dbg) {
	dbg->iob.system (dbg->iob.io, "ds");
	r_cons_flush();
	return 0;
}

static RList *__io_maps(RDebug *dbg) {
	RList *list = r_list_new ();
	dbg->iob.system (dbg->iob.io, "dm");
	char *ostr, *str = strdup (r_cons_get_buffer ());
	ut64 map_start, map_end;
	char perm[32];
	char name[512];
	ostr = str;
	while(true) {
		char *nl = strchr (str, '\n');
		if (nl) {
			*nl = 0;
			*name = 0;
			*perm = 0;
			map_start = map_end = 0LL;
			sscanf (str, "0x%"PFMT64x" - 0x%"PFMT64x" %s %s",
				&map_start, &map_end, perm, name);
			if (map_end != 0LL) {
				RDebugMap *map = r_debug_map_new (name, map_start, map_end, r_str_rwx (perm), 0);
				r_list_append (list, map);
			}
			str = nl + 1;
		} else {
			break;
		}
	}
	free (ostr);
	r_cons_reset();
	return list;
}

static int __io_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return true;
}

static int curPid = -1;
static int __io_attach(RDebug *dbg, int pid) {
	curPid = pid;
	return true;
}

#if 0
static int is_io_esil(RDebug *dbg) {
	RIODesc *d = dbg->iob.io->desc;
	if (d && d->plugin && d->plugin->name)
		if (!strcmp ("esil", d->plugin->name))
			return true;
	return false;
}
#endif
#if 0

static int __esil_step_over(RDebug *dbg) {
	eprintf ("TODO: ESIL STEP OVER\n");
	return true;
}

	int oplen;
	ut8 buf[64];
	ut64 pc = 0LL; // getreg("pc")
	RAnalOp op;

	pc = r_debug_reg_sync(dbg, R_REG_TYPE_GPR, 0);
	pc = r_debug_reg_get (dbg, "PC");
	eprintf ("PC = 0x%" PFMT64x "\n", pc);
/// XXX. hack to trick vaddr issue
//pc = 0x100001478;
	//memset (buf, 0, sizeof (buf));
	dbg->iob.read_at (dbg->iob.io, pc, buf, 64);
	eprintf ("READ 0x%08"PFMT64x" %02x %02x %02x\n", pc, buf[0], buf[1], buf[2]);
	oplen = r_anal_op (dbg->anal, &op, pc, buf, sizeof (buf));
	if (oplen > 0) {
		if (*R_STRBUF_SAFEGET (&op.esil)) {
			eprintf ("ESIL: %s\n", R_STRBUF_SAFEGET (&op.esil));
			r_anal_esil_parse (dbg->anal->esil, R_STRBUF_SAFEGET (&op.esil));
		}
	}
	eprintf ("TODO: ESIL STEP\n");
	return true;
}

static int __esil_init(RDebug *dbg) {
	dbg->tid = dbg->pid = 1;
	// aeim
	// aei
	eprintf ("TODO: esil-vm not initialized\n");
	return true;
}

static int __esil_continue(RDebug *dbg, int pid, int tid, int sig) {
	eprintf ("TODO continue\n");
	return true;
}

static int __esil_continue_syscall(RDebug *dbg, int pid, int num) {
	eprintf ("TODO: esil continue until syscall\n");
	return true;
}

static int __esil_detach(RDebug *dbg, int pid) {
	// reset vm?
	return true;
}

static char *__esil_reg_profile(RDebug *dbg) {
	if (!strcmp (dbg->arch, "bf")) {
		return strdup (
			"=PC	pc\n"
			"=SP	esp\n"
			"=BP	ptr\n"
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
	return r_anal_get_reg_profile (dbg->anal);
}

static int __esil_breakpoint (RBreakpointItem *bp, int set, void *user) {
	//r_io_system (dbg->iob.io, "db");
	return false;
}

static int __esil_kill(RDebug *dbg, int pid, int tid, int sig) {
	// TODO: ESIL reset
	return true;
}

static int __esil_stop(RDebug *dbg) {
	eprintf ("ESIL: stop\n");
	return true;
}

static int __reg_read (RDebug *dbg, int type, ut8 *buf, int size) {
	int sz;
	/* do nothing */
	ut8 *bytes = r_reg_get_bytes (dbg->reg, type, &sz);
	memcpy (buf, bytes, R_MIN (size, sz));
	free (bytes);
	return size;
}
#endif

RDebugPlugin r_debug_plugin_io = {
	.name = "io",
	.keepio = 1,
	.license = "MIT",
	.arch = "any", // TODO: exception!
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
	.step = __io_step,
	.map_get = __io_maps,
	.attach = &__io_attach,
	.wait = &__io_wait,
#if 0
	.init = __esil_init,
	.step_over = __esil_step_over,
	.cont = __esil_continue,
	.contsc = __esil_continue_syscall,
	.detach = &__esil_detach,
	.stop = __esil_stop,
	.kill = __esil_kill,
	.breakpoint = &__esil_breakpoint,
	.reg_profile = __esil_reg_profile,
	.reg_read = __reg_read,
#endif
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_io,
	.version = R2_VERSION
};
#endif
