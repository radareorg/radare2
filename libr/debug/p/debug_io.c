/* radare - LGPL - Copyright 2016-2025 pancake */

#include <r_debug.h>
#include <r_core.h>
#include <r_asm.h>

static bool __io_step(RDebug *dbg) {
	free (dbg->iob.system (dbg->iob.io, "ds"));
	return true;
}

static bool __io_step_over(RDebug *dbg) {
	free (dbg->iob.system (dbg->iob.io, "dso"));
	return true;
}

static RList *__io_maps(RDebug *dbg) {
	RList *list = r_list_new ();
	char *str = dbg->iob.system (dbg->iob.io, "dm");
	if (!str) {
		r_list_free (list);
		return NULL;
	}
	char *ostr = str;
	ut64 map_start, map_end;
	char perm[32];
	char name[512];
	RCore *core = dbg->coreb.core;
	RCons *cons = core->cons;
	for (;;) {
		char *nl = strchr (str, '\n');
		if (nl) {
			*nl = 0;
			*name = 0;
			*perm = 0;
			map_start = map_end = 0LL;
			if (!strncmp (str, "sys ", 4)) {
				char *sp = strchr (str + 4, ' ');
				if (sp) {
					str = sp + 1;
				} else {
					str += 4;
				}
			}
			char *_s_ = strstr (str, " s ");
			if (_s_) {
				memmove (_s_, _s_ + 2, strlen (_s_));
			}
			_s_ = strstr (str, " ? ");
			if (_s_) {
				memmove (_s_, _s_ + 2, strlen (_s_));
			}
			if (r_str_scanf (str, "0x%Lx - 0x%Lx %.s %.s", &map_start, &map_end, sizeof (perm), perm, sizeof (name), name) > 4) {
				break;
			}
			if (map_end != 0LL) {
				int sperm = r_str_rwx (perm);
				if (sperm >= 0) {
					RDebugMap *map = r_debug_map_new (name, map_start, map_end, sperm, 0);
					r_list_append (list, map);
				} else {
					R_LOG_WARN ("Invalid permission string (%s)", perm);
				}
			}
			str = nl + 1;
		} else {
			break;
		}
	}
	free (ostr);
	r_cons_reset (cons);
	return list;
}

static RDebugReasonType __io_wait(RDebug *dbg, int pid) {
	/* do nothing */
	return R_DEBUG_REASON_NONE;
}

static bool __io_attach(RDebug *dbg, int pid) {
	return true;
}

// "drp" register profile
static char *__io_reg_profile(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	RCons *cons = core->cons;
	r_cons_push (cons);
	char *drp = dbg->iob.system (dbg->iob.io, "drp");
	if (drp) {
		return drp;
	}
	const char *buf = r_kons_get_buffer (cons, NULL);
	if (R_STR_ISNOTEMPTY (buf)) {
		char *ret = strdup (buf);
		r_cons_pop (cons);
		return ret;
	}
	// r_cons_pop (cons);
	return r_anal_get_reg_profile (dbg->anal);
}

// "dr8" read register state
static bool __reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	RCore *core = dbg->coreb.core;
	RCons *cons = core->cons;
	r_cons_push (cons);
	char *dr8 = dbg->iob.system (dbg->iob.io, "dr8");
	if (!dr8) {
		const char *fb = r_cons_get_buffer ();
		if (R_STR_ISEMPTY (fb)) {
			R_LOG_ERROR ("Failed to get dr8 from io");
			r_cons_pop (cons);
			return false;
		}
		dr8 = strdup (fb);
		r_cons_reset (cons);
	}
	r_cons_pop (cons);
	ut8 *bregs = calloc (1, strlen (dr8));
	if (!bregs) {
		free (dr8);
		return false;
	}
	r_str_trim ((char *)bregs);
	int sz = r_hex_str2bin (dr8, bregs);
	if (sz > 0) {
		memcpy (buf, bregs, R_MIN (size, sz));
	}
	free (bregs);
	free (dr8);
	return (sz > 0);
}

// "dc" continue execution
static bool __io_continue(RDebug *dbg, int pid, int tid, int sig) {
	dbg->iob.system (dbg->iob.io, "dc");
	return true;
}

// "dk" send kill signal
static bool __io_kill(RDebug *dbg, int pid, int tid, int sig) {
	r_strf_var (cmd, 32, "dk %d", sig);
	dbg->iob.system (dbg->iob.io, cmd);
	return true;
}

RDebugPlugin r_debug_plugin_io = {
	.meta = {
		.name = "io",
		.author = "pancake",
		.license = "MIT",
		.desc = "io debug plugin",
	},
	.arch = "any", // TODO: exception!
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.step = __io_step,
	.map_get = __io_maps,
	.attach = &__io_attach,
	.wait = &__io_wait,
	.reg_read = __reg_read,
	.cont = __io_continue,
	.kill = __io_kill,
	.reg_profile = __io_reg_profile,
	.step_over = __io_step_over,
	.canstep = 1,
#if 0
	.init_debugger = __esil_init,
	.contsc = __esil_continue_syscall,
	.detach = &__esil_detach,
	.stop = __esil_stop,
	.breakpoint = &__esil_breakpoint,
#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_io,
	.version = R2_VERSION
};
#endif
