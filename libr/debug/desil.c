/* radare - LGPL - Copyright 2015-2021 - pancake */

#include <r_debug.h>

#if 0
	/* debugesil performs step into + esil conditionals */
	ESIL conditionals can be used to detect when a specific address is
	accessed, or a register. Those esil conditionals must be evaluated
	every iteration to ensure the register values are updated. Think
	in DebugESIL as software-watchpoints.

	[read|write|exec]-[reg|mem] [expression]

	de rw reg eax
	de-*

	# expression can be a number or a range (if .. is found)
	# The <=, >=, ==, <, > comparisons are also supported

#endif

typedef struct {
	int rwx;
	int dev;
	char *expr;
} EsilBreak;

// TODO: Kill those globals
RDebug *dbg = NULL;
static int has_match = 0;
static int prestep = 1; // TODO: make it configurable
static ut64 opc = 0;
RList *esil_watchpoints = NULL;
#define EWPS esil_watchpoints
#define ESIL dbg->anal->esil

static int exprmatch(RDebug *dbg, ut64 addr, const char *expr) {
	char *e = strdup (expr);
	if (!e) {
		return 0;
	}
	char *p = strstr (e, "..");
	ut64 a,b;
	int ret = 0;
	if (p) {
		*p = 0;
		p += 2;
		a = r_num_math (dbg->num, e);
		b = r_num_math (dbg->num, p);
		if (a<b) {
			if (addr >= a && addr <= b) {
				ret = 1;
			}
		} else {
			if (addr >= b && addr <= a) {
				ret = 1;
			}
		}
	} else {
		a = r_num_math (dbg->num, e);
		if (addr == a) {
			ret = 1;
		}
	}
	has_match = ret;
	free (e);
	return ret;
}

static bool esilbreak_check_pc (RDebug *dbg, ut64 pc) {
	EsilBreak *ew;
	RListIter *iter;
	if (!pc) {
		pc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	}
	r_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & R_PERM_X) {
			if (exprmatch (dbg, pc, ew->expr)) {
				return 1;
			}
		}
	}
	return false;
}

static bool esilbreak_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	EsilBreak *ew;
	RListIter *iter;
	eprintf (Color_GREEN"MEM READ 0x%"PFMT64x"\n"Color_RESET, addr);
	r_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & R_PERM_R && ew->dev == 'm') {
			if (exprmatch (dbg, addr, ew->expr)) {
				has_match = 1;
				return 1;
			}
		}
	}
	return false;
}

static bool esilbreak_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	EsilBreak *ew;
	RListIter *iter;
	eprintf (Color_RED"MEM WRTE 0x%"PFMT64x"\n"Color_RESET, addr);
	r_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & R_PERM_W && ew->dev == 'm') {
			if (exprmatch (dbg, addr, ew->expr)) {
				has_match = 1;
				return true;
			}
		}
	}
	return false; // fallback
}

static bool esilbreak_reg_read(RAnalEsil *esil, const char *regname, ut64 *num, int *size) {
	EsilBreak *ew;
	RListIter *iter;
	if (regname[0]>='0' && regname[0]<='9') {
		//eprintf (Color_CYAN"IMM READ %s\n"Color_RESET, regname);
		return false;
	}
	eprintf (Color_YELLOW"REG READ %s\n"Color_RESET, regname);
	r_list_foreach (EWPS, iter, ew) {
		if (ew->rwx & R_PERM_R && ew->dev == 'r') {
			// XXX: support array of regs in expr
			if (!strcmp (regname, ew->expr)) {
				has_match = 1;
				return true;
			}
		}
	}
	return false;
}

static int exprtoken(RDebug *dbg, char *s, const char *sep, char **o) {
	char *p = strstr (s, sep);
	if (p) {
		*p = 0;
		p += strlen (sep);
		*o = p;
		return 1;
	}
	*o = NULL;
	return 0;
}

static int exprmatchreg(RDebug *dbg, const char *regname, const char *expr) {
	int ret = 0;
	char *p;
	char *s = strdup (expr);
	if (!s) {
		return 0;
	}
	if (!strcmp (regname, s)) {
		ret = 1;
	} else {
#define CURVAL 0){}r_str_trim (s);if (!strcmp(regname,s) && regval
		ut64 regval = r_debug_reg_get_err (dbg, regname, NULL, NULL);
		if (exprtoken (dbg, s, ">=", &p)) {
			if (CURVAL >= r_num_math (dbg->num, p))
				ret = 1;
		} else if (exprtoken (dbg, s, "<=", &p)) {
			if (CURVAL <= r_num_math (dbg->num, p))
				ret = 1;
		} else if (exprtoken (dbg, s, "==", &p)) {
			if (CURVAL <= r_num_math (dbg->num, p))
				ret = 1;
		} else if (exprtoken (dbg, s, "<", &p)) {
			if (CURVAL < r_num_math (dbg->num, p))
				ret = 1;
		} else if (exprtoken (dbg, s, ">", &p)) {
			if (CURVAL > r_num_math (dbg->num, p))
				ret = 1;
		} else if (exprtoken (dbg, s, " ", &p)) {
			r_str_trim (s);
			if (!strcmp (regname, s)) {
				ut64 num = r_num_math (dbg->num, p);
				ret = exprmatch (dbg, num, s);
			}
		} else {
			if (!strcmp (regname, s)) {
				ret = 1;
			}
		}
	}
	free (s);
	return ret;
}

static bool esilbreak_reg_write(RAnalEsil *esil, const char *regname, ut64 *num) {
	EsilBreak *ew;
	RListIter *iter;
	if (regname[0] >= '0' && regname[0] <= '9') {
		// wtf this should never happen
		//eprintf (Color_BLUE"IMM WRTE %s\n"Color_RESET, regname);
		return false;
	}
	eprintf (Color_MAGENTA"REG WRTE %s 0x%"PFMT64x"\n"Color_RESET, regname, *num);
	r_list_foreach (EWPS, iter, ew) {
		if ((ew->rwx & R_PERM_W) && (ew->dev == 'r')) {
			// XXX: support array of regs in expr
			if (exprmatchreg (dbg, regname, ew->expr)) {
				has_match = 1;
				return true;
			}
		}
	}
	return true;
}

R_API void r_debug_esil_prestep(RDebug *d, int p) {
	prestep = p;
}

R_API bool r_debug_esil_stepi(RDebug *d) {
	r_return_val_if_fail (d, false);
	RAnalOp op;
	ut8 obuf[64];
	int ret = 1;
	dbg = d;
	if (!ESIL) {
		ESIL = r_anal_esil_new (32, true, 64);
		// TODO setup something?
		if (!ESIL) {
			return 0;
		}
	}

	r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
	opc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	dbg->iob.read_at (dbg->iob.io, opc, obuf, sizeof (obuf));

	//dbg->iob.read_at (dbg->iob.io, npc, buf, sizeof (buf));

	//dbg->anal->reg = dbg->reg; // hack
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;
	ESIL->cb.hook_reg_read = &esilbreak_reg_read;
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;

	if (prestep) {
		// required when a exxpression is like <= == ..
		// otherwise it will stop at the next instruction
		if (r_debug_step (dbg, 1)<1) {
			eprintf ("Step failed\n");
			return 0;
		}
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		//	npc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	}

	if (r_anal_op (dbg->anal, &op, opc, obuf, sizeof (obuf), R_ANAL_OP_MASK_ESIL)) {
		if (esilbreak_check_pc (dbg, opc)) {
			eprintf ("STOP AT 0x%08"PFMT64x"\n", opc);
			ret = 0;
		} else {
			r_anal_esil_set_pc (ESIL, opc);
			eprintf ("0x%08"PFMT64x"  %s\n", opc, R_STRBUF_SAFEGET (&op.esil));
			(void)r_anal_esil_parse (ESIL, R_STRBUF_SAFEGET (&op.esil));
			//r_anal_esil_dumpstack (ESIL);
			r_anal_esil_stack_free (ESIL);
			ret = 1;
		}
	}
	if (!prestep) {
		if (ret && !has_match) {
			if (r_debug_step (dbg, 1)<1) {
				eprintf ("Step failed\n");
				return 0;
			}
			r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
			//	npc = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
		}
	}
	return ret;
}

R_API ut64 r_debug_esil_step(RDebug *dbg, ut32 count) {
	count++;
	has_match = 0;
	r_cons_break_push (NULL, NULL);
	do {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (has_match) {
			eprintf ("EsilBreak match at 0x%08"PFMT64x"\n", opc);
			break;
		}
		if (count > 0) {
			count--;
			if (!count) {
				//eprintf ("Limit reached\n");
				break;
			}
		}
	} while (r_debug_esil_stepi (dbg));
	r_cons_break_pop ();
	return opc;
}

R_API ut64 r_debug_esil_continue (RDebug *dbg) {
	return r_debug_esil_step (dbg, UT32_MAX);
}

static void ewps_free(EsilBreak *ew) {
	R_FREE (ew->expr);
	free (ew);
}

R_API bool r_debug_esil_watch_empty(RDebug *dbg) {
	return r_list_empty (EWPS);
}

R_API void r_debug_esil_watch(RDebug *dbg, int rwx, int dev, const char *expr) {
	if (!EWPS) {
		EWPS = r_list_new ();
		if (!EWPS) {
			return;
		}
		EWPS->free = (RListFree)ewps_free;
	}
	EsilBreak *ew = R_NEW0 (EsilBreak);
	if (!ew) {
		R_FREE (EWPS);
		return;
	}
	ew->rwx = rwx;
	ew->dev = dev;
	ew->expr = strdup (expr);
	r_list_append (EWPS, ew);
}

R_API void r_debug_esil_watch_reset(RDebug *dbg) {
	r_list_free (EWPS);
	EWPS = NULL;
}

R_API void r_debug_esil_watch_list(RDebug *dbg) {
	EsilBreak *ew;
	RListIter *iter;
	r_list_foreach (EWPS, iter, ew) {
		dbg->cb_printf ("de %s %c %s\n", r_str_rwx_i (ew->rwx), ew->dev, ew->expr);
	}
}
