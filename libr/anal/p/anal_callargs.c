// radare - LGPL - Copyright 2026 - pancake

#include <r_anal.h>

#define SENT ((ut64)0xdeadbeefcafebabeULL)
#define MAX_REGS 8
#define MAX_FCN_BBS 256
#define DEFAULT_NARGS 4

typedef enum { OUT_PLAIN, OUT_QUIET, OUT_JSON, OUT_STAR } OutMode;

static RCoreHelpMessage help = {
	"Usage:", "a:callargs", "[qj*f] [addr] # analyze call args via ESIL",
	"a:callargs", " [addr]", "plaintext summary of args at call [addr]",
	"a:callargs q", " [addr]", "quiet plaintext (stripped symbol, no arg names or raw)",
	"a:callargs j", " [addr]", "same in JSON",
	"a:callargs *", " [addr]", "emit a CCu comment command for the call",
	"a:callargs f", "", "apply to every call in the current function",
	"a:callargs fq", "", "same as 'f' but quiet",
	"a:callargs fj", "", "same as 'f' but as a JSON array",
	"a:callargs f*", "", "same as 'f' but as r2 commands",
	NULL
};

static ut64 normalize(ut64 v) {
	return ((v >> 32) == 0xffffffffULL && (v & 0x80000000ULL)) ? (v & 0xffffffffULL) : v;
}

static bool is_call(int t) {
	return t == R_ANAL_OP_TYPE_CALL || t == R_ANAL_OP_TYPE_UCALL
		|| t == R_ANAL_OP_TYPE_ICALL || t == R_ANAL_OP_TYPE_RCALL
		|| t == R_ANAL_OP_TYPE_CCALL || t == R_ANAL_OP_TYPE_UCCALL;
}

static void prime_regs(RAnal *a) {
	a->coreb.cmd (a->coreb.core, "aei");
	a->coreb.cmd (a->coreb.core, "aeim");
	ut64 sp = r_reg_getv (a->reg, "SP");
	r_reg_arena_zero (a->reg);
	if (sp && sp != UT64_MAX) {
		r_reg_setv (a->reg, "SP", sp);
	}
	char rn[16];
	int i;
	for (i = 0; i < MAX_REGS; i++) {
		snprintf (rn, sizeof (rn), "A%d", i);
		r_reg_setv (a->reg, rn, SENT);
	}
}

static void emulate_to(RAnal *a, ut64 pcv) {
	RAnalFunction *fcn = r_anal_get_fcn_in (a, pcv, -1);
	if (fcn && r_list_length (fcn->bbs) <= MAX_FCN_BBS) {
		a->coreb.cmdf (a->coreb.core, "abpe 0x%08"PFMT64x, pcv);
		return;
	}
	RList *bbs = r_anal_get_blocks_in (a, pcv);
	RAnalBlock *bb = bbs ? (RAnalBlock *)r_list_first (bbs) : NULL;
	if (bb) {
		a->coreb.cmdf (a->coreb.core, "aepc 0x%08"PFMT64x, bb->addr);
		a->coreb.cmdf (a->coreb.core, "aesou 0x%08"PFMT64x, pcv);
	}
	r_list_free (bbs);
}

static RAnalOp *decode(RAnal *a, ut64 pcv) {
	ut8 buf[16] = {0};
	if (!a->iob.read_at || !a->iob.read_at (a->iob.io, pcv, buf, sizeof (buf))) {
		return NULL;
	}
	RAnalOp *op = r_anal_op_new ();
	if (r_anal_op (a, op, pcv, buf, sizeof (buf), R_ARCH_OP_MASK_BASIC) <= 0) {
		r_anal_op_free (op);
		return NULL;
	}
	return op;
}

static const char *resolve_callee(RAnal *a, ut64 target) {
	if (!target || target == UT64_MAX) {
		return NULL;
	}
	RAnalFunction *fcn = r_anal_get_function_at (a, target);
	if (fcn) {
		return fcn->name;
	}
	RFlagItem *item = a->flb.get_at ? a->flb.get_at (a->flb.f, target, true) : NULL;
	return item ? item->name : NULL;
}

static void emit_arg(RAnal *a, int idx, const char *name, const char *type,
		const char *source, const char *fmt, int size, ut64 raw,
		bool on_stack, bool quiet, PJ *pj, RStrBuf *sb) {
	bool unknown = (raw == SENT);
	ut64 disp = normalize (raw);
	char *typed = NULL;
	if (!unknown && fmt && name) {
		typed = a->coreb.cmdStrF (a->coreb.core, "pfq %s%s %s @ 0x%08"PFMT64x,
			on_stack ? "*" : "", fmt, name, disp);
		if (typed) {
			r_str_trim (typed);
			if (!*typed) {
				R_FREE (typed);
			}
		}
	}
	if (pj) {
		pj_o (pj);
		pj_kn (pj, "index", idx);
		if (name) { pj_ks (pj, "name", name); }
		if (type) { pj_ks (pj, "type", type); }
		if (source) { pj_ks (pj, "source", source); }
		if (size) { pj_kn (pj, "size", size); }
		pj_kb (pj, "known", !unknown);
		if (!unknown) {
			pj_kn (pj, "raw", disp);
			if (typed) { pj_ks (pj, "value", typed); }
		}
		pj_end (pj);
	} else {
		if (idx > 0) { r_strbuf_append (sb, ", "); }
		if (!quiet && name) { r_strbuf_appendf (sb, "%s=", name); }
		if (unknown) {
			r_strbuf_append (sb, "?");
		} else if (typed) {
			if (quiet) {
				r_strbuf_append (sb, typed);
			} else {
				r_strbuf_appendf (sb, "%s /*0x%"PFMT64x"*/", typed, disp);
			}
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x, disp);
		}
	}
	free (typed);
}

static int emit_signature(RAnal *a, const char *fcn_name, bool quiet, PJ *pj, RStrBuf *sb) {
	if (!fcn_name) {
		return -1;
	}
	char *key = r_type_func_name (a->sdb_types, fcn_name);
	if (!key) {
		return -1;
	}
	const char *cc = r_anal_cc_func (a, key);
	if (!cc) {
		cc = r_anal_cc_default (a);
	}
	int nargs = r_type_func_args_count (a->sdb_types, key);
	if (nargs <= 0 || !cc) {
		free (key);
		return -1;
	}
	int s_width = (a->config->bits == 64) ? 8 : 4;
	ut64 spv = r_reg_getv (a->reg, "SP") + s_width;
	r_strf_buffer (256);
	int i;
	for (i = 0; i < nargs; i++) {
		const char *name = r_type_func_args_name (a->sdb_types, key, i);
		char *type = r_type_func_args_type (a->sdb_types, key, i);
		const char *ctype = type;
		if (ctype && r_str_startswith (ctype, "const ")) {
			ctype += 6;
		}
		const char *fmt = ctype ? sdb_const_get (a->sdb_types, r_strf ("type.%s", ctype), 0) : NULL;
		int size = ctype ? (int)(sdb_num_get (a->sdb_types, r_strf ("type.%s.size", ctype), 0) / 8) : 0;
		const char *src = r_anal_cc_arg (a, cc, i, -1);
		ut64 raw = SENT;
		bool on_stack = false;
		if (src && r_str_startswith (src, "stack")) {
			on_stack = true;
			raw = spv;
			spv += size ? size : s_width;
		} else if (src) {
			raw = r_reg_getv (a->reg, src);
		}
		emit_arg (a, i, name, type, src, fmt, size, raw, on_stack, quiet, pj, sb);
		free (type);
	}
	free (key);
	return nargs;
}

static void emit_raw(RAnal *a, ut64 target, bool quiet, PJ *pj, RStrBuf *sb) {
	int nargs = DEFAULT_NARGS;
	RAnalFunction *callee = (target && target != UT64_MAX) ? r_anal_get_function_at (a, target) : NULL;
	if (callee) {
		int n = r_anal_var_count_args (callee);
		if (n > 0) {
			nargs = n;
		}
	}
	if (nargs > MAX_REGS) {
		nargs = MAX_REGS;
	}
	int i;
	char rn[16];
	for (i = 0; i < nargs; i++) {
		snprintf (rn, sizeof (rn), "A%d", i);
		emit_arg (a, i, rn, NULL, rn, NULL, 0, r_reg_getv (a->reg, rn), false, quiet, pj, sb);
	}
}

static char *analyze_call(RAnal *a, ut64 pcv, OutMode mode) {
	prime_regs (a);
	emulate_to (a, pcv);
	RAnalOp *op = decode (a, pcv);
	if (!op || !is_call (op->type)) {
		r_anal_op_free (op);
		return strdup ("");
	}
	const char *fcn_name = resolve_callee (a, op->jump);
	char *key = fcn_name ? r_type_func_name (a->sdb_types, fcn_name) : NULL;
	const char *ret_type = key ? r_type_func_ret (a->sdb_types, key) : NULL;
	const char *cc = key ? r_anal_cc_func (a, key) : NULL;
	if (!cc) {
		cc = r_anal_cc_default (a);
	}
	bool quiet = (mode == OUT_QUIET);
	const char *disp_name = quiet && key ? key : fcn_name;
	PJ *pj = NULL;
	RStrBuf *sb = NULL;
	if (mode == OUT_JSON) {
		pj = pj_new ();
		pj_o (pj);
		pj_kn (pj, "addr", pcv);
		if (op->jump != UT64_MAX) { pj_kn (pj, "target", op->jump); }
		if (fcn_name) { pj_ks (pj, "function", fcn_name); }
		if (ret_type) { pj_ks (pj, "return_type", ret_type); }
		if (cc) { pj_ks (pj, "calling_convention", cc); }
		pj_ka (pj, "args");
	} else {
		sb = r_strbuf_new ("");
		if (disp_name && ret_type) {
			r_strbuf_appendf (sb, "%s%s%s(", ret_type,
				ret_type[strlen (ret_type) - 1] == '*' ? "" : " ", disp_name);
		} else if (disp_name) {
			r_strbuf_appendf (sb, "%s(", disp_name);
		} else if (op->jump != UT64_MAX && op->jump) {
			r_strbuf_appendf (sb, "0x%08"PFMT64x"(", op->jump);
		} else {
			r_strbuf_append (sb, "?(");
		}
	}
	free (key);
	int s_width = (a->config->bits == 64) ? 8 : 4;
	ut64 spv = r_reg_getv (a->reg, "SP");
	r_reg_setv (a->reg, "SP", spv + s_width);
	if (emit_signature (a, fcn_name, quiet, pj, sb) < 0) {
		emit_raw (a, op->jump, quiet, pj, sb);
	}
	r_reg_setv (a->reg, "SP", spv);
	r_anal_op_free (op);
	if (mode == OUT_JSON) {
		pj_end (pj);
		pj_end (pj);
		return pj_drain (pj);
	}
	r_strbuf_append (sb, ")");
	char *s = r_strbuf_drain (sb);
	if (mode == OUT_STAR) {
		char *u = (char *)r_base64_encode_dyn ((const ut8 *)s, -1);
		char *ret = r_str_newf ("'@0x%08"PFMT64x"'CCu base64:%s", pcv, u ? u : "");
		free (s);
		free (u);
		return ret;
	}
	return s;
}

static char *analyze_fcn(RAnal *a, OutMode mode) {
	ut64 here = a->coreb.numGet (a->coreb.core, "$$");
	RAnalFunction *fcn = r_anal_get_fcn_in (a, here, 0);
	if (!fcn) {
		R_LOG_ERROR ("No function at 0x%08"PFMT64x, here);
		return strdup ("");
	}
	RStrBuf *out = r_strbuf_new (mode == OUT_JSON ? "[" : "");
	RListIter *it;
	RAnalBlock *bb;
	bool first = true;
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		while (at < bb->addr + bb->size) {
			RAnalOp *op = decode (a, at);
			if (!op || op->size < 1) {
				r_anal_op_free (op);
				break;
			}
			int sz = op->size;
			bool call = is_call (op->type);
			r_anal_op_free (op);
			if (call) {
				char *s = analyze_call (a, at, mode);
				if (s && *s) {
					if (mode == OUT_JSON) {
						if (!first) { r_strbuf_append (out, ","); }
						r_strbuf_append (out, s);
					} else {
						r_strbuf_append (out, s);
						r_strbuf_append (out, "\n");
					}
					first = false;
				}
				free (s);
			}
			at += sz;
		}
	}
	if (mode == OUT_JSON) {
		r_strbuf_append (out, "]");
	}
	return r_strbuf_drain (out);
}

static char *callargscmd(RAnal *a, const char *input) {
	if (!r_str_startswith (input, "callargs")) {
		return NULL;
	}
	const char *arg = r_str_trim_head_ro (input + 8);
	if (*arg == '?' || (!*arg && !a->coreb.numGet)) {
		if (a->coreb.help) {
			a->coreb.help (a->coreb.core, help);
		}
		return strdup ("");
	}
	OutMode mode = OUT_PLAIN;
	if (*arg == 'f') {
		arg++;
		if (*arg == 'j') { mode = OUT_JSON; arg++; }
		else if (*arg == '*') { mode = OUT_STAR; arg++; }
		else if (*arg == 'q') { mode = OUT_QUIET; arg++; }
		while (*arg == ' ') { arg++; }
		return analyze_fcn (a, mode);
	}
	if (*arg == 'j') { mode = OUT_JSON; arg++; }
	else if (*arg == '*') { mode = OUT_STAR; arg++; }
	else if (*arg == 'q') { mode = OUT_QUIET; arg++; }
	while (*arg == ' ') { arg++; }
	ut64 pcv = R_STR_ISEMPTY (arg)
		? a->coreb.numGet (a->coreb.core, "$$")
		: r_num_math (NULL, arg);
	if (!pcv || pcv == UT64_MAX) {
		if (a->coreb.help) {
			a->coreb.help (a->coreb.core, help);
		}
		return strdup ("");
	}
	return analyze_call (a, pcv, mode);
}

RAnalPlugin r_anal_plugin_callargs = {
	.meta = {
		.name = "callargs",
		.desc = "analyze function call arguments via ESIL emulation",
		.license = "LGPL-3.0-only",
		.author = "pancake",
	},
	.cmd = callargscmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_callargs,
	.version = R2_VERSION
};
#endif
