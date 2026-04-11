// radare - LGPL - Copyright 2026 - pancake

#include <r_core.h>

#define ACE_SENTINEL ((ut64)0xdeadbeefcafebabeULL)
#define ACE_MAX_REG_ARGS 8
#define ACE_MAX_FCN_BBS 256
#define ACE_DEFAULT_NARGS 4

typedef enum {
	ACE_MODE_PLAIN = 0,
	ACE_MODE_JSON,
	ACE_MODE_R2,
} AceMode;

static RCoreHelpMessage help_msg_aC = {
	"Usage:", "aC[fej*] [addr-of-call]", " # analyze function call args via ESIL emulation",
	"aCe", " [addr]", "resolve args of the call at [addr] (uses 'abpe' to emulate the shortest path)",
	"aCej", " [addr]", "same as aCe but in JSON (one object per argument with raw + typed value)",
	"aCe*", " [addr]", "emit r2 commands to set a CCu comment with the resolved call args",
	"aCf", "", "apply aCe to every call instruction in the current function",
	"aCfj", "", "apply aCej to every call in the current function (JSON array)",
	"aCf*", "", "apply aCe* to every call in the current function (sets comments at each call site)",
	NULL
};

static inline bool ace_is_unknown(ut64 v) {
	return v == ACE_SENTINEL;
}

static ut64 ace_display_value(ut64 v) {
	if ((v >> 32) == 0xffffffffULL && (v & 0x80000000ULL)) {
		return v & 0xffffffffULL;
	}
	return v;
}

static char *ace_render_typed(RCore *core, const char *type, const char *name, const char *fmt, ut64 addr, bool on_stack) {
	if (addr == UT32_MAX || addr == UT64_MAX || addr == 0) {
		if (type && strchr (type, '*')) {
			return strdup ("(void*)-1");
		}
		return strdup ("-1");
	}
	char *res = r_core_cmd_strf (core, "pfq %s%s %s @ 0x%08" PFMT64x,
		on_stack ? "*" : "", fmt, name ? name : "", addr);
	if (res) {
		r_str_trim (res);
		if (r_str_startswith (res, "\"\\xff\\xff")) {
			free (res);
			return strdup ("\"\"");
		}
	}
	return res;
}

static void ace_prime_regs(RCore *core, int nregs) {
	r_core_cmd0 (core, "aei");
	r_core_cmd0 (core, "aeim");
	ut64 sp = r_reg_getv (core->anal->reg, "SP");
	r_reg_arena_zero (core->anal->reg);
	if (sp != 0 && sp != UT64_MAX) {
		r_reg_setv (core->anal->reg, "SP", sp);
	}
	if (nregs > ACE_MAX_REG_ARGS) {
		nregs = ACE_MAX_REG_ARGS;
	}
	int i;
	char name[16];
	for (i = 0; i < nregs; i++) {
		snprintf (name, sizeof (name), "A%d", i);
		r_reg_setv (core->anal->reg, name, ACE_SENTINEL);
	}
}

static void ace_run_emulation(RCore *core, ut64 pcv) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, pcv, -1);
	if (fcn && r_list_length (fcn->bbs) <= ACE_MAX_FCN_BBS) {
		r_core_cmdf (core, "abpe 0x%08"PFMT64x, pcv);
		return;
	}
	RList *bbs = r_anal_get_blocks_in (core->anal, pcv);
	RAnalBlock *bb = bbs ? (RAnalBlock *)r_list_first (bbs) : NULL;
	if (bb) {
		r_core_cmdf (core, "aepc 0x%08"PFMT64x, bb->addr);
		r_core_cmdf (core, "aesou 0x%08"PFMT64x, pcv);
	}
	r_list_free (bbs);
}

static void ace_append_arg(RCore *core, RAnalFuncArg *arg, bool on_stack, int idx, PJ *pj, RStrBuf *sb) {
	bool unknown = ace_is_unknown (arg->src);
	ut64 disp = ace_display_value (arg->src);
	char *typed = NULL;
	if (!unknown && arg->fmt) {
		typed = ace_render_typed (core, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack);
		if (typed && R_STR_ISEMPTY (typed)) {
			R_FREE (typed);
		}
	}
	if (pj) {
		pj_o (pj);
		pj_kn (pj, "index", idx);
		if (R_STR_ISNOTEMPTY (arg->name)) {
			pj_ks (pj, "name", arg->name);
		}
		if (arg->orig_c_type) {
			pj_ks (pj, "type", arg->orig_c_type);
		} else if (arg->c_type) {
			pj_ks (pj, "type", arg->c_type);
		}
		if (R_STR_ISNOTEMPTY (arg->cc_source)) {
			pj_ks (pj, "source", arg->cc_source);
		}
		pj_kn (pj, "size", arg->size);
		pj_kb (pj, "known", !unknown);
		if (!unknown) {
			pj_kn (pj, "raw", disp);
			if (typed) {
				pj_ks (pj, "value", typed);
			}
		}
		pj_end (pj);
	} else {
		if (idx > 0) {
			r_strbuf_append (sb, ", ");
		}
		if (R_STR_ISNOTEMPTY (arg->name)) {
			r_strbuf_appendf (sb, "%s=", arg->name);
		}
		if (unknown) {
			r_strbuf_append (sb, "?");
		} else if (typed) {
			r_strbuf_appendf (sb, "%s /*0x%"PFMT64x"*/", typed, disp);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x, disp);
		}
	}
	free (typed);
}

static void ace_append_raw(RCore *core, int nargs, PJ *pj, RStrBuf *sb) {
	if (nargs < 0) {
		nargs = ACE_DEFAULT_NARGS;
	}
	if (nargs > ACE_MAX_REG_ARGS) {
		nargs = ACE_MAX_REG_ARGS;
	}
	int i;
	char regname[16];
	for (i = 0; i < nargs; i++) {
		snprintf (regname, sizeof (regname), "A%d", i);
		ut64 v = r_reg_getv (core->anal->reg, regname);
		bool unknown = ace_is_unknown (v);
		ut64 disp = ace_display_value (v);
		if (pj) {
			pj_o (pj);
			pj_kn (pj, "index", i);
			pj_ks (pj, "source", regname);
			pj_kb (pj, "known", !unknown);
			if (!unknown) {
				pj_kn (pj, "raw", disp);
			}
			pj_end (pj);
		} else {
			if (i > 0) {
				r_strbuf_append (sb, ", ");
			}
			if (unknown) {
				r_strbuf_appendf (sb, "%s=?", regname);
			} else {
				r_strbuf_appendf (sb, "%s=0x%"PFMT64x, regname, disp);
			}
		}
	}
}

static bool ace_is_call_op(int t) {
	return t == R_ANAL_OP_TYPE_CALL
		|| t == R_ANAL_OP_TYPE_UCALL
		|| t == R_ANAL_OP_TYPE_ICALL
		|| t == R_ANAL_OP_TYPE_RCALL
		|| t == R_ANAL_OP_TYPE_CCALL
		|| t == R_ANAL_OP_TYPE_UCCALL;
}

static void ace_at(RCore *core, ut64 pcv, AceMode mode) {
	ace_prime_regs (core, ACE_MAX_REG_ARGS);
	ace_run_emulation (core, pcv);
	RAnalOp *op = r_core_anal_op (core, pcv, -1);
	if (!op) {
		return;
	}
	bool is_call = ace_is_call_op (op->type);
	const char *fcn_name = NULL;
	RAnalFunction *callee = NULL;
	if (is_call && op->jump != UT64_MAX && op->jump != 0) {
		callee = r_anal_get_function_at (core->anal, op->jump);
		if (callee) {
			fcn_name = callee->name;
		} else {
			RFlagItem *item = r_flag_get_in (core->flags, op->jump);
			if (item) {
				fcn_name = item->name;
			}
		}
	}
	char *key = fcn_name ? r_type_func_name (core->anal->sdb_types, fcn_name) : NULL;
	const char *ret_type = key ? r_type_func_ret (core->anal->sdb_types, key) : NULL;
	const char *cc_name = key ? r_anal_cc_func (core->anal, key) : NULL;
	if (!cc_name) {
		cc_name = r_anal_cc_default (core->anal);
	}
	int s_width = (core->anal->config->bits == 64) ? 8 : 4;
	ut64 spv = r_reg_getv (core->anal->reg, "SP");
	r_reg_setv (core->anal->reg, "SP", spv + s_width);
	RList *list = fcn_name ? r_core_get_func_args (core, fcn_name) : NULL;
	PJ *pj = NULL;
	RStrBuf *sb = NULL;
	if (mode == ACE_MODE_JSON) {
		pj = r_core_pj_new (core);
		pj_o (pj);
		pj_kn (pj, "addr", pcv);
		pj_ks (pj, "op", is_call ? "call" : r_anal_optype_tostring (op->type));
		if (is_call && op->jump != UT64_MAX) {
			pj_kn (pj, "target", op->jump);
		}
		if (fcn_name) {
			pj_ks (pj, "function", fcn_name);
		}
		if (ret_type) {
			pj_ks (pj, "return_type", ret_type);
		}
		if (cc_name) {
			pj_ks (pj, "calling_convention", cc_name);
		}
		pj_ka (pj, "args");
	} else {
		sb = r_strbuf_new ("");
		if (fcn_name) {
			if (ret_type) {
				r_strbuf_appendf (sb, "%s%s%s(", ret_type,
					(ret_type[strlen (ret_type) - 1] == '*') ? "" : " ",
					fcn_name);
			} else {
				r_strbuf_appendf (sb, "%s(", fcn_name);
			}
		} else if (is_call && op->jump != UT64_MAX && op->jump != 0) {
			r_strbuf_appendf (sb, "0x%08"PFMT64x"(", op->jump);
		} else {
			r_strbuf_append (sb, "?(");
		}
	}
	bool has_typed_args = list && !r_list_empty (list);
	if (has_typed_args) {
		bool on_stack = false;
		RAnalFuncArg *first = r_list_first (list);
		if (first && first->cc_source && r_str_startswith (first->cc_source, "stack")) {
			on_stack = true;
		}
		int idx = 0;
		RListIter *iter;
		RAnalFuncArg *arg;
		r_list_foreach (list, iter, arg) {
			ace_append_arg (core, arg, on_stack, idx, pj, sb);
			idx++;
		}
	} else {
		int nargs = ACE_DEFAULT_NARGS;
		if (callee) {
			int n = r_anal_var_count_args (callee);
			if (n > 0) {
				nargs = n;
			}
		}
		ace_append_raw (core, nargs, pj, sb);
	}
	r_list_free (list);
	r_reg_setv (core->anal->reg, "SP", spv);
	free (key);
	if (mode == ACE_MODE_JSON) {
		pj_end (pj);
		pj_end (pj);
		char *j = pj_drain (pj);
		r_cons_printf (core->cons, "%s\n", j);
		free (j);
	} else {
		r_strbuf_append (sb, ")");
		char *s = r_strbuf_drain (sb);
		if (mode == ACE_MODE_R2) {
			char *u = (char *)r_base64_encode_dyn ((const ut8 *)s, -1);
			if (u) {
				r_cons_printf (core->cons, "'@0x%08"PFMT64x"'CCu base64:%s\n", pcv, u);
				free (u);
			}
		} else {
			r_cons_println (core->cons, s);
		}
		free (s);
	}
	r_anal_op_free (op);
}

static void ace_iter_fcn(RCore *core, AceMode mode) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	if (!fcn) {
		R_LOG_ERROR ("No function at 0x%08"PFMT64x, core->addr);
		return;
	}
	RList *calls = r_list_new ();
	if (!calls) {
		return;
	}
	RListIter *it;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		while (at < bb->addr + bb->size) {
			RAnalOp *op = r_core_anal_op (core, at, R_ARCH_OP_MASK_BASIC);
			if (!op || op->size < 1) {
				r_anal_op_free (op);
				break;
			}
			if (ace_is_call_op (op->type)) {
				ut64 *p = R_NEW (ut64);
				if (p) {
					*p = at;
					r_list_append (calls, p);
				}
			}
			at += op->size;
			r_anal_op_free (op);
		}
	}
	if (mode == ACE_MODE_JSON) {
		r_cons_print (core->cons, "[");
		RListIter *cit;
		ut64 *pv;
		bool first = true;
		r_list_foreach (calls, cit, pv) {
			if (!first) {
				r_cons_print (core->cons, ",");
			}
			first = false;
			ace_at (core, *pv, ACE_MODE_JSON);
		}
		r_cons_print (core->cons, "]\n");
	} else {
		RListIter *cit;
		ut64 *pv;
		r_list_foreach (calls, cit, pv) {
			ace_at (core, *pv, mode);
		}
	}
	r_list_free (calls);
}

static bool ace_handle(RCore *core, const char *input) {
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_aC);
		return true;
	}
	if (*input == 'f') {
		AceMode mode = ACE_MODE_PLAIN;
		if (input[1] == 'j') {
			mode = ACE_MODE_JSON;
		} else if (input[1] == '*') {
			mode = ACE_MODE_R2;
		} else if (input[1] != '\0' && input[1] != ' ') {
			r_core_cmd_help (core, help_msg_aC);
			return true;
		}
		ace_iter_fcn (core, mode);
		return true;
	}
	if (*input != 'e') {
		r_core_cmd_help (core, help_msg_aC);
		return true;
	}
	input++;
	AceMode mode = ACE_MODE_PLAIN;
	if (*input == 'j') {
		mode = ACE_MODE_JSON;
		input++;
	} else if (*input == '*') {
		mode = ACE_MODE_R2;
		input++;
	}
	while (*input == ' ') {
		input++;
	}
	ut64 pcv = R_STR_ISEMPTY (input) ? core->addr : r_num_math (core->num, input);
	if (pcv == 0 || pcv == UT64_MAX) {
		r_core_cmd_help (core, help_msg_aC);
		return true;
	}
	ace_at (core, pcv, mode);
	return true;
}

static bool r_cmd_callargs_call(RCorePluginSession *cps, const char *input) {
	RCore *core = cps->core;
	if (!core || !r_str_startswith (input, "aC")) {
		return false;
	}
	return ace_handle (core, input + 2);
}

RCorePlugin r_core_plugin_callargs = {
	.meta = {
		.name = "callargs",
		.desc = "analyze call arguments via ESIL emulation (aC/aCe/aCf)",
		.license = "LGPL-3.0-only",
		.author = "pancake",
	},
	.call = r_cmd_callargs_call,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_callargs,
	.version = R2_VERSION
};
#endif
