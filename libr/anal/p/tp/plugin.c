/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: command glue and the plugin definition */

#include "tp.h"

static bool tp_requirements_met(RAnal *anal, bool noisy) {
	if (!anal) {
		if (noisy) {
			R_LOG_WARN ("analysis context not ready");
		}
		return false;
	}
	if (!anal->iob.io) {
		if (noisy) {
			R_LOG_WARN ("IO not ready");
		}
		return false;
	}
	if (!anal->esil) {
		if (noisy) {
			R_LOG_WARN ("Run 'aei' to initialize ESIL");
		}
		return false;
	}
	bool is_debug = anal->coreb.cfgGetB? anal->coreb.cfgGetB (anal->coreb.core, "cfg.debug"): false;
	if (is_debug) {
		if (noisy) {
			R_LOG_WARN ("Type propagation is disabled in debugger mode");
		}
		return false;
	}
	return true;
}

RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	int maxopsz = r_arch_info (anal->arch, R_ARCH_INFO_MAXOP_SIZE);
	if (maxopsz <= 0) {
		maxopsz = 32;
	}
	ut8 stack_buf[64];
	ut8 *buf = stack_buf;
	if (maxopsz > (int)sizeof (stack_buf)) {
		buf = malloc (maxopsz);
		if (!buf) {
			return NULL;
		}
	}
	RAnalOp *op = NULL;
	if (!anal->iob.read_at) {
		goto beach;
	}
	const int nread = anal->iob.read_at (anal->iob.io, addr, buf, maxopsz);
	if (nread < 1) {
		goto beach;
	}
	op = R_NEW0 (RAnalOp);
	if (!op) {
		goto beach;
	}
	if (r_anal_op (anal, op, addr, buf, nread, mask) < 1) {
		r_anal_op_free (op);
		op = NULL;
		goto beach;
	}
beach:
	if (buf != stack_buf) {
		free (buf);
	}
	return op;
}

static RCoreHelpMessage help_msg_tp = {
	"Usage:", "a:tp", "propagate types for current function",
	"a:tp", "all", "propagate types for every function (aaft)",
	"a:tp", "synth", "synthesize struct types from pointer-argument and allocator-return accesses (afts)",
	"a:tp", "synth*", "show the synthesis as r2 commands without applying (afts*)",
	"a:tp", "synthj", "apply the synthesis and report it in json (aftsj)",
	"a:tp", "?", "show this help",
	NULL
};

// afts / afts* / aftsj: synthesize struct types at the current function; suffix selects the mode
static char *tp_synth_cmd(RAnal *anal, void *core, const char *suffix) {
	const char mode = *suffix;
	if (mode && !((mode == '*' || mode == 'j') && !suffix[1])) {
		if (anal->coreb.help) {
			anal->coreb.help (core, help_msg_tp);
		}
		return strdup ("");
	}
	const ut64 cur_addr = anal->coreb.numGet? anal->coreb.numGet (core, "$$"): 0;
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, cur_addr, -1);
	if (!fcn) {
		R_LOG_WARN ("Cannot find function at current offset");
		return strdup ("");
	}
	RVecSynthRec recs;
	RVecSynthRec_init (&recs);
	type_synth (anal, fcn, mode != '*', &recs);
	char *res = NULL;
	if (mode == 'j') {
		res = synth_json (&recs);
	} else if (mode == '*') {
		res = synth_commands (anal, fcn, &recs);
	} else {
		SynthRec *rec;
		R_VEC_FOREACH (&recs, rec) {
			if (anal->coreb.cmdf) {
				anal->coreb.cmdf (core, "tsc %s", rec->bt->name);
			}
		}
		if (RVecSynthRec_empty (&recs)) {
			R_LOG_INFO ("no struct recovered here");
		}
	}
	RVecSynthRec_fini (&recs);
	return res? res: strdup ("");
}

static char *tp_cmd(RAnal *anal, const char *input) {
	R_RETURN_VAL_IF_FAIL (anal && input, NULL);
	if (!r_str_startswith (input, "tp")) {
		return NULL;
	}
	const char *args = r_str_trim_head_ro (input + 2);
	void *core = anal->coreb.core;
	if (*args == '?') {
		if (anal->coreb.help && core) {
			anal->coreb.help (core, help_msg_tp);
		}
		return strdup ("");
	}
	if (!core) {
		return strdup ("");
	}
	if (!tp_requirements_met (anal, true)) {
		return strdup ("");
	}
	if (!*args) {
		ut64 cur_addr = anal->coreb.numGet? anal->coreb.numGet (core, "$$"): 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, cur_addr, -1);
		if (!fcn) {
			R_LOG_WARN ("Cannot find function at current offset");
			return strdup ("");
		}
		r_cons_break_push (r_cons_singleton (), NULL, NULL);
		r_esil_set_pc (anal->esil, fcn->addr);
		r_anal_type_match (anal, fcn);
		r_cons_break_pop (r_cons_singleton ());
		if (anal->coreb.cfgGetB && anal->coreb.cfgGetB (core, "types.synth") && synth_args_untyped (fcn)) {
			type_synth (anal, fcn, true, NULL);
		}
		return strdup ("");
	}
	if (!strcmp (args, "all")) {
		if (anal->coreb.cmd) {
			anal->coreb.cmd (core, "aaft");
		} else {
			R_LOG_WARN ("Cannot run 'aaft' because core bindings are missing");
		}
		return strdup ("");
	}
	if (r_str_startswith (args, "synth")) {
		return tp_synth_cmd (anal, core, args + 5);
	}
	if (anal->coreb.help && core) {
		anal->coreb.help (core, help_msg_tp);
	}
	return strdup ("");
}

static int tp_plugin_eligible(RAnal *anal) {
	return tp_requirements_met (anal, false) ? 0 : -1;
}

RAnalPlugin r_anal_plugin_tp = {
	.meta = {
		.name = "tp",
		.desc = "Type propagation analysis",
		.author = "radare2",
		.license = "LGPL3",
	},
	.depends = "esil",
	.cmd = tp_cmd,
	.eligible = tp_plugin_eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tp,
	.version = R2_VERSION
};
#endif
