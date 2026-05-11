/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>

// JVM calling convention is per-method. Every method's bytecode is preceded
// by a Code attribute header whose last 8 bytes before the code bytes are:
//   max_stack(u2, BE) max_locals(u2, BE) code_length(u4, BE)
// Java passes arguments via the local-variable array starting at slot 0
// (slot 0 = `this` for non-static methods, then params; long/double use 2).
// We expose max_locals as the upper bound on arg slots.

static int java_eligible(RAnal *anal) {
	const char *arch = anal->config? anal->config->arch: NULL;
	return (arch && !strcmp (arch, "java"))? 0: -1;
}

static void var_prot_free(RAnalVarProt *vp) {
	if (vp) {
		free (vp->name);
		free (vp->type);
		free (vp);
	}
}

static RList *java_recover_vars(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	if (fcn->addr < 8 || !anal->iob.read_at) {
		return NULL;
	}
	ut8 hdr[2];
	if (!anal->iob.read_at (anal->iob.io, fcn->addr - 6, hdr, sizeof (hdr))) {
		return NULL;
	}
	int max_locals = r_read_be16 (hdr);
	if (max_locals <= 0) {
		return NULL;
	}
	if (max_locals > 16) {
		max_locals = 16; // capped to what regs() exposes (l0..l15)
	}
	RList *vars = r_list_newf ((RListFree)var_prot_free);
	if (!vars) {
		return NULL;
	}
	RRegItem *l0 = r_reg_get (anal->reg, "l0", -1);
	const int base = l0? l0->index: 0;
	if (l0) {
		r_unref (l0);
	}
	int i;
	for (i = 0; i < max_locals; i++) {
		RAnalVarProt *p = R_NEW0 (RAnalVarProt);
		p->name = r_str_newf ("l%d", i);
		p->kind = R_ANAL_VAR_KIND_REG;
		p->delta = base + i;
		p->isarg = true;
		p->type = strdup ("int");
		r_list_append (vars, p);
	}
	return vars;
}

RAnalPlugin r_anal_plugin_java = {
	.meta = {
		.name = "java",
		.desc = "Per-method JVM argument recovery",
		.author = "pancake",
		.license = "MIT",
	},
	.recover_vars = java_recover_vars,
	.eligible = java_eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_java,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
