/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>

// Dalvik's calling convention is per-method, not arch-wide. Every method
// body is preceded by a 16-byte code_item header whose first two u16 fields
// are registers_size and ins_size. Arguments occupy the last ins_size
// virtual registers of the frame: v(regsz - ins_size) .. v(regsz - 1).

static int dalvik_eligible(RAnal *anal) {
	const char *arch = anal->config? anal->config->arch: NULL;
	return (arch && !strcmp (arch, "dalvik"))? 0: -1;
}

static void var_prot_free(RAnalVarProt *vp) {
	if (vp) {
		free (vp->name);
		free (vp->type);
		free (vp);
	}
}

static RList *dalvik_recover_vars(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	if (fcn->addr < 16 || !anal->iob.read_at) {
		return NULL;
	}
	ut8 hdr[4];
	if (!anal->iob.read_at (anal->iob.io, fcn->addr - 16, hdr, sizeof (hdr))) {
		return NULL;
	}
	const int regsz = r_read_le16 (hdr);
	const int ins_size = r_read_le16 (hdr + 2);
	if (ins_size <= 0 || ins_size > regsz || regsz > 256) {
		return NULL;
	}
	RList *vars = r_list_newf ((RListFree)var_prot_free);
	if (!vars) {
		return NULL;
	}
	const int first = regsz - ins_size;
	int i;
	for (i = 0; i < ins_size; i++) {
		RAnalVarProt *p = R_NEW0 (RAnalVarProt);
		p->name = r_str_newf ("v%d", first + i);
		p->kind = R_ANAL_VAR_KIND_REG;
		p->delta = first + i;
		p->isarg = true;
		p->type = strdup ("int");
		r_list_append (vars, p);
	}
	return vars;
}

RAnalPlugin r_anal_plugin_dalvik = {
	.meta = {
		.name = "dalvik",
		.desc = "Per-method Dalvik argument recovery",
		.author = "pancake",
		.license = "MIT",
	},
	.recover_vars = dalvik_recover_vars,
	.eligible = dalvik_eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dalvik,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
