/* radare - LGPL - Copyright 2021-2025 - pancake */

#include <r_anal.h>

#if HAVE_GPERF
extern SdbGperf gperf_cc_arm_16;
extern SdbGperf gperf_cc_arm_32;
extern SdbGperf gperf_cc_arm_64;
extern SdbGperf gperf_cc_avr_8;
// extern SdbGperf gperf_cc_hexagon_32;
extern SdbGperf gperf_cc_m68k_32;
extern SdbGperf gperf_cc_mips_32;
extern SdbGperf gperf_cc_mips_64;
extern SdbGperf gperf_cc_ppc_32;
extern SdbGperf gperf_cc_ppc_64;
extern SdbGperf gperf_cc_riscv_64;
extern SdbGperf gperf_cc_s390_64;
extern SdbGperf gperf_cc_sparc_32;
extern SdbGperf gperf_cc_v850_32;
extern SdbGperf gperf_cc_x86_16;
extern SdbGperf gperf_cc_x86_32;
extern SdbGperf gperf_cc_x86_64;
//extern SdbGperf gperf_cc_xtensa_32;
extern SdbGperf gperf_spec;
extern SdbGperf gperf_types_16;
extern SdbGperf gperf_types_32;
extern SdbGperf gperf_types_64;
extern SdbGperf gperf_types_android;
extern SdbGperf gperf_types_arm_ios_16;
extern SdbGperf gperf_types_arm_ios_32;
extern SdbGperf gperf_types_arm_ios_64;
extern SdbGperf gperf_types_darwin;
extern SdbGperf gperf_types_linux;
extern SdbGperf gperf_types_x86_macos_64;
extern SdbGperf gperf_types;
// #OBJS+=d/types_windows.o
// #OBJS+=d/types_x86_windows_32.o
// #OBJS+=d/types_x86_windows_64.o

static const SdbGperf *gperfs_cc[] = {
	&gperf_cc_arm_16,
	&gperf_cc_arm_32,
	&gperf_cc_arm_64,
	&gperf_cc_avr_8,
	// &gperf_cc_hexagon_32,
	&gperf_cc_m68k_32,
	&gperf_cc_mips_32,
	&gperf_cc_mips_64,
	&gperf_cc_ppc_32,
	&gperf_cc_ppc_64,
	&gperf_cc_riscv_64,
	&gperf_cc_s390_64,
	&gperf_cc_sparc_32,
	&gperf_cc_v850_32,
	&gperf_cc_x86_16,
	&gperf_cc_x86_32,
	&gperf_cc_x86_64,
	// &gperf_cc_xtensa_32,
	NULL
};
static const SdbGperf *gperfs_types[] = {
	&gperf_spec,
	&gperf_types_16,
	&gperf_types_32,
	&gperf_types_64,
	&gperf_types_android,
	&gperf_types_arm_ios_16,
	&gperf_types_arm_ios_32,
	&gperf_types_arm_ios_64,
	&gperf_types_darwin,
	&gperf_types_linux,
	&gperf_types_x86_macos_64,
	&gperf_types,
	NULL
};

R_API SdbGperf *r_anal_get_gperf_cc(const char *k) {
	R_RETURN_VAL_IF_FAIL (k, NULL);
	SdbGperf **gp = (SdbGperf**)gperfs_cc;
	char *kk = strdup (k);
	r_str_replace_char (kk, '_', '-');
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (kk, g->name)) {
			free (kk);
			return *gp;
		}
		gp++;
	}
	free (kk);
	return NULL;
}

R_API SdbGperf *r_anal_get_gperf_types(const char *k) {
	R_RETURN_VAL_IF_FAIL (k, NULL);
	SdbGperf **gp = (SdbGperf**)gperfs_types;
	char *s = strdup (k);
	r_str_replace_char (s, '-', '_');
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (s, g->name)) {
			free (s);
			return *gp;
		}
		gp++;
	}
	free (s);
	return NULL;
}
#else
R_API SdbGperf *r_anal_get_gperf_cc(const char * R_NULLABLE k) {
	return NULL;
}

R_API SdbGperf *r_anal_get_gperf_types(const char * R_NULLABLE k) {
	return NULL;
}
#endif

// Call all plugins' analyze_fcn callback for a function (hook after af completes)
R_API void r_anal_plugin_analyze_fcn(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (anal && fcn);
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (anal->plugins, iter, p) {
		if (p->analyze_fcn) {
			p->analyze_fcn (anal, fcn);
		}
	}
}

// Try plugins for variable recovery, return first non-NULL result
R_API RList *r_anal_plugin_recover_vars(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (anal->plugins, iter, p) {
		if (p->recover_vars) {
			RList *vars = p->recover_vars (anal, fcn);
			if (vars) {
				return vars;  // First plugin wins
			}
		}
	}
	return NULL;
}

// Collect data refs from all plugins
R_API RVecAnalRef *r_anal_plugin_get_data_refs(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	RVecAnalRef *all_refs = NULL;
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (anal->plugins, iter, p) {
		if (p->get_data_refs) {
			RVecAnalRef *refs = p->get_data_refs (anal, fcn);
			if (refs) {
				if (!all_refs) {
					all_refs = refs;
				} else {
					// Merge refs
					RAnalRef *ref;
					R_VEC_FOREACH (refs, ref) {
						RVecAnalRef_push_back (all_refs, ref);
					}
					RVecAnalRef_free (refs);
				}
			}
		}
	}
	return all_refs;
}

// Call post_analysis on all plugins (for aaaa)
R_API void r_anal_plugin_post_analysis(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (anal->plugins, iter, p) {
		if (p->post_analysis) {
			p->post_analysis (anal);
		}
	}
}

// Apply plugin-recovered variables to a function
// Returns true if a plugin provided variables, false to fall back to default recovery
R_API bool r_anal_function_recover_vars_plugin(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, false);
	RList *plugin_vars = r_anal_plugin_recover_vars (anal, fcn);
	if (!plugin_vars) {
		return false;
	}
	// Plugin provided variables, add them to the function
	RListIter *iter;
	RAnalVarProt *prot;
	r_list_foreach (plugin_vars, iter, prot) {
		if (prot && prot->name) {
			r_anal_function_set_var (fcn, prot->delta, prot->kind,
				prot->type, 0, prot->isarg, prot->name);
		}
	}
	r_list_free (plugin_vars);
	return true;
}

