/* radare - LGPL - Copyright 2021-2026 - pancake */

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

// Returns plugin priority score: >0 = eligible (higher first), 0 = eligible default, <0 = ineligible
static int plugin_score(RAnal *anal, RAnalPlugin *p) {
	R_RETURN_VAL_IF_FAIL (anal && p, -1);
	if (p->eligible) {
		return p->eligible (anal);
	}
	return 0; // no callback = eligible, default priority
}

static bool plugin_is_eligible(RAnal *anal, RAnalPlugin *p) {
	return plugin_score (anal, p) >= 0;
}

static bool plugin_has_callback(RAnalPlugin *p, RAnalPluginAction action) {
	R_RETURN_VAL_IF_FAIL (p, false);
	switch (action) {
	case R_ANAL_PLUGIN_ACTION_ANALYZE_FCN:
		return p->analyze_fcn != NULL;
	case R_ANAL_PLUGIN_ACTION_RECOVER_VARS:
		return p->recover_vars != NULL;
	case R_ANAL_PLUGIN_ACTION_GET_DATA_REFS:
		return p->get_data_refs != NULL;
	case R_ANAL_PLUGIN_ACTION_POST_ANALYSIS:
		return p->post_analysis != NULL;
	}
	return false;
}

static bool plugin_in_list(RList *list, RAnalPlugin *plugin) {
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (list, iter, p) {
		if (p == plugin) {
			return true;
		}
	}
	return false;
}

static RAnalPlugin *plugin_find_by_name(RAnal *anal, const char *name) {
	RListIter *iter;
	RAnalPlugin *p;
	r_list_foreach (anal->plugins, iter, p) {
		if (!strcmp (p->meta.name, name)) {
			return p;
		}
	}
	return NULL;
}

static void plugin_append_if_valid(RList *list, RAnal *anal, RAnalPlugin *p, RAnalPluginAction action) {
	R_RETURN_IF_FAIL (list && anal && p);
	if (!plugin_has_callback (p, action)) {
		return;
	}
	if (!plugin_is_eligible (anal, p)) {
		return;
	}
	if (plugin_in_list (list, p)) {
		return;
	}
	r_list_append (list, p);
}

typedef struct {
	int score;
	RAnalPlugin *plugin;
} ScoredPlugin;

// Sort comparator: higher score first (descending); equal scores keep registration order (stable mergesort)
static int scored_plugin_cmp(const void *a, const void *b) {
	const ScoredPlugin *sa = (const ScoredPlugin *)a;
	const ScoredPlugin *sb = (const ScoredPlugin *)b;
	return sb->score - sa->score; // descending
}

// Append all eligible plugins sorted by score (higher priority first).
// Plugins already in `list` (from explicit config names) are skipped.
static void plugin_append_all(RList *list, RAnal *anal, RAnalPluginAction action) {
	RListIter *iter;
	RAnalPlugin *p;
	RList *scored = r_list_newf (free);
	r_list_foreach (anal->plugins, iter, p) {
		if (!plugin_has_callback (p, action)) {
			continue;
		}
		int sc = plugin_score (anal, p);
		if (sc < 0) {
			continue;
		}
		if (plugin_in_list (list, p)) {
			continue;
		}
		ScoredPlugin *sp = R_NEW (ScoredPlugin);
		sp->score = sc;
		sp->plugin = p;
		r_list_append (scored, sp);
	}
	// r_list_sort is a stable mergesort, so equal scores keep registration order
	r_list_sort (scored, (RListComparator)scored_plugin_cmp);
	ScoredPlugin *sp;
	r_list_foreach (scored, iter, sp) {
		r_list_append (list, sp->plugin);
	}
	r_list_free (scored);
}

static const char *plugin_action_config_key(RAnalPluginAction action) {
	switch (action) {
	case R_ANAL_PLUGIN_ACTION_ANALYZE_FCN:
		return "anal.plugins.fcn";
	case R_ANAL_PLUGIN_ACTION_RECOVER_VARS:
		return "anal.plugins.vars";
	case R_ANAL_PLUGIN_ACTION_GET_DATA_REFS:
		return "anal.plugins.datarefs";
	case R_ANAL_PLUGIN_ACTION_POST_ANALYSIS:
		return "anal.plugins.post";
	}
	return NULL;
}

// Build ordered plugin list from config or fall back to NULL (= use registration order).
// Order: explicit config names first, then '*' expands to remaining eligible sorted by score.
static RList *plugin_order_list(RAnal *anal, RAnalPluginAction action) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	const char *cfg = NULL;
	const char *cfgkey = plugin_action_config_key (action);
	if (cfgkey && anal->coreb.cfgGet && anal->coreb.core) {
		cfg = anal->coreb.cfgGet (anal->coreb.core, cfgkey);
	}
	if (R_STR_ISEMPTY (cfg)) {
		return NULL;
	}
	RList *names = r_str_split_duplist (cfg, ",", true);
	if (!names) {
		return NULL;
	}
	RList *plugins = r_list_new ();
	RListIter *iter;
	char *name;
	r_list_foreach (names, iter, name) {
		if (R_STR_ISEMPTY (name)) {
			continue;
		}
		if (!strcmp (name, "*")) {
			plugin_append_all (plugins, anal, action);
			continue;
		}
		RAnalPlugin *p = plugin_find_by_name (anal, name);
		if (p) {
			plugin_append_if_valid (plugins, anal, p, action);
		}
	}
	r_list_free (names);
	return plugins;
}

static void merge_refs(RVecAnalRef **all_refs, RVecAnalRef *refs) {
	if (all_refs && refs) {
		if (*all_refs) {
			RAnalRef *ref;
			R_VEC_FOREACH (refs, ref) {
				RVecAnalRef_push_back (*all_refs, ref);
			}
			RVecAnalRef_free (refs);
		} else {
			*all_refs = refs;
		}
	}
}

// Unified plugin action dispatcher.
// For ANALYZE_FCN and POST_ANALYSIS: calls all eligible plugins (returns NULL).
// For RECOVER_VARS: returns first non-NULL RList* of vars from an eligible plugin.
// For GET_DATA_REFS: returns merged RVecAnalRef* from all eligible plugins.
R_API void *r_anal_plugin_action(RAnal *anal, RAnalPluginAction action, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RList *ordered = plugin_order_list (anal, action);
	RListIter *iter;
	RAnalPlugin *p;
	RVecAnalRef *all_refs = NULL;

	if (ordered) {
		r_list_foreach (ordered, iter, p) {
			switch (action) {
			case R_ANAL_PLUGIN_ACTION_ANALYZE_FCN:
				p->analyze_fcn (anal, fcn);
				break;
			case R_ANAL_PLUGIN_ACTION_RECOVER_VARS:
				{
					RList *vars = p->recover_vars (anal, fcn);
					if (vars) {
						r_list_free (ordered);
						return vars;
					}
				}
				break;
			case R_ANAL_PLUGIN_ACTION_GET_DATA_REFS:
				merge_refs (&all_refs, p->get_data_refs (anal, fcn));
				break;
			case R_ANAL_PLUGIN_ACTION_POST_ANALYSIS:
				p->post_analysis (anal);
				break;
			}
		}
		r_list_free (ordered);
		return all_refs; // non-NULL only for GET_DATA_REFS
	}

	// Fallback: iterate all plugins in registration order with eligibility check
	r_list_foreach (anal->plugins, iter, p) {
		if (!plugin_has_callback (p, action) || !plugin_is_eligible (anal, p)) {
			continue;
		}
		switch (action) {
		case R_ANAL_PLUGIN_ACTION_ANALYZE_FCN:
			p->analyze_fcn (anal, fcn);
			break;
		case R_ANAL_PLUGIN_ACTION_RECOVER_VARS:
			{
				RList *vars = p->recover_vars (anal, fcn);
				if (vars) {
					return vars;
				}
			}
			break;
		case R_ANAL_PLUGIN_ACTION_GET_DATA_REFS:
			merge_refs (&all_refs, p->get_data_refs (anal, fcn));
			break;
		case R_ANAL_PLUGIN_ACTION_POST_ANALYSIS:
			p->post_analysis (anal);
			break;
		}
	}
	return all_refs; // non-NULL only for GET_DATA_REFS
}

// Apply plugin-recovered variables to a function
// Returns true if a plugin provided variables, false to fall back to default recovery
R_API bool r_anal_function_recover_vars_plugin(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, false);
	RList *plugin_vars = r_anal_plugin_action (anal, R_ANAL_PLUGIN_ACTION_RECOVER_VARS, fcn);
	if (!plugin_vars) {
		return false;
	}
	RListIter *iter;
	RAnalVarProt *prot;
	r_list_foreach (plugin_vars, iter, prot) {
		if (prot && prot->name) {
			r_anal_function_set_var (fcn, prot->delta, prot->kind, prot->type, 0, prot->isarg, prot->name);
		}
	}
	r_list_free (plugin_vars);
	return true;
}
