/* radare - LGPL - Copyright 2009-2026 - pancake, nibble */
/* Autoname analysis plugin: names functions based on references */

#define R_LOG_ORIGIN "anal.autoname"

#include <r_anal.h>
#include <r_core.h>

static const char *blacklist[] = {
	"0x", "*", "func.", "\\", "fcn.0", "plt", "assert",
	"__stack_chk_guard", "__stderrp", "__stdinp", "__stdoutp",
	"_DefaultRuneLocale"
};

static bool blacklisted_word(const char *name) {
	if (!*name || *name == ';') {
		return true;
	}
	if (r_str_startswith (name, "arg")) {
		return true;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (blacklist); i++) {
		if (strstr (name, blacklist[i])) {
			return true;
		}
	}
	return false;
}

static bool is_valid_name(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const char *p;
	for (p = name; *p; p++) {
		if (!IS_PRINTABLE (*p)) {
			return false;
		}
	}
	if (r_str_startswith (name, "str.") || r_str_startswith (name, "func.") || r_str_startswith (name, "fcn.")) {
		return false;
	}
	return !blacklisted_word (name);
}

static inline ut64 cmpstrings(const void *a) {
	return r_str_hash64 (a);
}

static char *pick_best_name(RList *names) {
	RListIter *iter;
	char *n, *best = NULL;
	r_list_foreach (names, iter, n) {
		if (is_valid_name (n) && (!best || strlen (n) < strlen (best))) {
			free (best);
			best = strdup (n);
		}
	}
	if (!best) {
		const char *first = r_list_first (names);
		best = first ? strdup (first) : NULL;
	}
	return best;
}

// Fast path: use xrefs/flags to derive a function name
static char *autoname_fast(RAnal *anal, RAnalFunction *fcn, int mode) {
	RList *names = r_list_newf (free);
	if (!names) {
		return NULL;
	}
	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			const int type = ref->type & R_ANAL_REF_TYPE_MASK;
			if (type != R_ANAL_REF_TYPE_CODE && type != R_ANAL_REF_TYPE_CALL &&
				type != R_ANAL_REF_TYPE_ICOD && type != R_ANAL_REF_TYPE_JUMP) {
				continue;
			}
			RFlagItem *f = anal->flb.get_at ? anal->flb.get_at (anal->flb.f, ref->addr, false) : NULL;
			if (!f || blacklisted_word (f->name)) {
				continue;
			}
			const char *dot = r_str_rchr (f->name, NULL, '.');
			const char *base = dot ? dot + 1 : f->name;
			char *filtered = r_name_filter_dup (base);
			if (filtered) {
				r_list_append (names, r_str_newf ("auto.sub.%s", filtered));
				free (filtered);
			}
		}
		RVecAnalRef_free (refs);
	}
	if (!blacklisted_word (fcn->name)) {
		char *filtered = r_name_filter_dup (fcn->name);
		if (filtered) {
			r_list_append (names, filtered);
		}
	}
	r_list_uniq_inplace (names, cmpstrings);
	char *result = NULL;
	if (mode == 'l') {
		RCore *core = anal->coreb.core;
		RListIter *iter;
		char *n;
		r_list_foreach (names, iter, n) {
			r_cons_println (core->cons, n);
		}
	} else {
		result = pick_best_name (names);
	}
	r_list_free (names);
	return result;
}

// Slow path: use emulation (pdsfq) to resolve more string references
static char *autoname_slow(RAnal *anal, RAnalFunction *fcn, int mode) {
	if (!anal->coreb.cmdStr) {
		return autoname_fast (anal, fcn, mode);
	}
	void *core = anal->coreb.core;
	RList *names = r_list_newf (free);
	if (!names) {
		return NULL;
	}
	if (!blacklisted_word (fcn->name)) {
		char *filtered = r_name_filter_dup (fcn->name);
		if (filtered) {
			r_list_append (names, filtered);
		}
	}
	char *bestname = NULL;
	char *fd_cmd = r_str_newf ("fd @ 0x%08"PFMT64x, fcn->addr);
	char *fd = anal->coreb.cmdStr (core, fd_cmd);
	free (fd_cmd);
	if (fd && r_str_startswith (fd, "sym.") && !r_str_startswith (fd, "sym.func.")) {
		r_str_trim (fd);
		char *filtered = r_name_filter_dup (fd);
		if (filtered) {
			r_list_append (names, filtered);
			bestname = strdup (filtered);
		}
	}
	free (fd);

	int scr_color = anal->coreb.cfgGetI ? anal->coreb.cfgGetI (core, "scr.color") : 0;
	if (anal->coreb.cmd) {
		anal->coreb.cmd (core, "e scr.color=0");
	}
	char *pdsfq_cmd = r_str_newf ("pdsfq @ 0x%08"PFMT64x, fcn->addr);
	char *pdsfq = anal->coreb.cmdStr (core, pdsfq_cmd);
	free (pdsfq_cmd);
	if (anal->coreb.cmd) {
		char *restore = r_str_newf ("e scr.color=%d", scr_color);
		anal->coreb.cmd (core, restore);
		free (restore);
	}
	RList *strings = r_str_split_list (pdsfq ? pdsfq : "", "\n", 0);
	RListIter *iter;
	char *name;
	r_list_foreach (strings, iter, name) {
		r_str_trim (name);
		char *fcn0 = strstr (name, "fcn.0");
		if (fcn0) {
			*fcn0 = 0;
		}
		if (blacklisted_word (name)) {
			continue;
		}
		char *bra = strchr (name, '[');
		if (bra) {
			r_str_cpy (name, bra + 1);
		} else {
			char *dot = strchr (name, '.');
			if (dot) {
				name = dot + 1;
			}
		}
		if (*name) {
			char *filtered = r_name_filter_dup (name);
			if (filtered) {
				r_list_append (names, strdup (filtered));
				free (filtered);
			}
		}
	}
	r_list_free (strings);
	free (pdsfq);

	bool use_getopt = false;
	r_list_uniq_inplace (names, cmpstrings);
	r_list_foreach (names, iter, name) {
		if (mode == 'l' || mode == 's') {
			r_cons_println (((RCore *)core)->cons, name);
		}
		if (strstr (name, "getopt") || strstr (name, "optind")) {
			use_getopt = true;
		} else if (r_str_startswith (name, "reloc.")) {
			name += 6;
		} else if (r_str_startswith (name, "sym.imp.")) {
			name += 4;
		} else if (r_str_startswith (name, "sym.")) {
			name += 4;
		} else if (r_str_startswith (name, "imp.")) {
			name += 4;
		}
		if (!bestname) {
			bestname = strdup (name);
		}
	}
	r_list_free (names);

	if (use_getopt) {
		if (bestname && !strcmp (bestname, "main")) {
			return bestname;
		}
		free (bestname);
		return strdup ("main_args");
	}
	if (bestname) {
		if (r_str_startswith (bestname, "sym.")) {
			return bestname;
		}
		if (r_str_startswith (bestname, "imp.")) {
			char *bn = r_str_newf ("sym.%s", bestname);
			free (bestname);
			return bn;
		}
		char *ret = r_str_startswith (bestname, "sub.")
			? r_str_newf ("%s_%"PFMT64x, bestname, fcn->addr)
			: r_str_newf ("sub.%s_%"PFMT64x, bestname, fcn->addr);
		free (bestname);
		return ret;
	}
	return NULL;
}

static char *autoname_fcn(RAnal *anal, RAnalFunction *fcn, int mode) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	bool slow = anal->coreb.cfgGetB ? anal->coreb.cfgGetB (anal->coreb.core, "anal.slow") : false;
	return slow ? autoname_slow (anal, fcn, mode) : autoname_fast (anal, fcn, mode);
}

static void autoname_all(RAnal *anal) {
	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, it, fcn) {
		if (!r_str_startswith (fcn->name, "fcn.") && !r_str_startswith (fcn->name, "sym.func.")) {
			continue;
		}
		char *name = autoname_fcn (anal, fcn, 0);
		if (!name) {
			continue;
		}
		if (anal->flb.f && anal->coreb.cmd) {
			char *cmd = r_str_newf ("fr %s %s", fcn->name, name);
			anal->coreb.cmd (anal->coreb.core, cmd);
			free (cmd);
		}
		free (fcn->name);
		fcn->name = name;
	}
}

static char *autonamecmd(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, "autoname")) {
		return NULL;
	}
	static RCoreHelpMessage help_msg = {
		"Usage:", "a:autoname", "[subcmd]",
		"a:autoname", "", "autoname function at current offset",
		"a:autoname", " all", "autoname all fcn.*/sym.func.* functions",
		"a:autoname", " list", "list candidate names for function at current offset",
		NULL
	};
	const char *arg = r_str_trim_head_ro (input + 8);

	if (*arg == '?' || (!*arg && !anal->coreb.numGet)) {
		if (anal->coreb.help) {
			anal->coreb.help (anal->coreb.core, help_msg);
		}
		return strdup ("");
	}
	if (!*arg || r_str_startswith (arg, "list")) {
		int mode = *arg ? 'l' : 'v';
		ut64 addr = anal->coreb.numGet (anal->coreb.core, "$$");
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
		if (fcn) {
			char *name = autoname_fcn (anal, fcn, mode);
			if (name && mode == 'v') {
				char *res = r_str_newf ("'0x%08"PFMT64x"'afnq %s", fcn->addr, name);
				free (name);
				return res;
			}
			free (name);
		} else {
			R_LOG_ERROR ("No function at 0x%08"PFMT64x, addr);
		}
		return strdup ("");
	}
	if (r_str_startswith (arg, "fcn ")) {
		const char *p = r_str_trim_head_ro (arg + 4);
		ut64 addr = r_num_get (NULL, p);
		const char *sp = strchr (p, ' ');
		int mode = (sp && sp[1] && sp[1] != '0') ? sp[1] : 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
		if (fcn) {
			char *name = autoname_fcn (anal, fcn, mode);
			return name ? name : strdup ("");
		}
		return strdup ("");
	}
	if (r_str_startswith (arg, "all")) {
		autoname_all (anal);
		return strdup ("");
	}
	if (anal->coreb.help) {
		anal->coreb.help (anal->coreb.core, help_msg);
	}
	return strdup ("");
}

RAnalPlugin r_anal_plugin_autoname = {
	.meta = {
		.name = "autoname",
		.author = "pancake",
		.desc = "Automatic function naming based on references and emulation",
		.license = "LGPL3",
	},
	.cmd = autonamecmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_autoname,
	.version = R2_VERSION
};
#endif
