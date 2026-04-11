/* radare - LGPL - Copyright 2009-2026 - pancake, nibble */
/* Autoname analysis plugin.
 *
 * Score-based strategy: several collectors push naming candidates into a
 * shared bag with a weight; duplicates accumulate so repeated hints
 * reinforce each other; the highest ranked name wins. Adding a new
 * heuristic only requires calling cand_add() from a new collector.
 *
 * Sources (all arch-agnostic, metadata only):
 *   - outgoing refs: callees (flags) and string literals (meta strings)
 *   - incoming xrefs: the sole named caller when there is exactly one
 *   - string shape: "foo:", "foo()", "... foo failed" → __func__-style
 */

#define R_LOG_ORIGIN "anal.autoname"

#include <r_anal.h>
#include <r_core.h>

/* scoring weights, tuned so strong signals outrank noise */
#define W_FUNCTAG   100 /* string of the form "name:" / "name()" */
#define W_SYMIMP     70 /* lone sym.imp.* callee (plt thunk) */
#define W_SOLECALL   55 /* unique meaningful callee */
#define W_IDENT      40 /* string is a clean identifier */
#define W_CALLER     30 /* unique named caller */
#define W_CALLEE     20 /* any callee flag */
#define W_TOKEN      10 /* first ident token of other strings */

typedef struct {
	char *name;
	int score;
} ANCand;

static const char *blacklist[] = {
	"0x", "*", "func.", "\\", "fcn.0", "plt", "assert",
	"segment.", "section.", "LOAD", "entry.",
	"__stack_chk_guard", "__stack_chk_fail",
	"__stderrp", "__stdinp", "__stdoutp", "_DefaultRuneLocale"
};

static bool blacklisted(const char *n) {
	if (R_STR_ISEMPTY (n) || *n == ';' || r_str_startswith (n, "arg")) {
		return true;
	}
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (blacklist); i++) {
		if (strstr (n, blacklist[i])) {
			return true;
		}
	}
	return false;
}

static bool valid_ident(const char *n) {
	if (R_STR_ISEMPTY (n)
		|| r_str_startswith (n, "str.")
		|| r_str_startswith (n, "func.")
		|| r_str_startswith (n, "fcn.")) {
		return false;
	}
	const char *p;
	for (p = n; *p; p++) {
		if (!IS_PRINTABLE (*p)) {
			return false;
		}
	}
	return !blacklisted (n);
}

/* collapse equivalent candidates by peeling radare2 name prefixes */
static const char *strip_prefix(const char *s) {
	static const char *pfx[] = {
		"sym.imp.", "sym.func.", "reloc.", "auto.sub.", "sub.",
		"imp.", "sym.", "str.", "obj.", NULL
	};
	bool changed = true;
	while (changed) {
		changed = false;
		size_t i;
		for (i = 0; pfx[i]; i++) {
			size_t n = strlen (pfx[i]);
			if (!strncmp (s, pfx[i], n)) {
				s += n;
				changed = true;
			}
		}
	}
	return s;
}

/* Strip trailing "_<hex>" address suffixes from a derived name so that
 * "free_46b0" collapses to "free" when reused as a base name. */
static void strip_addr_tail(char *name) {
	for (;;) {
		char *p = strrchr (name, '_');
		if (!p || p == name) {
			return;
		}
		const char *h;
		size_t n = 0;
		for (h = p + 1; *h; h++, n++) {
			if (!isxdigit ((unsigned char)*h)) {
				return;
			}
		}
		if (n < 3 || n > 16) {
			return;
		}
		*p = 0;
	}
}

static void cand_free(void *p) {
	ANCand *c = p;
	if (c) {
		free (c->name);
		free (c);
	}
}

static void cand_add(RList *bag, const char *raw, int score) {
	if (!raw || !*raw || score <= 0) {
		return;
	}
	const char *base = strip_prefix (raw);
	if (!*base || blacklisted (base)) {
		return;
	}
	char *name = r_name_filter_dup (base);
	if (!name) {
		return;
	}
	strip_addr_tail (name);
	if (!valid_ident (name) || strlen (name) > 48) {
		free (name);
		return;
	}
	RListIter *it;
	ANCand *c;
	r_list_foreach (bag, it, c) {
		if (!strcmp (c->name, name)) {
			c->score += score;
			free (name);
			return;
		}
	}
	c = R_NEW0 (ANCand);
	if (!c) {
		free (name);
		return;
	}
	c->name = name;
	c->score = score;
	r_list_append (bag, c);
}

static int cand_cmp(const void *a, const void *b) {
	const ANCand *ca = a, *cb = b;
	if (ca->score != cb->score) {
		return cb->score - ca->score;
	}
	size_t la = strlen (ca->name), lb = strlen (cb->name);
	return (la != lb)? (int)(la - lb): strcmp (ca->name, cb->name);
}

/* Digest a string literal into 0..1 candidate(s).
 * Detects __func__-style tags ("name:", "name()", "... name failed"),
 * pure identifiers, and the first identifier-like token as fallback. */
static void digest_string(const char *s, RList *bag) {
	if (!s || !*s) {
		return;
	}
	while (*s == ' ' || *s == '\t') {
		s++;
	}
	const char *start = s, *p = s;
	while (*p && (isalnum ((unsigned char)*p) || *p == '_')) {
		p++;
	}
	size_t len = p - start;
	if (len >= 3 && len <= 48 && isalpha ((unsigned char)*start)) {
		bool tag = (*p == ':')
			|| (p[0] == '(' && p[1] == ')')
			|| (*p == ' ' && (strstr (p, "failed") || strstr (p, "error")));
		if (tag) {
			char *t = r_str_ndup (start, len);
			cand_add (bag, t, W_FUNCTAG);
			free (t);
			return;
		}
		/* pure identifier: no spaces, no %, no punctuation */
		if (!*p) {
			cand_add (bag, start, W_IDENT);
			return;
		}
	}
	/* generic fallback: first ident-looking token */
	while (*s && !(isalnum ((unsigned char)*s) || *s == '_')) {
		s++;
	}
	start = s;
	while (*s && (isalnum ((unsigned char)*s) || *s == '_')) {
		s++;
	}
	len = s - start;
	if (len >= 3 && len <= 32 && isalpha ((unsigned char)*start)) {
		char *t = r_str_ndup (start, len);
		int w = strchr (start, '%') ? W_TOKEN / 2 : W_TOKEN;
		cand_add (bag, t, w);
		free (t);
	}
}

/* Pull candidates from everything the function references or is referenced by. */
static void collect(RAnal *a, RAnalFunction *fcn, RList *bag) {
	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (refs) {
		int n_call = 0, n_sym = 0;
		const char *sole_call = NULL, *sole_sym = NULL;
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			const int t = ref->type & R_ANAL_REF_TYPE_MASK;
			RFlagItem *f = a->flb.get_at
				? a->flb.get_at (a->flb.f, ref->addr, false) : NULL;
			if (t == R_ANAL_REF_TYPE_CALL || t == R_ANAL_REF_TYPE_ICOD
				|| t == R_ANAL_REF_TYPE_CODE || t == R_ANAL_REF_TYPE_JUMP) {
				if (f && !blacklisted (f->name)) {
					cand_add (bag, f->name, W_CALLEE);
					n_call++;
					sole_call = f->name;
					if (r_str_startswith (f->name, "sym.")) {
						n_sym++;
						sole_sym = f->name;
					}
				}
			} else if (t == R_ANAL_REF_TYPE_DATA || t == R_ANAL_REF_TYPE_STRN) {
				const char *s = r_meta_get_string (a, R_META_TYPE_STRING, ref->addr);
				if (s) {
					digest_string (s, bag);
				} else if (f && !blacklisted (f->name)) {
					/* obj.* / sym.* data symbols: solid hints */
					if (r_str_startswith (f->name, "obj.")
						|| r_str_startswith (f->name, "sym.")
						|| r_str_startswith (f->name, "reloc.")) {
						cand_add (bag, f->name, W_IDENT);
					} else if (r_str_startswith (f->name, "str.")) {
						cand_add (bag, f->name + 4, W_TOKEN);
					}
				}
			}
		}
		if (n_call == 1 && sole_call) {
			cand_add (bag, sole_call, W_SOLECALL);
		}
		if (n_sym == 1 && sole_sym) {
			cand_add (bag, sole_sym, W_SYMIMP);
		}
		RVecAnalRef_free (refs);
	}
	RVecAnalRef *xrefs = r_anal_function_get_xrefs (fcn);
	if (xrefs) {
		int n = 0;
		const char *sole = NULL;
		RAnalRef *ref;
		R_VEC_FOREACH (xrefs, ref) {
			const int t = ref->type & R_ANAL_REF_TYPE_MASK;
			if (t != R_ANAL_REF_TYPE_CALL && t != R_ANAL_REF_TYPE_ICOD) {
				continue;
			}
			RAnalFunction *c = r_anal_get_fcn_in (a, ref->at, 0);
			if (!c || !c->name
				|| r_str_startswith (c->name, "fcn.")
				|| r_str_startswith (c->name, "sym.func.")
				|| r_str_startswith (c->name, "sub.")
				|| r_str_startswith (c->name, "auto.sub.")) {
				continue;
			}
			n++;
			sole = c->name;
		}
		if (n == 1 && sole) {
			cand_add (bag, sole, W_CALLER);
		}
		RVecAnalRef_free (xrefs);
	}
}

static char *autoname_fcn(RAnal *anal, RAnalFunction *fcn, int mode) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	/* Never override an already meaningful name. Only fcn. and
	 * sym.func. prefixed functions are considered unnamed. */
	if (mode != 'l' && mode != 's'
		&& !r_str_startswith (fcn->name, "fcn.")
		&& !r_str_startswith (fcn->name, "sym.func.")) {
		return NULL;
	}
	RList *bag = r_list_newf (cand_free);
	if (!bag) {
		return NULL;
	}
	collect (anal, fcn, bag);
	r_list_sort (bag, cand_cmp);

	if (mode == 'l' || mode == 's') {
		RCore *core = anal->coreb.core;
		RListIter *it;
		ANCand *c;
		r_list_foreach (bag, it, c) {
			if (core && core->cons) {
				r_cons_printf (core->cons, "%4d %s\n", c->score, c->name);
			}
		}
	}

	char *result = NULL;
	ANCand *best = r_list_first (bag);
	if (best) {
		/* Always suffix with the function address to guarantee that the
		 * resulting flag is unique across the whole binary. */
		result = r_str_newf ("sub.%s_%"PFMT64x, best->name, fcn->addr);
	}
	r_list_free (bag);
	return result;
}

static void autoname_all(RAnal *anal) {
	/* Two passes: when fcn A calls B and B is processed first, A will
	 * pick up B's freshly assigned name in the second pass. */
	int pass;
	for (pass = 0; pass < 2; pass++) {
		RListIter *it;
		RAnalFunction *fcn;
		bool changed = false;
		r_list_foreach (anal->fcns, it, fcn) {
			if (!r_str_startswith (fcn->name, "fcn.")
				&& !r_str_startswith (fcn->name, "sym.func.")) {
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
			changed = true;
		}
		if (!changed) {
			break;
		}
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
		"a:autoname", " list", "list ranked candidate names for current function",
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
		.desc = "Score-based function autonaming from refs, strings and callers",
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
