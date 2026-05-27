/* radare - LGPL - Copyright 2011-2021 - pancake, Oddcoder */

/* Universal calling convention implementation based on sdb */

#include <r_anal_priv.h>
#define DB anal->sdb_cc

static const char *cc_from_static_loc(RAnal *anal, const char *loc) {
	if (!loc) {
		return NULL;
	}
	if (!strcmp (loc, "stack")) {
		return r_str_constpool_get (&anal->constpool, "^");
	}
	if (!strcmp (loc, "stack_rev")) {
		return r_str_constpool_get (&anal->constpool, "^-");
	}
	if (r_str_startswith (loc, "stack_rev") && isdigit ((ut8)loc[9])) {
		r_strf_var (name, 64, "^-%s", loc + 9);
		return r_str_constpool_get (&anal->constpool, name);
	}
	if (r_str_startswith (loc, "stack") && isdigit ((ut8)loc[5])) {
		r_strf_var (name, 64, "^%s", loc + 5);
		return r_str_constpool_get (&anal->constpool, name);
	}
	return r_str_constpool_get (&anal->constpool, loc);
}

static bool cc_parse_int(const char **sp, int *out) {
	const char *s = *sp;
	ut64 n = 0;
	if (!isdigit ((ut8)*s)) {
		return false;
	}
	while (isdigit ((ut8)*s)) {
		n = (n * 10) + (*s++ - '0');
		if (n > ST32_MAX) {
			return false;
		}
	}
	*out = (int)n;
	*sp = s;
	return true;
}

static const char *cc_group_next(const char *s, const char *end) {
	const char *p = s;
	for (; p < end; p++) {
		if (*p == ',') {
			return p;
		}
		if (*p == ':') {
			const char *n = s;
			while (n < p && isdigit ((ut8)*n)) {
				n++;
			}
			if (n != p) {
				return p;
			}
		}
	}
	return p;
}

static bool cc_location_range(const char *loc, const char **s, const char **end) {
	size_t len = strlen (loc);
	if (len < 2 || loc[0] != '{' || loc[len - 1] != '}') {
		return false;
	}
	*s = loc + 1;
	*end = loc + len - 1;
	return true;
}

static const char *cc_location_next(RAnal *anal, const char **sp, const char *end) {
	const char *s = *sp;
	const char *next = cc_group_next (s, end);
	const char *e = next;
	while (s < end && isspace ((ut8)*s)) {
		s++;
	}
	while (e > s && isspace ((ut8)e[-1])) {
		e--;
	}
	if (s >= e) {
		return NULL;
	}
	if (isdigit ((ut8)*s)) {
		const char *p = s;
		int n = 0;
		if (cc_parse_int (&p, &n) && p < e && *p == ':') {
			s = p + 1;
		}
	}
	const char *dot = e;
	while (dot > s && isdigit ((ut8)dot[-1])) {
		dot--;
	}
	if (dot > s && dot[-1] == '.') {
		const char *p = dot;
		int n = 0;
		if (cc_parse_int (&p, &n) && p == e) {
			e = dot - 1;
		}
	}
	*sp = next + (next < end);
	char *name = r_str_ndup (s, e - s);
	const char *ret = cc_from_static_loc (anal, name);
	free (name);
	return ret;
}

R_API const char *r_anal_cc_location_first(RAnal *anal, const char *loc) {
	R_RETURN_VAL_IF_FAIL (anal && loc, NULL);
	if (*loc && *loc != '{') {
		return cc_from_static_loc (anal, loc);
	}
	const char *s, *end;
	return cc_location_range (loc, &s, &end) && s < end? cc_location_next (anal, &s, end): NULL;
}

R_IPI bool r_anal_cc_location_uses(RAnal *anal, const char *loc, const char *reg) {
	R_RETURN_VAL_IF_FAIL (anal && loc && reg, false);
	if (*loc && *loc != '{') {
		const char *first = r_anal_cc_location_first (anal, loc);
		return first && !strcmp (first, reg);
	}
	const char *s, *end;
	if (!cc_location_range (loc, &s, &end)) {
		return false;
	}
	while (s < end) {
		const char *name = cc_location_next (anal, &s, end);
		if (!name) {
			return false;
		}
		if (!strcmp (name, reg)) {
			return true;
		}
	}
	return false;
}

R_API void r_anal_cc_del(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	size_t i;
	RStrBuf sb;
	sdb_unset (DB, r_strbuf_initf (&sb, "%s", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.ret", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.retn", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.argn", name), 0);
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.arg%u", name, (unsigned int)i), 0);
		sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.ret%u", name, (unsigned int)i), 0);
	}
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.self", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.error", name), 0);
	r_strbuf_fini (&sb);
}

R_API bool r_anal_cc_set(RAnal *anal, const char *expr) {
	R_RETURN_VAL_IF_FAIL (anal && expr, false);
	char *e = strdup (expr);
	char *p = strchr (e, '(');
	if (!p) {
		free (e);
		return false;
	}
	*p++ = 0;
	char *args = strdup (p);
	r_str_trim (p);
	char *end = strchr (args, ')');
	if (!end) {
		free (args);
		free (e);
		return false;
	}
	*end++ = 0;
	r_str_trim (p);
	r_str_trim (e);
	char *ccname = strchr (e, ' ');
	if (ccname) {
		*ccname++ = 0;
		r_str_trim (ccname);
	} else {
		free (args);
		free (e);
		return false;
	}
	sdb_set (DB, ccname, "cc", 0);
	r_strf_buffer (64);
	sdb_unset (DB, r_strf ("cc.%s.ret", ccname), 0);
	int i;
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, r_strf ("cc.%s.ret%d", ccname, i), 0);
	}
	if (strchr (e, ',')) {
		RList *ccRets = r_str_split_list (e, ",", 0);
		RListIter *iter;
		char *ret;
		int n = 0;
		r_list_foreach (ccRets, iter, ret) {
			r_str_trim (ret);
			sdb_set (DB, r_strf ("cc.%s.ret%d", ccname, n), ret, 0);
			n++;
		}
		sdb_num_set (DB, r_strf ("cc.%s.retn", ccname), n, 0);
		r_list_free (ccRets);
	} else {
		sdb_set (DB, r_strf ("cc.%s.ret0", ccname), e, 0);
		sdb_unset (DB, r_strf ("cc.%s.retn", ccname), 0);
	}

	RList *ccArgs = r_str_split_list (args, ",", 0);
	RListIter *iter;
	const char *arg;
	int n = 0;
	r_list_foreach (ccArgs, iter, arg) {
		if (!strcmp (arg, "stack")) {
			sdb_set (DB, r_strf ("cc.%s.argn", ccname), arg, 0);
		} else {
			sdb_set (DB, r_strf ("cc.%s.arg%d", ccname, n), arg, 0);
			n++;
		}
	}
	r_list_free (ccArgs);
	free (e);
	free (args);
	return true;
}

R_API bool r_anal_cc_once(RAnal *anal) {
	R_CRITICAL_ENTER (anal);
	bool res = sdb_add (DB, "warn", "once", 0);
	R_CRITICAL_LEAVE (anal);
	return res;
}

R_API void r_anal_cc_reset(RAnal *anal) {
	R_CRITICAL_ENTER (anal);
	sdb_reset (DB);
	R_CRITICAL_LEAVE (anal);
}

R_API void r_anal_cc_get_json(RAnal *anal, PJ *pj, const char *name) {
	R_RETURN_IF_FAIL (anal && pj && name);
	int i;
	// get cc by name and print the expr
	const char *cc_type = sdb_const_get (DB, name, 0);
	if (!cc_type || strcmp (cc_type, "cc")) {
		return;
	}
	const char *ret = r_anal_cc_ret (anal, name, 0);
	if (!ret) {
		return;
	}
	pj_ks (pj, "ret", ret);
	pj_ka (pj, "rets");
	int rn;
	for (rn = 0; ; rn++) {
		const char *r = r_anal_cc_ret (anal, name, rn);
		if (!r) {
			break;
		}
		pj_s (pj, r);
	}
	pj_end (pj);
	char *sig = r_anal_cc_get (anal, name);
	pj_ks (pj, "signature", sig);
	free (sig);
	pj_ka (pj, "args");
	const int max = r_anal_cc_max_arg (anal, name);
	for (i = 0; i < max; i++) {
		pj_s (pj, r_anal_cc_argloc (anal, name, i, 0, -1));
	}
	pj_end (pj);
	const char *argn = r_anal_cc_argloc (anal, name, max, 0, -1);
	if (argn) {
		pj_ks (pj, "argn", argn);
	}
	const char *error = r_anal_cc_roleloc (anal, name, "error");
	if (error) {
		pj_ks (pj, "error", error);
	}
}

R_API char *r_anal_cc_get(RAnal *anal, const char *name) {
	Sdb *db = anal->sdb_cc;
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);
	int i;
	// get cc by name and print the expr
	const char *cc = sdb_const_get (db, name, 0);
	if (cc && strcmp (cc, "cc")) {
		R_LOG_ERROR ("Invalid calling convention name (%s)", name);
		return NULL;
	}
	const char *ret = r_anal_cc_ret (anal, name, 0);
	if (!ret) {
		R_LOG_ERROR ("Cannot find return type for %s", name);
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new (NULL);
	const char *self = r_anal_cc_roleloc (anal, name, "self");
	// Multi-return: print "r0:r1:r2 ..."
	r_strbuf_appendf (sb, "%s", ret);
	int rn;
	for (rn = 1; ; rn++) {
		const char *rs = r_anal_cc_ret (anal, name, rn);
		if (!rs) {
			break;
		}
		r_strbuf_appendf (sb, ":%s", rs);
	}
	r_strbuf_appendf (sb, " %s%s%s (", r_str_get (self), self? ".": "", name);
	bool isFirst = true;
	bool revarg = false;
	{
		r_strf_var (k, 128, "cc.%s.revarg", name);
		const char *s = sdb_const_get (db, k, 0);
		revarg = r_str_is_true (s);
	}
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		r_strf_var (k, 128, "cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get (db, k, 0);
		if (!arg) {
			break;
		}
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", arg);
		isFirst = false;
	}
	r_strf_var (rename, 128, "cc.%s.argn", name);
	const char *argn = sdb_const_get (db, rename, 0);
	if (argn) {
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", argn);
	}
	r_strbuf_append (sb, ")");

	const char *error = r_anal_cc_roleloc (anal, name, "error");
	if (error) {
		r_strbuf_appendf (sb, " %s", error);
	}

	r_strbuf_append (sb, ";");
	if (revarg) {
		r_strbuf_append (sb, " // revarg");
	}
	return r_strbuf_drain (sb);
}

R_API bool r_anal_cc_exist(RAnal *anal, const char *cc) {
	R_RETURN_VAL_IF_FAIL (anal && cc, false);
	const char *x = sdb_const_get (DB, cc, 0);
	return (x != NULL) && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_argloc(RAnal *anal, const char *cc, int n, int home, int argc) {
	R_RETURN_VAL_IF_FAIL (anal && n >= 0 && home >= 0, NULL);
	if (!cc) {
		return NULL;
	}
	if (home > 0) {
		return NULL;
	}
	Sdb *db = DB;
	r_strf_buffer (64);
	if (argc > 0) {
		char *revarg = r_strf ("cc.%s.revarg", cc);
		if (r_str_is_true (sdb_const_get (db, revarg, 0))) {
			if (n >= argc) {
				return NULL;
			}
			n = argc - n - 1;
		}
	}
	char *query = r_strf ("cc.%s.arg%d", cc, n);
	const char *ret = sdb_const_get (db, query, 0);
	if (!ret) {
		query = r_strf ("cc.%s.argn", cc);
		ret = sdb_const_get (db, query, 0);
	}
	return ret? cc_from_static_loc (anal, ret): NULL;
}

R_API const char *r_anal_cc_arg(RAnal *anal, const char *cc, int n, int lastn) {
	return r_anal_cc_argloc (anal, cc, n, 0, lastn);
}

R_API const char *r_anal_cc_roleloc(RAnal *anal, const char *convention, const char *role) {
	R_RETURN_VAL_IF_FAIL (anal && convention && role, NULL);
	RStrBuf sb;
	const char *key = r_strbuf_initf (&sb, "cc.%s.%s", convention, role);
	const char *value = sdb_const_get (DB, key, 0);
	const char *res = value? cc_from_static_loc (anal, value): NULL;
	r_strbuf_fini (&sb);
	return res;
}

R_API const char *r_anal_cc_self(RAnal *anal, const char *convention) {
	return r_anal_cc_roleloc (anal, convention, "self");
}

static void cc_set_roleloc(RAnal *anal, const char *convention, const char *role, const char *loc) {
	if (!r_anal_cc_exist (anal, convention)) {
		return;
	}
	RStrBuf sb;
	sdb_set (DB, r_strbuf_initf (&sb, "cc.%s.%s", convention, role), loc, 0);
	r_strbuf_fini (&sb);
}

R_API void r_anal_cc_set_self(RAnal *anal, const char *convention, const char *self) {
	R_RETURN_IF_FAIL (anal && convention && self);
	cc_set_roleloc (anal, convention, "self", self);
}

R_API const char *r_anal_cc_error(RAnal *anal, const char *convention) {
	return r_anal_cc_roleloc (anal, convention, "error");
}

R_API void r_anal_cc_set_error(RAnal *anal, const char *convention, const char *error) {
	R_RETURN_IF_FAIL (anal && convention && error);
	cc_set_roleloc (anal, convention, "error", error);
}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int i = 0;
	R_RETURN_VAL_IF_FAIL (anal && DB && cc, 0);

	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		r_strf_var (query, 64, "cc.%s.arg%d", cc, i);
		const char *res = sdb_const_get (DB, query, 0);
		if (!res) {
			break;
		}
	}
	return i;
}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention, int n) {
	R_RETURN_VAL_IF_FAIL (anal && convention && n >= 0, NULL);
	r_strf_buffer (64);
	if (n > 0) {
		int retn = sdb_num_get (DB, r_strf ("cc.%s.retn", convention), 0);
		if (n >= retn) {
			return NULL;
		}
	}
	const char *ret = sdb_const_get (DB, r_strf ("cc.%s.ret%d", convention, n), 0);
	if (ret) {
		return ret;
	}
	if (n > 0) {
		return NULL;
	}
	return sdb_const_get (DB, r_strf ("cc.%s.ret", convention), 0);
}

R_API const char *r_anal_cc_default(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	return sdb_const_get (DB, "default.cc", 0);
}

R_API void r_anal_set_cc_default(RAnal *anal, const char *cc) {
	R_RETURN_IF_FAIL (anal && cc);
	sdb_set (DB, "default.cc", cc, 0);
}

R_API const char *r_anal_syscc_default(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	return sdb_const_get (DB, "default.syscc", 0);
}

R_API void r_anal_set_syscc_default(RAnal *anal, const char *cc) {
	R_RETURN_IF_FAIL (anal && cc);
	sdb_set (DB, "default.syscc", cc, 0);
}

R_API const char *r_anal_cc_func(RAnal *anal, const char *func_name) {
	R_RETURN_VAL_IF_FAIL (anal && func_name, NULL);
	r_strf_var (query, 64, "func.%s.cc", func_name);
	const char *cc = sdb_const_get (anal->sdb_types, query, 0);
	return cc ? cc : r_anal_cc_default (anal);
}
