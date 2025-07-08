/* radare - LGPL - Copyright 2011-2021 - pancake, Oddcoder */

/* Universal calling convention implementation based on sdb */

#include <r_anal.h>
#define DB anal->sdb_cc

R_API void r_anal_cc_del(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	size_t i;
	RStrBuf sb;
	sdb_unset (DB, r_strbuf_initf (&sb, "%s", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.ret", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.argn", name), 0);
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.arg%u", name, (unsigned int)i), 0);
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
	sdb_set (DB, r_strf ("cc.%s.ret", ccname), e, 0);

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
	r_strf_buffer (64);
	int i;
	// get cc by name and print the expr
	if (strcmp (sdb_const_get (DB, name, 0), "cc")) {
		return;
	}
	const char *ret = sdb_const_get (DB, r_strf ("cc.%s.ret", name), 0);
	if (!ret) {
		return;
	}
	pj_ks (pj, "ret", ret);
	const char *ret2 = sdb_const_get (DB, r_strf ("cc.%s.ret2", name), 0);
	if (ret2) {
		pj_ks (pj, "ret2", ret2);
	}
	char *sig = r_anal_cc_get (anal, name);
	pj_ks (pj, "signature", sig);
	free (sig);
	pj_ka (pj, "args");
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		const char *k = r_strf ("cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get (DB, k, 0);
		if (!arg) {
			break;
		}
		pj_s (pj, arg);
	}
	pj_end (pj);
	const char *argn = sdb_const_get (DB, r_strf ("cc.%s.argn", name), 0);
	if (argn) {
		pj_ks (pj, "argn", argn);
	}
	const char *error = r_anal_cc_error (anal, name);
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
	r_strf_var (ccret, 128, "cc.%s.ret", name);
	const char *ret = sdb_const_get (db, ccret, 0);
	if (!ret) {
		R_LOG_ERROR ("Cannot find return type for %s", name);
		return NULL;
	}
	r_strf_var (ccret2, 128, "cc.%s.ret2", name);
	const char *ret2 = sdb_const_get (db, ccret2, 0);

	RStrBuf *sb = r_strbuf_new (NULL);
	const char *self = r_anal_cc_self (anal, name);
	if (ret2) {
		r_strbuf_appendf (sb, "%s:%s %s%s%s (", ret, ret2, r_str_get (self), self? ".": "", name);
	} else {
		r_strbuf_appendf (sb, "%s %s%s%s (", ret, r_str_get (self), self? ".": "", name);
	}
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

	const char *error = r_anal_cc_error (anal, name);
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

R_API const char *r_anal_cc_arg(RAnal *anal, const char *cc, int n, int lastn) {
	R_RETURN_VAL_IF_FAIL (anal && n >= 0, NULL);
	if (!cc) {
		return NULL;
	}
	Sdb *db = DB;
	r_strf_buffer (64);
	if (lastn >= 0) {
		char *revarg = r_strf ("cc.%s.revarg", cc);
		if (r_str_is_true (revarg)) {
			// check if revarg is set, this is used only for D
			R_LOG_INFO ("EXPERIMENTAL: Reversing argument position");
			n = lastn - n;
		}
	}
	char *query = r_strf ("cc.%s.arg%d", cc, n);
	const char *ret = sdb_const_get (db, query, 0);
	if (!ret) {
		query = r_strf ("cc.%s.argn", cc);
		ret = sdb_const_get (db, query, 0);
	}
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

R_API const char *r_anal_cc_self(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, NULL);
	r_strf_var (query, 64, "cc.%s.self", convention);
	const char *self = sdb_const_get (DB, query, 0);
	return self? r_str_constpool_get (&anal->constpool, self): NULL;
}

R_API void r_anal_cc_set_self(RAnal *anal, const char *convention, const char *self) {
	R_RETURN_IF_FAIL (anal && convention && self);
	if (!r_anal_cc_exist (anal, convention)) {
		return;
	}
	RStrBuf sb;
	sdb_set (DB, r_strbuf_initf (&sb, "cc.%s.self", convention), self, 0);
	r_strbuf_fini (&sb);
}

R_API const char *r_anal_cc_error(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, NULL);
	R_CRITICAL_ENTER (anal);
	r_strf_var (query, 64, "cc.%s.error", convention);
	const char *error = sdb_const_get (DB, query, 0);
	const char *res = error? r_str_constpool_get (&anal->constpool, error): NULL;
	R_CRITICAL_LEAVE (anal);
	return res;
}

R_API void r_anal_cc_set_error(RAnal *anal, const char *convention, const char *error) {
	R_RETURN_IF_FAIL (anal && convention && error);
	if (!r_anal_cc_exist (anal, convention)) {
		return;
	}
	RStrBuf sb;
	sdb_set (DB, r_strbuf_initf (&sb, "cc.%s.error", convention), error, 0);
	r_strbuf_fini (&sb);
}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int i = 0;
	R_RETURN_VAL_IF_FAIL (anal && DB && cc, 0);

	r_strf_var (lastarg, 64, "cc.%s.lastarg", cc);
	int count = sdb_num_get (DB, lastarg, 0);
	if (count > 0) {
		return count;
	}
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		r_strf_var (query, 64, "cc.%s.arg%d", cc, i);
		const char *res = sdb_const_get (DB, query, 0);
		if (!res) {
			break;
		}
	}
	if (i > 0) {
		sdb_num_set (DB, lastarg, i, 0);
	}
	return i;
}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, NULL);
	r_strf_var (query, 64, "cc.%s.ret", convention);
	return sdb_const_get (DB, query, 0);
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
