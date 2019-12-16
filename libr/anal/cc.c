/* radare - LGPL - Copyright 2011-2019 - pancake, Oddcoder */

/* Universal calling convention implementation based on sdb */

#include <r_anal.h>
#define DB anal->sdb_cc

R_API void r_anal_cc_del(RAnal *anal, const char *name) {
	int i;
	sdb_unset (DB, sdb_fmt ("%s", name), 0);
	sdb_unset (DB, sdb_fmt ("cc.%s.ret", name), 0);
	sdb_unset (DB, sdb_fmt ("cc.%s.argn", name), 0);
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		sdb_unset (DB, sdb_fmt ("cc.%s.arg%d", name, i), 0);
	}
}

R_API void r_anal_cc_set(RAnal *anal, const char *expr) {
	char *e = strdup (expr);
	char *p = strchr (e, '(');
	if (p) {
		*p++ = 0;
	}
	char *args = strdup (p);
	char *end = strchr (args, ')');
	if (end) {
		*end++ = 0;
		RList *retName = r_str_split_list (e, " ", 0);
		RList *ccArgs = r_str_split_list (args, ",", 0);
		if (r_list_length (retName) == 2) {
			const char *ret = r_list_get_n (retName, 0);
			const char *name = r_list_get_n (retName, 1);
			sdb_set (DB, name, "cc", 0);
			sdb_set (DB, sdb_fmt ("cc.%s.ret", name), ret, 0);
			RListIter *iter;
			const char *arg;
			int n = 0;
			r_list_foreach (ccArgs, iter, arg) {
				if (!strcmp (arg, "stack")) {
					sdb_set (DB, sdb_fmt ("cc.%s.argn", name), arg, 0);
				} else {
					sdb_set (DB, sdb_fmt ("cc.%s.arg%d", name, n), arg, 0);
					n++;
				}
			}
		}
		r_list_free (retName);
		r_list_free (ccArgs);
	}
	free (e);
	free (args);
}

R_API char *r_anal_cc_get(RAnal *anal, const char *name) {
	int i;
	// get cc by name and print the expr
	if (r_str_cmp (sdb_const_get (DB, name, 0), "cc", -1)) {
		eprintf ("This is not a valid calling convention name\n");
		return NULL;
	}
	const char *ret = sdb_const_get (DB, sdb_fmt ("cc.%s.ret", name), 0);
	if (!ret) {
		eprintf ("Cannot find return key\n");
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new (NULL);
	r_strbuf_appendf (sb, "%s %s (", ret, name);
	bool isFirst = true;
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		const char *k = sdb_fmt ("cc.%s.arg%d", name, i);
		const char *arg = sdb_const_get (DB, k, 0);
		if (!arg) {
			break;
		}
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", arg);
		isFirst = false;
	}
	const char *argn = sdb_const_get (DB, sdb_fmt ("cc.%s.argn", name), 0);
	if (argn) {
		r_strbuf_appendf (sb, "%s%s", isFirst? "": ", ", argn);
	}
	r_strbuf_appendf (sb, ");");
	return r_strbuf_drain (sb);
}


R_API bool r_anal_cc_exist (RAnal *anal, const char *convention) {
	r_return_val_if_fail (anal && convention, false);
	const char *x = sdb_const_get (DB, convention, 0);
	return x && *x && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_arg(RAnal *anal, const char *convention, int n) {
	r_return_val_if_fail (anal && convention, NULL);
	if (n < 0) {
		return NULL;
	}
	const char *query = sdb_fmt ("cc.%s.arg%d", convention, n);
	const char *ret = sdb_const_get (DB, query, 0);
	if (!ret) {
		query = sdb_fmt ("cc.%s.argn", convention);
		ret = sdb_const_get (DB, query, 0);
	}
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int i = 0;
	r_return_val_if_fail (anal && DB && cc, 0);
	static void *oldDB = NULL;
	static char *oldCC = NULL;
	static int oldArg = 0;
	if (oldDB == DB && !strcmp (cc, oldCC)) {
		return oldArg;
	}
	oldDB = DB;
	free (oldCC);
	oldCC = strdup (cc);
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		const char *query = sdb_fmt ("cc.%s.arg%d", cc, i);
		const char *res = sdb_const_get (DB, query, 0);
		if (!res) {
			break;
		}
	}
	oldArg = i;
	return i;
}

R_API const char *r_anal_cc_ret(RAnal *anal, const char *convention) {
	r_return_val_if_fail (anal && convention, NULL);
	char *query = sdb_fmt ("cc.%s.ret", convention);
	return sdb_const_get (DB, query, 0);
}

R_API const char *r_anal_cc_default(RAnal *anal) {
	r_return_val_if_fail (anal, NULL);
	return sdb_const_get (DB, "default.cc", 0);
}

R_API const char *r_anal_cc_func(RAnal *anal, const char *func_name) {
	r_return_val_if_fail (anal && func_name, NULL);
	const char *query = sdb_fmt ("func.%s.cc", func_name);
	const char *cc = sdb_const_get (anal->sdb_types, query, 0);
	return cc ? cc : r_anal_cc_default (anal);
}
