/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: table of functions whose call sites state an object size */

#include "tp.h"

#define TP_SIZEFN_BUILTINS "memset/0/2,bzero/0/1,memcpy/0/2,memcpy/1/2,memmove/0/2,memmove/1/2," \
	"malloc/r/0,calloc/r/1*0,realloc/r0/1,_Znwm/r/0,_Znam/r/0,_Znwj/r/0,_Znaj/r/0"

// one function may constrain several pointer operands (memcpy dst and src), so entries key on name + ptr_arg
static void tp_sizefn_set(RVecTPSizeFn *v, const char *name, int ptr_arg, int alias_arg, int size_arg, int mul_arg) {
	TPSizeFn *f;
	R_VEC_FOREACH (v, f) {
		if (f->ptr_arg == ptr_arg && !strcmp (f->name, name)) {
			f->alias_arg = alias_arg;
			f->size_arg = size_arg;
			f->mul_arg = mul_arg;
			return;
		}
	}
	f = RVecTPSizeFn_emplace_back (v);
	if (f) {
		f->name = strdup (name);
		f->ptr_arg = ptr_arg;
		f->alias_arg = alias_arg;
		f->size_arg = size_arg;
		f->mul_arg = mul_arg;
	}
}

static void tp_sizefn_remove(RVecTPSizeFn *v, const char *name) {
	size_t i = RVecTPSizeFn_length (v);
	while (i > 0) {
		i--;
		if (!strcmp (RVecTPSizeFn_at (v, i)->name, name)) {
			RVecTPSizeFn_remove (v, i);
		}
	}
}

static bool tp_sizefn_num(const char *s, int *out) {
	if (!isdigit ((ut8)*s)) {
		return false;
	}
	char *end = NULL;
	const long v = strtol (s, &end, 10);
	if (!end || *end || v < 0 || v > 15) {
		return false;
	}
	*out = (int)v;
	return true;
}

// name/ptrarg/sizearg[*mularg], ptrarg r for an allocator return or rN for one aliasing arg N; shadow mode drops what a valid entry replaces
static void tp_sizefns_parse(RVecTPSizeFn *v, const char *list, bool shadow) {
	char *s = strdup (list);
	RList *entries = r_str_split_list (s, ",", 0);
	RListIter *it;
	char *tok;
	r_list_foreach (entries, it, tok) {
		r_str_trim (tok);
		if (R_STR_ISEMPTY (tok)) {
			continue;
		}
		char *p1 = strchr (tok, '/');
		if (!p1 || tok == p1) {
			if (!shadow) {
				R_LOG_WARN ("Ignoring invalid types.sizefns entry for '%s'", tok);
			}
			continue;
		}
		*p1++ = 0;
		if (!strcmp (p1, "-")) {
			tp_sizefn_remove (v, tok);
			continue;
		}
		char *p2 = strchr (p1, '/');
		if (p2) {
			*p2++ = 0;
		}
		int ptr_arg = -1, alias_arg = -1, size_arg = 0, mul_arg = -1;
		char *mul = p2? strchr (p2, '*'): NULL;
		if (mul) {
			*mul++ = 0;
		}
		const bool is_ret = *p1 == 'r' && (!p1[1] || tp_sizefn_num (p1 + 1, &alias_arg));
		if (!p2 || (!is_ret && !tp_sizefn_num (p1, &ptr_arg)) || !tp_sizefn_num (p2, &size_arg)
				|| (mul && !tp_sizefn_num (mul, &mul_arg))) {
			if (!shadow) {
				R_LOG_WARN ("Ignoring invalid types.sizefns entry for '%s'", tok);
			}
			continue; // a rejected entry must not shadow the builtin it names
		}
		if (shadow) {
			tp_sizefn_remove (v, tok);
		} else {
			tp_sizefn_set (v, tok, ptr_arg, alias_arg, size_arg, mul_arg);
		}
	}
	r_list_free (entries);
	free (s);
}

void tp_sizefns_init(RVecTPSizeFn *v, const char *extra) {
	tp_sizefns_parse (v, TP_SIZEFN_BUILTINS, false);
	if (R_STR_ISNOTEMPTY (extra)) {
		// a user entry replaces the builtins for that function, so overriding one kind cannot leave the other live
		tp_sizefns_parse (v, extra, true);
		tp_sizefns_parse (v, extra, false);
	}
}

bool tp_sizefn_name_match(const TPSizeFn *f, const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const char *dot = r_str_rchr (name, NULL, '.');
	const char *base = dot? dot + 1: name;
	if (!strcmp (f->name, base) || !strcmp (f->name, name)) {
		return true;
	}
	// darwin-style leading underscore
	return *base == '_' && !strcmp (f->name, base + 1);
}

static const TPSizeFn *tp_sizefn_for_arg(const RVecTPSizeFn *v, const char *name, int arg_num) {
	const TPSizeFn *f;
	R_VEC_FOREACH (v, f) {
		if (f->ptr_arg == arg_num && tp_sizefn_name_match (f, name)) {
			return f;
		}
	}
	return NULL;
}

bool tp_sizefns_have_rets(const RVecTPSizeFn *v) {
	const TPSizeFn *f;
	R_VEC_FOREACH (v, f) {
		if (f->ptr_arg < 0) {
			return true;
		}
	}
	return false;
}

#define TP_SIZEFN_MAXSZ 0x100000 // sizes past 1 MiB are dynamic or stale register values

// pointer and computed size operands of a size-fn call, false when unresolvable or zero
bool tp_sizefn_read(TPState *tps, const char *cc, const TPSizeFn *sf, int argc, ut64 *pv, ut64 *n) {
	*pv = 0;
	if ((sf->ptr_arg >= 0 && !tp_argloc_val (tps, cc, sf->ptr_arg, argc, pv))
			|| !tp_argloc_val (tps, cc, sf->size_arg, argc, n)) {
		return false;
	}
	if (sf->mul_arg >= 0) {
		ut64 m = 0;
		if (!tp_argloc_val (tps, cc, sf->mul_arg, argc, &m) || !m || *n > UT64_MAX / m) {
			return false;
		}
		*n *= m;
	}
	return *n > 0;
}

// exact stack-object size stated for this argument by a size-fn entry, 0 when absent
ut64 tp_sizefn_arg_stacksize(TPState *tps, const char *cc, const char *fcn_name, int arg_num, int argc, ut64 *pv_out) {
	const TPSizeFn *sf = tp_sizefn_for_arg (&tps->sizefns, fcn_name, arg_num);
	ut64 pv = 0, n = 0;
	if (!sf || !tp_sizefn_read (tps, cc, sf, argc, &pv, &n) || n >= TP_SIZEFN_MAXSZ) {
		return 0;
	}
	// only a pointer into the emulated stack maps back to a stack variable
	if (pv < tps->stack_base || pv >= tps->stack_base + tps->stack_size) {
		return 0;
	}
	*pv_out = pv;
	return n;
}
