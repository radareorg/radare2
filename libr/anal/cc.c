/* radare - LGPL - Copyright 2011-2026 - pancake, Oddcoder */

#include <r_anal_priv.h>
#define DB anal->sdb_cc

#define R_ANAL_DYNCC_NAME_SIZE 32
#define R_ANAL_DYNCC_GROUP_SIZE 256
#define R_ANAL_DYNCC_REGSET_SIZE 256
#define R_ANAL_DYNCC_MAX_HOMES 8
#define R_ANAL_DYNCC_MAX_ROLES 16
#define R_ANAL_DYNCC_STACK_PREFIX '\1'
#define R_ANAL_DYNCC_REVSTACK_PREFIX '\2'

typedef struct r_anal_dyn_cc_slice_t {
	const char *p;
	ut16 len;
} RAnalDynCCSlice;

static bool dyncc_parse_int(const char **sp, int *out) {
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

static bool dyncc_parse_name(const char **sp, const char *end, RAnalDynCCSlice *out) {
	const char *s = *sp;
	const char *n = s;
	while (n < end && (isalnum ((ut8)*n) || *n == '_' || *n == '.' || *n == '-')) {
		n++;
	}
	size_t len = n - s;
	if (!len || len >= R_ANAL_DYNCC_NAME_SIZE) {
		return false;
	}
	out->p = s;
	out->len = (ut16)len;
	*sp = n;
	return true;
}

static const char *dyncc_range_startswith(const char *s, const char *end, const char *prefix) {
	size_t len = strlen (prefix);
	return end - s >= len && !strncmp (s, prefix, len)? s + len: NULL;
}

static bool cc_parse_stack_pop_range(const char *s, const char *end, int *out) {
	if (!s || s >= end) {
		return false;
	}
	if (dyncc_range_startswith (s, end, "caller") == end) {
		*out = 0;
		return true;
	}
	if (dyncc_range_startswith (s, end, "callee") == end) {
		*out = R_ANAL_CC_STACK_POP_UNKNOWN;
		return true;
	}
	const char *p = dyncc_range_startswith (s, end, "pop=");
	if (!p) {
		p = s;
	}
	if (!dyncc_parse_int (&p, out)) {
		return false;
	}
	return p == end;
}

static bool cc_parse_stack_pop(const char *s, int *out) {
	return s? cc_parse_stack_pop_range (s, s + strlen (s), out): false;
}

static bool dyncc_slice_eq(const RAnalDynCCSlice *slice, const char *s) {
	size_t len = strlen (s);
	return slice->len == len && !strncmp (slice->p, s, len);
}

static const char *dyncc_intern(RAnal *anal, const char *p, size_t len) {
	if (!p || !len) {
		return NULL;
	}
	char tmp[R_ANAL_DYNCC_GROUP_SIZE];
	char *heap = NULL;
	if (len < sizeof (tmp)) {
		memcpy (tmp, p, len);
		tmp[len] = 0;
		p = tmp;
	} else {
		heap = r_str_ndup (p, len);
		if (!heap) {
			return NULL;
		}
		p = heap;
	}
	const char *ret = r_str_constpool_get (&anal->constpool, p);
	free (heap);
	return ret;
}

typedef struct r_anal_dyn_cc_loc_t {
	RAnalDynCCSlice text;
	bool indexed;
	char prefix;
	int index;
} RAnalDynCCLoc;

typedef struct r_anal_dyn_cc_seq_t {
	RAnalDynCCLoc locs[R_ANAL_CC_MAXARG];
	int count;
} RAnalDynCCSeq;

typedef struct r_anal_dyn_cc_homes_t {
	RAnalDynCCLoc homes[R_ANAL_DYNCC_MAX_HOMES];
	int home_count;
} RAnalDynCCHomes;

typedef struct r_anal_dyn_cc_role_t {
	char tag;
	int arg;
	RAnalDynCCLoc loc;
} RAnalDynCCRole;

typedef struct r_anal_dyn_cc_t {
	RAnalDynCCHomes args[R_ANAL_CC_MAXARG];
	int arg_count;
	bool arg_tail;
	RAnalDynCCLoc arg_tail_loc;
	RAnalDynCCSlice arg_ref;
	RAnalDynCCHomes rets[R_ANAL_CC_MAXARG];
	int ret_count;
	RAnalDynCCSlice ret_ref;
	int stack_pop;
	RAnalDynCCSlice clobbers;
	RAnalDynCCSlice preserves;
	RAnalDynCCRole roles[R_ANAL_DYNCC_MAX_ROLES];
	int role_count;
} RAnalDynCC;

static bool dyncc_slice_empty(const RAnalDynCCSlice *slice) {
	return !slice || !slice->p || !slice->len;
}

static bool dyncc_set_slice(const char *s, const char *end, RAnalDynCCSlice *out, size_t maxlen) {
	size_t len = end - s;
	if (!len || len >= maxlen) {
		return false;
	}
	out->p = s;
	out->len = (ut16)len;
	return true;
}

static bool dyncc_parse_ref(const char *s, const char *end, RAnalDynCCSlice *out) {
	if (s >= end || *s++ != '&') {
		return false;
	}
	if (!dyncc_parse_name (&s, end, out)) {
		return false;
	}
	return s == end;
}

static bool dyncc_parse_ref_only(const char *s, const char *end, RAnalDynCCSlice *out) {
	return !memchr (s, ',', end - s) && !memchr (s, '\'', end - s)
		&& dyncc_parse_ref (s, end, out);
}

static bool dyncc_parse_loc(const char *s, const char *end, RAnalDynCCLoc *out) {
	if (!dyncc_set_slice (s, end, &out->text, R_ANAL_DYNCC_GROUP_SIZE)) {
		return false;
	}
	if (dyncc_slice_eq (&out->text, "_")) {
		return true;
	}
	if (dyncc_range_startswith (s, end, "stack")) {
		return false;
	}
	if (*s == '&') {
		return false;
	}
	if (!isalnum ((ut8)*s)) {
		return false;
	}
	while (s < end) {
		if (!isalnum ((ut8)*s) && *s != '_' && *s != '.') {
			return false;
		}
		s++;
	}
	return true;
}

static bool dyncc_set_indexed_seq(RAnalDynCCSeq *seq, char prefix, int base, int count, int delta) {
	if (count <= 0 || count > R_ANAL_CC_MAXARG || (delta < 0 && base < count - 1)) {
		return false;
	}
	int i;
	for (i = 0; i < count; i++) {
		seq->locs[i] = (RAnalDynCCLoc) {
			.indexed = true,
			.prefix = prefix,
			.index = base + (i * delta)
		};
	}
	seq->count = count;
	return true;
}

static int dyncc_parse_indexed_seq(RAnalDynCCSeq *seq, const char *s, const char *end, char prefix) {
	const char *p = s;
	int base = 0;
	if (!dyncc_parse_int (&p, &base)) {
		return 0;
	}
	int count = 1;
	int delta = 1;
	if (p < end) {
		if (*p != '+' && *p != '-') {
			return 0;
		}
		delta = *p++ == '-'? -1: 1;
		if (!dyncc_parse_int (&p, &count) || p != end) {
			return -1;
		}
	}
	return p == end && dyncc_set_indexed_seq (seq, prefix, base, count, delta)? 1: -1;
}

static bool dyncc_parse_loc_seq(const char *s, const char *end, RAnalDynCCSeq *seq) {
	if (s >= end) {
		return false;
	}
	if (*s == '^') {
		s++;
		const bool rev = s < end && *s == '-';
		if (rev) {
			s++;
		}
		if (s == end) {
			seq->locs[0] = (RAnalDynCCLoc) {
				.text = {
					.p = rev? "^-": "^",
					.len = rev? 2: 1
				}
			};
			seq->count = 1;
			return true;
		}
		const char prefix = rev? R_ANAL_DYNCC_REVSTACK_PREFIX: R_ANAL_DYNCC_STACK_PREFIX;
		return dyncc_parse_indexed_seq (seq, s, end, prefix) == 1;
	}
	const char *token = s;
	if (isalpha ((ut8)*s)) {
		const char prefix = *s++;
		int parsed = dyncc_parse_indexed_seq (seq, s, end, prefix);
		if (parsed > 0) {
			return true;
		}
		if (parsed < 0) {
			return false;
		}
	}
	if (!dyncc_parse_loc (token, end, &seq->locs[0])) {
		return false;
	}
	seq->count = 1;
	return true;
}

static bool dyncc_tail_loc(const RAnalDynCCLoc *loc) {
	return loc && !loc->indexed
		&& (dyncc_slice_eq (&loc->text, "^") || dyncc_slice_eq (&loc->text, "^-"));
}

static bool dyncc_parse_homes(const char *s, const char *end, RAnalDynCCHomes *homes, int *count) {
	RAnalDynCCSeq seqs[R_ANAL_DYNCC_MAX_HOMES] = {0};
	int home_count = 0;
	int loc_count = -1;
	while (s < end) {
		if (home_count >= R_ANAL_DYNCC_MAX_HOMES) {
			return false;
		}
		const char *next = memchr (s, '\'', end - s);
		if (!next) {
			next = end;
		}
		if (next == s || !dyncc_parse_loc_seq (s, next, &seqs[home_count])) {
			return false;
		}
		if (loc_count < 0) {
			loc_count = seqs[home_count].count;
		} else if (loc_count != seqs[home_count].count) {
			return false;
		}
		home_count++;
		s = next < end? next + 1: next;
	}
	if (home_count < 1 || loc_count < 1) {
		return false;
	}
	int i;
	for (i = 0; i < loc_count; i++) {
		int h;
		for (h = 0; h < home_count; h++) {
			homes[i].homes[h] = seqs[h].locs[i];
		}
		homes[i].home_count = home_count;
	}
	*count = loc_count;
	return true;
}

static bool dyncc_parse_homed_list(const char *s, const char *end, RAnalDynCC *d, bool args) {
	if (s == end) {
		return true;
	}
	RAnalDynCCSlice *ref = args? &d->arg_ref: &d->ret_ref;
	if (dyncc_parse_ref_only (s, end, ref)) {
		return true;
	}
	RAnalDynCCHomes *dst = args? d->args: d->rets;
	int *dst_count = args? &d->arg_count: &d->ret_count;
	while (s < end) {
		const char *next = memchr (s, ',', end - s);
		if (!next) {
			next = end;
		}
		if (next == s || (args && d->arg_tail)) {
			return false;
		}
		RAnalDynCCHomes homes[R_ANAL_CC_MAXARG] = {0};
		int count = 0;
		if (!dyncc_parse_homes (s, next, homes, &count)) {
			return false;
		}
		if (args && count == 1 && homes[0].home_count == 1 && dyncc_tail_loc (&homes[0].homes[0])) {
			if (next < end) {
				return false;
			}
			d->arg_tail = true;
			d->arg_tail_loc = homes[0].homes[0];
		} else {
			if (*dst_count > R_ANAL_CC_MAXARG - count) {
				return false;
			}
			int i;
			for (i = 0; i < count; i++) {
				if (!args && homes[i].home_count != 1) {
					return false;
				}
				dst[(*dst_count)++] = homes[i];
			}
		}
		s = next < end? next + 1: next;
	}
	return true;
}

static bool dyncc_role_tag(char tag) {
	switch (tag) {
	case 'T':
	case 'R':
	case 'V':
	case 'E':
	case 'X':
		return true;
	default:
		return islower ((ut8)tag) && tag != 'p';
	}
}

static int dyncc_find_role(const RAnalDynCC *d, char tag) {
	int i;
	for (i = 0; i < d->role_count; i++) {
		if (d->roles[i].tag == tag) {
			return i;
		}
	}
	return -1;
}

static bool dyncc_set_role(RAnalDynCC *d, char tag, const char *s, const char *end) {
	if (!dyncc_role_tag (tag) || s >= end) {
		return false;
	}
	int slot = dyncc_find_role (d, tag);
	if (slot < 0) {
		if (d->role_count >= R_ANAL_DYNCC_MAX_ROLES) {
			return false;
		}
		slot = d->role_count++;
	}
	RAnalDynCCRole *role = &d->roles[slot];
	memset (role, 0, sizeof (*role));
	role->tag = tag;
	role->arg = -1;
	const char *p = s;
	int arg = -1;
	if (dyncc_parse_int (&p, &arg) && p == end) {
		role->arg = arg;
		return true;
	}
	RAnalDynCCSeq seq = {0};
	if (!dyncc_parse_loc_seq (s, end, &seq) || seq.count != 1) {
		return false;
	}
	role->loc = seq.locs[0];
	return true;
}

static bool dyncc_parse_attrs(const char *s, const char *end, RAnalDynCC *d) {
	while (s < end) {
		if (*s++ != '!' || s >= end) {
			return false;
		}
		const char tag = *s++;
		const char *next = memchr (s, '!', end - s);
		if (!next) {
			next = end;
		}
		if (tag == 'p') {
			if (s == next) {
				return false;
			}
			if (next - s == 1 && *s == '?') {
				d->stack_pop = R_ANAL_CC_STACK_POP_UNKNOWN;
			} else {
				const char *p = s;
				int pop = 0;
				if (!dyncc_parse_int (&p, &pop) || p != next) {
					return false;
				}
				d->stack_pop = pop;
			}
		} else if (tag == 'C' || tag == 'P') {
			if (next - s < 2 || *s != '(' || next[-1] != ')') {
				return false;
			}
			if (!dyncc_set_slice (s, next, tag == 'C'? &d->clobbers: &d->preserves, R_ANAL_DYNCC_REGSET_SIZE)) {
				return false;
			}
		} else if (!dyncc_set_role (d, tag, s, next)) {
			return false;
		}
		s = next;
	}
	return true;
}

static bool dyncc_parse(const char *cc, RAnalDynCC *out) {
	if (!cc || !r_str_startswith (cc, "dyncc:")) {
		return false;
	}
	const char *args = cc + strlen ("dyncc:");
	const char *end = cc + strlen (cc);
	const char *rets = memchr (args, ':', end - args);
	if (!rets) {
		return false;
	}
	const char *attrs = memchr (rets + 1, '!', end - (rets + 1));
	const char *ret_end = attrs? attrs: end;
	RAnalDynCC d = {0};
	if (!dyncc_parse_homed_list (args, rets, &d, true)) {
		return false;
	}
	if (!dyncc_parse_homed_list (rets + 1, ret_end, &d, false)) {
		return false;
	}
	if (attrs && !dyncc_parse_attrs (attrs, end, &d)) {
		return false;
	}
	*out = d;
	return true;
}

static const char *dyncc_loc_name(RAnal *anal, const RAnalDynCCLoc *loc) {
	if (!loc) {
		return NULL;
	}
	if (loc->indexed) {
		if (loc->prefix == R_ANAL_DYNCC_REVSTACK_PREFIX) {
			r_strf_var (name, 64, "^-%d", loc->index);
			return r_str_constpool_get (&anal->constpool, name);
		}
		if (loc->prefix == R_ANAL_DYNCC_STACK_PREFIX) {
			r_strf_var (name, 64, "^%d", loc->index);
			return r_str_constpool_get (&anal->constpool, name);
		}
		r_strf_var (name, 64, "%c%d", loc->prefix, loc->index);
		return r_str_constpool_get (&anal->constpool, name);
	}
	const RAnalDynCCSlice *text = &loc->text;
	if (dyncc_slice_empty (text) || dyncc_slice_eq (text, "_")) {
		return NULL;
	}
	if (dyncc_slice_eq (text, "^")) {
		return r_str_constpool_get (&anal->constpool, "^");
	}
	if (dyncc_slice_eq (text, "^-")) {
		return r_str_constpool_get (&anal->constpool, "^-");
	}
	return dyncc_intern (anal, text->p, text->len);
}

static const char *dyncc_from_static_loc(RAnal *anal, const char *loc) {
	if (!loc) {
		return NULL;
	}
	if (!strcmp (loc, "stack")) {
		return r_str_constpool_get (&anal->constpool, "^");
	}
	if (!strcmp (loc, "stack_rev")) {
		return r_str_constpool_get (&anal->constpool, "^-");
	}
	const char *p = dyncc_range_startswith (loc, loc + strlen (loc), "stack_rev");
	if (p && isdigit ((ut8)*p)) {
		r_strf_var (name, 64, "^-%s", p);
		return r_str_constpool_get (&anal->constpool, name);
	}
	p = dyncc_range_startswith (loc, loc + strlen (loc), "stack");
	if (p && isdigit ((ut8)*p)) {
		r_strf_var (name, 64, "^%s", p);
		return r_str_constpool_get (&anal->constpool, name);
	}
	return loc;
}

static const char *dyncc_arg_home(RAnal *anal, const RAnalDynCC *d, int n, int home, int argc) {
	if (n < 0 || home < 0) {
		return NULL;
	}
	if (!dyncc_slice_empty (&d->arg_ref)) {
		const char *refcc = dyncc_intern (anal, d->arg_ref.p, d->arg_ref.len);
		return refcc? dyncc_from_static_loc (anal, r_anal_cc_argloc (anal, refcc, n, home, argc)): NULL;
	}
	if (n < d->arg_count) {
		const RAnalDynCCHomes *homes = &d->args[n];
		return home < homes->home_count? dyncc_loc_name (anal, &homes->homes[home]): NULL;
	}
	if (d->arg_tail && home == 0) {
		return dyncc_loc_name (anal, &d->arg_tail_loc);
	}
	return NULL;
}

static const RAnalDynCCRole *dyncc_role(const RAnalDynCC *d, char tag) {
	int slot = dyncc_role_tag (tag)? dyncc_find_role (d, tag): -1;
	return slot >= 0? &d->roles[slot]: NULL;
}

static const char *dyncc_role_loc(RAnal *anal, const RAnalDynCC *d, char tag) {
	const RAnalDynCCRole *role = dyncc_role (d, tag);
	if (!role) {
		return NULL;
	}
	return role->arg >= 0
		? dyncc_arg_home (anal, d, role->arg, 0, -1)
		: dyncc_loc_name (anal, &role->loc);
}

static const char *dyncc_ret(RAnal *anal, const RAnalDynCC *d, int n) {
	if (n < 0) {
		return NULL;
	}
	if (!dyncc_slice_empty (&d->ret_ref)) {
		const char *refcc = dyncc_intern (anal, d->ret_ref.p, d->ret_ref.len);
		return refcc? dyncc_from_static_loc (anal, r_anal_cc_ret (anal, refcc, n)): NULL;
	}
	return n < d->ret_count? dyncc_loc_name (anal, &d->rets[n].homes[0]): NULL;
}

static int dyncc_max_arg(RAnal *anal, const RAnalDynCC *d) {
	if (!dyncc_slice_empty (&d->arg_ref)) {
		const char *refcc = dyncc_intern (anal, d->arg_ref.p, d->arg_ref.len);
		return refcc? r_anal_cc_max_arg (anal, refcc): 0;
	}
	return d->arg_count;
}

static bool dyncc_ref_exists(RAnal *anal, const RAnalDynCCSlice *ref) {
	if (dyncc_slice_empty (ref)) {
		return true;
	}
	r_strf_var (refcc, R_ANAL_DYNCC_NAME_SIZE, "%.*s", (int)ref->len, ref->p);
	const char *x = sdb_const_get (DB, refcc, 0);
	return x && !strcmp (x, "cc");
}

static bool dyncc_refs_exist(RAnal *anal, const RAnalDynCC *d) {
	if (!dyncc_ref_exists (anal, &d->arg_ref) || !dyncc_ref_exists (anal, &d->ret_ref)) {
		return false;
	}
	int i;
	for (i = 0; i < d->role_count; i++) {
		if (d->roles[i].arg >= 0 && !dyncc_arg_home (anal, d, d->roles[i].arg, 0, -1)) {
			return false;
		}
	}
	return true;
}

R_API void r_anal_cc_del(RAnal *anal, const char *name) {
	R_RETURN_IF_FAIL (anal && name);
	RAnalDynCC d;
	if (dyncc_parse (name, &d)) {
		return;
	}
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
	RAnalDynCC d;
	if (dyncc_parse (ccname, &d)) {
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

R_API char *r_anal_cc_get(RAnal *anal, const char *name) {
	Sdb *db = anal->sdb_cc;
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);
	int i;
	RAnalDynCC d;
	if (dyncc_parse (name, &d)) {
		RStrBuf *sb = r_strbuf_new (NULL);
		const char *ret = dyncc_ret (anal, &d, 0);
		r_strbuf_append (sb, ret? ret: "void");
		for (i = 1; ; i++) {
			const char *rs = dyncc_ret (anal, &d, i);
			if (!rs) {
				break;
			}
			r_strbuf_appendf (sb, ":%s", rs);
		}
		const char *self = dyncc_role_loc (anal, &d, 'T');
		r_strbuf_appendf (sb, " %s%s%s (", r_str_get (self), self? ".": "", name);
		int max = dyncc_max_arg (anal, &d);
		bool is_first = true;
		for (i = 0; i < max; i++) {
			const char *arg = dyncc_arg_home (anal, &d, i, 0, -1);
			if (!arg) {
				continue;
			}
			r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", arg);
			is_first = false;
		}
		const char *argn = dyncc_arg_home (anal, &d, max, 0, -1);
		if (argn) {
			r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", argn);
		}
		r_strbuf_append (sb, ");");
		return r_strbuf_drain (sb);
	}
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
	if (!strcmp (cc, "dyncc")) {
		return true;
	}
	RAnalDynCC d;
	if (dyncc_parse (cc, &d)) {
		return dyncc_refs_exist (anal, &d);
	}
	const char *x = sdb_const_get (DB, cc, 0);
	return (x != NULL) && !strcmp (x, "cc");
}

R_API const char *r_anal_cc_argloc(RAnal *anal, const char *cc, int n, int home, int argc) {
	R_RETURN_VAL_IF_FAIL (anal && n >= 0 && home >= 0, NULL);
	if (!cc) {
		return NULL;
	}
	RAnalDynCC d;
	if (dyncc_parse (cc, &d)) {
		return dyncc_arg_home (anal, &d, n, home, argc);
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
	return ret? dyncc_from_static_loc (anal, ret): NULL;
}

R_API const char *r_anal_cc_roleloc(RAnal *anal, const char *convention, const char *role) {
	R_RETURN_VAL_IF_FAIL (anal && convention && role, NULL);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return role[0] && !role[1]? dyncc_role_loc (anal, &d, role[0]): NULL;
	}
	RStrBuf sb;
	const char *key = r_strbuf_initf (&sb, "cc.%s.%s", convention, role);
	const char *value = sdb_const_get (DB, key, 0);
	const char *res = value? r_str_constpool_get (&anal->constpool, value): NULL;
	r_strbuf_fini (&sb);
	return res;
}

static void cc_set_roleloc(RAnal *anal, const char *convention, const char *role, const char *loc) {
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return;
	}
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

R_API void r_anal_cc_set_error(RAnal *anal, const char *convention, const char *error) {
	R_RETURN_IF_FAIL (anal && convention && error);
	cc_set_roleloc (anal, convention, "error", error);
}

R_API int r_anal_cc_max_arg(RAnal *anal, const char *cc) {
	int i = 0;
	R_RETURN_VAL_IF_FAIL (anal && DB && cc, 0);

	RAnalDynCC d;
	if (dyncc_parse (cc, &d)) {
		return dyncc_max_arg (anal, &d);
	}

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
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return dyncc_ret (anal, &d, n);
	}
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
	if (n == 0) {
		return sdb_const_get (DB, r_strf ("cc.%s.ret", convention), 0);
	}
	return NULL;
}

R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, 0);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return d.stack_pop;
	}
	r_strf_var (query, 64, "cc.%s.pop", convention);
	const char *pop = sdb_const_get (DB, query, 0);
	int ret = 0;
	return cc_parse_stack_pop (pop, &ret)? ret: 0;
}

static const char *cc_regset(RAnal *anal, const char *convention, const char *field) {
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		const RAnalDynCCSlice *slice = !strcmp (field, "clobber")? &d.clobbers: &d.preserves;
		return dyncc_intern (anal, slice->p, slice->len);
	}
	r_strf_var (query, 64, "cc.%s.%s", convention, field);
	const char *ret = sdb_const_get (DB, query, 0);
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

typedef struct r_anal_cc_piece_t {
	const char *loc;
} RAnalCCPiece;
R_VEC_TYPE (RVecAnalCCPiece, RAnalCCPiece);

static bool r_anal_cc_regset_contains(const char *regset, const char *reg);

static bool cc_piece_push(RAnal *anal, RVecAnalCCPiece *pieces, const char *loc, size_t loc_len) {
	if (!loc_len) {
		return false;
	}
	const char *name = dyncc_intern (anal, loc, loc_len);
	if (!name) {
		return false;
	}
	RAnalCCPiece piece = {
		.loc = name
	};
	RVecAnalCCPiece_push_back (pieces, &piece);
	return true;
}

static bool cc_piece_parse(RAnal *anal, RVecAnalCCPiece *pieces, const char *s, const char *end) {
	while (s < end && isspace ((ut8)*s)) {
		s++;
	}
	while (end > s && isspace ((ut8)end[-1])) {
		end--;
	}
	if (s >= end) {
		return false;
	}
	if (isdigit ((ut8)*s)) {
		const char *p = s;
		int n = 0;
		if (dyncc_parse_int (&p, &n) && p < end && *p == ':') {
			s = p + 1;
		}
	}
	const char *dot = end;
	while (dot > s && isdigit ((ut8)dot[-1])) {
		dot--;
	}
	if (dot > s && dot[-1] == '.') {
		const char *p = dot;
		int n = 0;
		if (dyncc_parse_int (&p, &n) && p == end) {
			end = dot - 1;
		}
	}
	return cc_piece_push (anal, pieces, s, end - s);
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

static bool r_anal_cc_location_pieces(RAnal *anal, const char *loc, RVecAnalCCPiece *pieces) {
	R_RETURN_VAL_IF_FAIL (anal && loc && pieces, false);
	RVecAnalCCPiece_clear (pieces);
	size_t len = strlen (loc);
	if (len < 2 || loc[0] != '{' || loc[len - 1] != '}') {
		return cc_piece_push (anal, pieces, loc, len);
	}
	const char *s = loc + 1;
	const char *end = loc + len - 1;
	while (s < end) {
		const char *next = cc_group_next (s, end);
		if (!cc_piece_parse (anal, pieces, s, next)) {
			RVecAnalCCPiece_clear (pieces);
			return false;
		}
		s = next + (next < end);
	}
	return RVecAnalCCPiece_length (pieces) > 0;
}

R_IPI bool r_anal_cc_location_uses(RAnal *anal, const char *loc, const char *reg) {
	R_RETURN_VAL_IF_FAIL (anal && loc && reg, false);
	if (*loc && *loc != '{') {
		return !strcmp (loc, reg);
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	bool ret = false;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece;
		R_VEC_FOREACH (&pieces, piece) {
			if (!strcmp (piece->loc, reg)) {
				ret = true;
				break;
			}
		}
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

R_IPI const char *r_anal_cc_location_first(RAnal *anal, const char *loc) {
	R_RETURN_VAL_IF_FAIL (anal && loc, NULL);
	if (*loc && *loc != '{') {
		return loc;
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	const char *ret = NULL;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece = RVecAnalCCPiece_at (&pieces, 0);
		ret = piece? piece->loc: NULL;
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all) {
	R_RETURN_VAL_IF_FAIL (anal && loc, false);
	if (R_STR_ISEMPTY (regset)) {
		return false;
	}
	if (*loc && *loc != '{') {
		return r_anal_cc_regset_contains (regset, loc);
	}
	RVecAnalCCPiece pieces;
	RVecAnalCCPiece_init (&pieces);
	bool ret = all;
	if (r_anal_cc_location_pieces (anal, loc, &pieces)) {
		RAnalCCPiece *piece;
		R_VEC_FOREACH (&pieces, piece) {
			bool contains = r_anal_cc_regset_contains (regset, piece->loc);
			if (contains != all) {
				ret = contains;
				break;
			}
		}
	} else {
		ret = false;
	}
	RVecAnalCCPiece_fini (&pieces);
	return ret;
}

static bool r_anal_cc_regset_contains(const char *regset, const char *reg) {
	R_RETURN_VAL_IF_FAIL (regset && reg, false);
	const char *s = regset;
	if (*s == '(') {
		s++;
	}
	while (*s) {
		while (*s == ',' || isspace ((ut8)*s)) {
			s++;
		}
		const char *e = s;
		while (*e && *e != ',' && *e != ')') {
			e++;
		}
		const char *t = e;
		while (t > s && isspace ((ut8)t[-1])) {
			t--;
		}
		if (t > s && strlen (reg) == (size_t)(t - s) && !strncmp (s, reg, t - s)) {
			return true;
		}
		if (*e == ')') {
			break;
		}
		s = e;
	}
	return false;
}

R_API bool r_anal_cc_argclob(RAnal *anal, const char *caller_cc, int n, const char *callee_cc) {
	R_RETURN_VAL_IF_FAIL (anal && caller_cc && n >= 0, false);
	const char *loc = r_anal_cc_argloc (anal, caller_cc, n, 0, 0);
	if (!loc) {
		return false;
	}
	const char *clobbers = callee_cc? cc_regset (anal, callee_cc, "clobber"): NULL;
	const char *preserves = callee_cc? cc_regset (anal, callee_cc, "preserve"): NULL;
	if (R_STR_ISNOTEMPTY (clobbers)) {
		return r_anal_cc_location_in_regset (anal, loc, clobbers, false)
			&& !r_anal_cc_location_in_regset (anal, loc, preserves, true);
	}
	return R_STR_ISEMPTY (preserves) || !r_anal_cc_location_in_regset (anal, loc, preserves, true);
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
