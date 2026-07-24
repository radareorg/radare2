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

R_IPI const char *r_anal_cc_rolelabel(char tag, char label[2], int *slot) {
	if (!dyncc_role_tag (tag)) {
		return NULL;
	}
	const char *roles = "TRVEX";
	const char *role = strchr (roles, tag);
	*slot = role? 26 + (int)(role - roles): tag - 'a';
	const char *tags = "dtcgi";
	const char *p = strchr (tags, tag);
	if (p) {
		const char *names[] = { "descriptor", "thread", "code", "global", "ic" };
		return names[p - tags];
	}
	label[0] = tag;
	label[1] = 0;
	return label;
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
	const char *x = sdb_const_getf (DB, NULL, "%.*s", (int)ref->len, ref->p);
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
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.pop", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.clobber", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.preserve", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.revarg", name), 0);
	sdb_unset (DB, r_strbuf_setf (&sb, "cc.%s.shadow", name), 0);
	r_strbuf_fini (&sb);
}

R_API bool r_anal_cc_set(RAnal *anal, const char *expr) {
	R_RETURN_VAL_IF_FAIL (anal && expr, false);
	bool ret = false;
	char *args = NULL;
	char *e = strdup (expr);
	char *p = strchr (e, '(');
	if (!p) {
		goto beach;
	}
	*p++ = 0;
	args = strdup (p);
	char *end = strchr (args, ')');
	if (!end) {
		goto beach;
	}
	*end = 0;
	r_str_trim (e);
	char *ccname = strchr (e, ' ');
	if (ccname) {
		*ccname++ = 0;
		r_str_trim (ccname);
	} else {
		goto beach;
	}
	RAnalDynCC d;
	if (dyncc_parse (ccname, &d)) {
		goto beach;
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
			sdb_setf (DB, ret, 0, "cc.%s.ret%d", ccname, n);
			n++;
		}
			sdb_num_setf (DB, n, 0, "cc.%s.retn", ccname);
		r_list_free (ccRets);
	} else {
		sdb_setf (DB, e, 0, "cc.%s.ret0", ccname);
		sdb_unset (DB, r_strf ("cc.%s.retn", ccname), 0);
	}

	RList *ccArgs = r_str_split_list (args, ",", 0);
	RListIter *iter;
	const char *arg;
	int n = 0;
	r_list_foreach (ccArgs, iter, arg) {
		if (!strcmp (arg, "stack")) {
			sdb_setf (DB, arg, 0, "cc.%s.argn", ccname);
		} else {
			sdb_setf (DB, arg, 0, "cc.%s.arg%d", ccname, n);
			n++;
		}
	}
	r_list_free (ccArgs);
	ret = true;
beach:
	free (e);
	free (args);
	return ret;
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

typedef struct r_anal_cc_sig_t {
	RAnal *anal;
	Sdb *db;
	const char *name;
	const RAnalDynCC *dyncc;
} RAnalCCSig;

static const char *cc_sig_ret(const RAnalCCSig *sig, int n) {
	if (sig->dyncc) {
		return dyncc_ret (sig->anal, sig->dyncc, n);
	}
	return r_anal_cc_ret (sig->anal, sig->name, n);
}

static char *cc_sig_tostring(const RAnalCCSig *sig) {
	RStrBuf *sb = r_strbuf_new (NULL);
	bool is_dyn = sig->dyncc;
	const char *ret = cc_sig_ret (sig, 0);
	r_strbuf_append (sb, ret? ret: "void");
	int i;
	for (i = 1; ; i++) {
		const char *rs = cc_sig_ret (sig, i);
		if (!rs) {
			break;
		}
		r_strbuf_appendf (sb, ":%s", rs);
	}
	const char *self = is_dyn
		? dyncc_role_loc (sig->anal, sig->dyncc, 'T')
		: r_anal_cc_roleloc (sig->anal, sig->name, "self");
	r_strbuf_appendf (sb, " %s%s%s (", r_str_get (self), self? ".": "", sig->name);
	const int max = is_dyn? dyncc_max_arg (sig->anal, sig->dyncc): R_ANAL_CC_MAXARG;
	bool is_first = true;
	for (i = 0; i < max; i++) {
		const char *arg;
		if (is_dyn) {
			arg = dyncc_arg_home (sig->anal, sig->dyncc, i, 0, -1);
		} else {
			arg = sdb_const_getf (sig->db, NULL, "cc.%s.arg%d", sig->name, i);
		}
		if (!arg) {
			if (!is_dyn) {
				break;
			}
			continue;
		}
		r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", arg);
		is_first = false;
	}
	const char *argn;
	if (is_dyn) {
		argn = dyncc_arg_home (sig->anal, sig->dyncc, max, 0, -1);
	} else {
		argn = sdb_const_getf (sig->db, NULL, "cc.%s.argn", sig->name);
	}
	if (argn) {
		r_strbuf_appendf (sb, "%s%s", is_first? "": ", ", argn);
	}
	r_strbuf_append (sb, ")");
	if (!is_dyn) {
		const char *error = r_anal_cc_roleloc (sig->anal, sig->name, "error");
		if (error) {
			r_strbuf_appendf (sb, " %s", error);
		}
	}
	r_strbuf_append (sb, ";");
	if (!is_dyn) {
		if (!r_str_is_true (sdb_const_getf (sig->db, NULL, "cc.%s.revarg", sig->name))) {
			return r_strbuf_drain (sb);
		}
		r_strbuf_append (sb, " // revarg");
	}
	return r_strbuf_drain (sb);
}

R_API char *r_anal_cc_get(RAnal *anal, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && name, NULL);
	Sdb *db = anal->sdb_cc;
	RAnalDynCC d;
	if (dyncc_parse (name, &d)) {
		RAnalCCSig sig = { anal, db, name, &d };
		return cc_sig_tostring (&sig);
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
	RAnalCCSig sig = { anal, db, name, NULL };
	return cc_sig_tostring (&sig);
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
	if (argc > 0) {
		if (r_str_is_true (sdb_const_getf (db, NULL, "cc.%s.revarg", cc))) {
			if (n >= argc) {
				return NULL;
			}
			n = argc - n - 1;
		}
	}
	const char *ret = sdb_const_getf (db, NULL, "cc.%s.arg%d", cc, n);
	if (!ret) {
		ret = sdb_const_getf (db, NULL, "cc.%s.argn", cc);
	}
	return ret? dyncc_from_static_loc (anal, ret): NULL;
}

// caller-reserved home space below the stack args (win64 shadow area)
R_IPI int r_anal_cc_shadow(RAnal *anal, const char *convention) {
	const char *s = sdb_const_getf (DB, NULL, "cc.%s.shadow", convention);
	return s? atoi (s): 0;
}

// bytes the call pushes before the stack args: one word unless the arch keeps the return address in a register
R_IPI int r_anal_cc_raslot(RAnal *anal, int word) {
	const bool ra_reg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_LR)
		|| r_reg_alias_getname (anal->reg, R_REG_ALIAS_RA);
	return ra_reg? 0: word;
}

// stack slot width: pointer-sized, refined by the first register argloc's width (thumb still passes 4-byte slots)
R_IPI int r_anal_cc_wordsize(RAnal *anal, const char *cc) {
	const int bits = anal->config->bits;
	int word = bits <= 16? 2: bits > 32? 8: 4;
	int i;
	for (i = 0; i < R_ANAL_CC_MAXARG; i++) {
		const char *place = r_anal_cc_argloc (anal, cc, i, 0, -1);
		if (R_STR_ISEMPTY (place) || *place == '^') {
			continue;
		}
		RRegItem *ri = r_reg_get (anal->reg, r_anal_cc_location_first (anal, place), -1);
		if (ri) {
			if (ri->size >= 32) {
				word = ri->size / 8;
			}
			r_unref (ri);
		}
		break;
	}
	return R_MIN (word, 8);
}

// where argument argno lives: a register, or a stack slot off bytes above SP
// incall shifts stack slots past the return address pushed by the call; argc is required for reverse-stack ccs
R_API bool r_anal_cc_argslot(RAnal *anal, const char *convention, int argno, int argc, bool incall, RAnalCCArgSlot *out) {
	R_RETURN_VAL_IF_FAIL (anal && out && argno >= 0, false);
	*out = (RAnalCCArgSlot){ 0 };
	const char *place = r_anal_cc_argloc (anal, convention, argno, 0, argc);
	if (R_STR_ISEMPTY (place)) {
		return false;
	}
	if (*place != '^') {
		out->reg = r_anal_cc_location_first (anal, place);
		return out->reg != NULL;
	}
	const int word = r_anal_cc_wordsize (anal, convention);
	const bool rev = place[1] == '-';
	const char *digits = rev? place + 2: place + 1;
	st64 off;
	if (isdigit ((ut8)*digits)) {
		off = (st64)atoi (digits) * word; // explicit call-frame slot index (doc/dyncc.md)
	} else if (rev) {
		if (argc < 0) {
			return false; // reverse layouts need the arg count
		}
		// only stack-located args occupy slots; the last one pushed sits at SP
		int after = 0, i;
		for (i = argno + 1; i < argc; i++) {
			const char *p = r_anal_cc_argloc (anal, convention, i, 0, argc);
			if (p && *p == '^') {
				after++;
			}
		}
		off = ((st64)after * word) + r_anal_cc_shadow (anal, convention);
	} else {
		// the tail starts past explicit ^N homes (mips o32 secondary homes) and earlier tail args
		int slots = 0, ntail = 0, i;
		for (i = 0; i < argno; i++) {
			int home;
			for (home = 0; ; home++) {
				const char *p = r_anal_cc_argloc (anal, convention, i, home, argc);
				if (!p) {
					break;
				}
				if (*p != '^') {
					continue;
				}
				const char *d = p[1] == '-'? p + 2: p + 1;
				if (isdigit ((ut8)*d)) {
					slots = R_MAX (slots, atoi (d) + 1);
				} else if (home == 0) {
					ntail++;
				}
			}
		}
		off = (((st64)slots + ntail) * word) + r_anal_cc_shadow (anal, convention);
	}
	if (incall) {
		off += r_anal_cc_raslot (anal, word);
	}
	out->off = off;
	out->size = word;
	return true;
}

// concrete value of argument argno read from the given reg arena and, for stack slots, through anal->iob
R_API bool r_anal_cc_argval(RAnal *anal, RReg *reg, const char *convention, int argno, int argc, bool incall, ut64 *out) {
	R_RETURN_VAL_IF_FAIL (anal && reg && out, false);
	RAnalCCArgSlot slot;
	if (!r_anal_cc_argslot (anal, convention, argno, argc, incall, &slot)) {
		return false;
	}
	if (slot.reg) {
		*out = r_reg_getv (reg, slot.reg);
		return true;
	}
	if (!anal->iob.read_at) {
		return false;
	}
	ut8 buf[8] = { 0 };
	const int sz = R_MIN (slot.size, 8);
	const ut64 addr = r_reg_getv (reg, "SP") + slot.off;
	if (!anal->iob.read_at (anal->iob.io, addr, buf, sz)) {
		return false;
	}
	*out = r_read_ble (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config), sz * 8);
	return true;
}

R_API const char *r_anal_cc_roleloc(RAnal *anal, const char *convention, const char *role) {
	R_RETURN_VAL_IF_FAIL (anal && convention && role, NULL);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return role[0] && !role[1]? dyncc_role_loc (anal, &d, role[0]): NULL;
	}
	const char *value = sdb_const_getf (DB, 0, "cc.%s.%s", convention, role);
	const char *res = value? r_str_constpool_get (&anal->constpool, value): NULL;
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
		const char *res = sdb_const_getf (DB, NULL, "cc.%s.arg%d", cc, i);
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
	if (n > 0) {
		int retn = sdb_num_getf (DB, NULL, "cc.%s.retn", convention);
		if (n >= retn) {
			return NULL;
		}
	}
	const char *ret = sdb_const_getf (DB, NULL, "cc.%s.ret%d", convention, n);
	if (ret) {
		return ret;
	}
	if (n == 0) {
		return sdb_const_getf (DB, NULL, "cc.%s.ret", convention);
	}
	return NULL;
}

R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention) {
	R_RETURN_VAL_IF_FAIL (anal && convention, 0);
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		return d.stack_pop;
	}
	const char *pop = sdb_const_getf (DB, NULL, "cc.%s.pop", convention);
	int ret = 0;
	return cc_parse_stack_pop (pop, &ret)? ret: 0;
}

static const char *cc_regset(RAnal *anal, const char *convention, const char *field) {
	RAnalDynCC d;
	if (dyncc_parse (convention, &d)) {
		const RAnalDynCCSlice *slice = !strcmp (field, "clobber")? &d.clobbers: &d.preserves;
		return dyncc_intern (anal, slice->p, slice->len);
	}
	const char *ret = sdb_const_getf (DB, NULL, "cc.%s.%s", convention, field);
	return ret? r_str_constpool_get (&anal->constpool, ret): NULL;
}

static bool r_anal_cc_regset_contains(const char *regset, const char *reg);
static const char *cc_group_next(const char *s, const char *end);

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
		if (dyncc_parse_int (&p, &n) && p < e && *p == ':') {
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
		if (dyncc_parse_int (&p, &n) && p == e) {
			e = dot - 1;
		}
	}
	*sp = next + (next < end);
	return dyncc_intern (anal, s, e - s);
}

static const char *cc_group_next(const char *s, const char *end) {
	const char *p = s;
	for (; p < end; p++) {
		if (*p == ',') {
			return p;
		}
		if (*p == ':') {
			if (r_str_trim_head_digits (s) != p) {
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

R_IPI bool r_anal_cc_location_uses(RAnal *anal, const char *loc, const char *reg) {
	R_RETURN_VAL_IF_FAIL (anal && loc && reg, false);
	if (*loc && *loc != '{') {
		return !strcmp (loc, reg);
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

R_API const char *r_anal_cc_location_first(RAnal *anal, const char *loc) {
	R_RETURN_VAL_IF_FAIL (anal && loc, NULL);
	if (*loc && *loc != '{') {
		return loc;
	}
	const char *s, *end;
	return cc_location_range (loc, &s, &end) && s < end? cc_location_next (anal, &s, end): NULL;
}

R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all) {
	R_RETURN_VAL_IF_FAIL (anal && loc, false);
	if (R_STR_ISEMPTY (regset)) {
		return false;
	}
	if (*loc && *loc != '{') {
		return r_anal_cc_regset_contains (regset, loc);
	}
	const char *s, *end;
	if (!cc_location_range (loc, &s, &end) || s >= end) {
		return false;
	}
	while (s < end) {
		const char *name = cc_location_next (anal, &s, end);
		if (!name) {
			return false;
		}
		bool contains = r_anal_cc_regset_contains (regset, name);
		if (contains != all) {
			return contains;
		}
	}
	return all;
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

R_API bool r_anal_cc_isclobber(RAnal *anal, const char *cc, const char *reg) {
	R_RETURN_VAL_IF_FAIL (anal && cc && reg, false);
	const char *clobbers = cc_regset (anal, cc, "clobber");
	if (R_STR_ISEMPTY (clobbers) || !r_anal_cc_regset_contains (clobbers, reg)) {
		return false;
	}
	const char *preserves = cc_regset (anal, cc, "preserve");
	return R_STR_ISEMPTY (preserves) || !r_anal_cc_regset_contains (preserves, reg);
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
	const char *cc = sdb_const_getf (anal->sdb_types, NULL, "func.%s.cc", func_name);
	return cc ? cc : r_anal_cc_default (anal);
}
