/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: type lattice, var retyping and struct field chains */

#include "tp.h"

bool type_pos_hit(TypeTrace *tt, bool in_stack, ut64 sp, int idx, st64 off, const char *place) {
	if (in_stack) {
		if (off < 0) {
			return false;
		}
		const ut64 write_addr = etrace_memwrite_addr (tt, idx); // AAA -1
		return (write_addr == sp + off);
	}
	return place && etrace_regwrite_contains (tt, idx, place);
}

void var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
	if (!name || !v) {
		return;
	}
	if (!*name || !strcmp (name, "...")) {
		return;
	}
	bool is_default = (r_str_startswith (v->name, VARPREFIX) || r_str_startswith (v->name, ARGPREFIX));
	if (*name == '*') {
		name++;
	}
	// longer name tends to be meaningful like "src" instead of "s1"
	if (!is_default && (strlen (v->name) > strlen (name))) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
	if (fcn) {
		r_anal_var_rename (anal, v, name);
	}
}

static bool tp_prim_scalar(const char *t);

// specificity lattice shared by var facts (var=true) and struct member types (var=false)
// vars: 0 default < 1 sign hint < 2 non-pointer < 3 scalar/void pointer < 4 char *, typed pointer or named type
// members: 0 default < 1 prim scalar < 2 void pointer < 3 prim pointer (char * ties) < 4 named type
static int tp_rank(const char *t, bool var) {
	if (R_STR_ISEMPTY (t)) {
		return 0;
	}
	t = r_str_skip_prefix (r_str_trim_head_ro (t), "const ");
	if (R_STR_ISEMPTY (t) || r_str_startswith (t, "undefined")) {
		return 0;
	}
	if (!strchr (t, '*')) {
		if (!strcmp (t, "void")) {
			return 0;
		}
		// member named types outrank prototype scalars; var facts keep a single non-pointer tier
		return var? 2: (tp_prim_scalar (t)? 1: 4);
	}
	if (r_str_startswith (t, "void")) {
		return var? 3: 2;
	}
	// char * is string evidence for a var, so it tops that lattice; for members it ties with the prim pointers
	if (var && r_str_startswith (t, "char")) {
		return 4;
	}
	return tp_prim_scalar (t)? 3: 4;
}

static bool tp_is_float_type(const char *t) {
	return !strcmp (t, "float") || !strcmp (t, "double") || !strcmp (t, "long double");
}

// the meet of facts proven on parallel paths is the weaker side: their common knowledge
static char *tp_type_meet(RAnal *anal, const char *a, int rank_a, const char *b, int rank_b) {
	a = r_str_skip_prefix (a, "const ");
	b = r_str_skip_prefix (b, "const ");
	if (!strcmp (a, b)) {
		return strdup (a);
	}
	// different pointees agree only on being a pointer; ranking one side would make the meet order-dependent
	if (strchr (a, '*') && strchr (b, '*')) {
		return strdup ("void *");
	}
	if (rank_a != rank_b) {
		return strdup (rank_a < rank_b? a: b);
	}
	if (tp_is_float_type (a) && tp_is_float_type (b)) {
		// unequal float spellings always include a 64-bit-or-wider side
		return strdup ("double");
	}
	// equal-rank scalar conflict: the order-independent common knowledge is the wider side's default int
	const ut64 w = R_MAX (r_anal_type_bitsize (anal, a), r_anal_type_bitsize (anal, b));
	switch (w) {
	case 64: return strdup ("int64_t");
	case 16: return strdup ("int16_t");
	case 8: return strdup ("int8_t");
	default: return strdup ("int32_t");
	}
}

static bool tp_reach_fill_cb(RAnalBlock *bb, void *user) {
	set_u_add ((SetU *)user, bb->addr);
	return true;
}

static bool tp_block_reaches(TPState *tps, ut64 from, ut64 to) {
	RAnalBlock *bb = r_anal_get_block_at (tps->anal, from);
	if (!bb) {
		// unknown topology counts as sequential, keeping the pre-lattice behavior
		return true;
	}
	bool found = false;
	SetU *reach = ht_up_find (tps->reach_cache, from, &found);
	if (!found) {
		reach = set_u_new ();
		if (!reach) {
			return true;
		}
		r_anal_block_recurse (bb, tp_reach_fill_cb, reach);
		ht_up_insert (tps->reach_cache, from, reach);
	}
	return set_u_contains (reach, to);
}

static bool tp_facts_parallel(TPState *tps, ut64 a, ut64 b) {
	if (a == b || a == UT64_MAX || b == UT64_MAX) {
		return false;
	}
	return !tp_block_reaches (tps, a, b) && !tp_block_reaches (tps, b, a);
}

// the canonical int spelling behind the sized aliases, as the legacy default test expects it
static const char *tp_expand_int(const char *t) {
	if (!strcmp (t, "int32_t")) {
		return "int";
	}
	if (!strcmp (t, "uint32_t")) {
		return "unsigned int";
	}
	if (!strcmp (t, "uint64_t")) {
		return "unsigned long long";
	}
	return t;
}

// canonical spelling as the retype applies it; NULL when a prefix form cannot attach to the var's current type
static char *tp_built_type(RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	bool is_ptr = (vname && *vname == '*');
	const char *tmp = strstr (tp_expand_int (var->type), "int");
	RStrBuf sb;
	r_strbuf_init (&sb);
	if (pfx) {
		if (tmp && !r_str_startswith (var->type, "signed")) {
			r_strbuf_setf (&sb, "%s %s", type, tmp);
		} else {
			r_strbuf_fini (&sb);
			return NULL;
		}
	} else {
		r_strbuf_set (&sb, type);
	}
	if (r_str_startswith (r_strbuf_get (&sb), "const ")) {
		// Dropping const from type
		// TODO: Inferring const type
		r_strbuf_setf (&sb, "%s", type + 6);
	}
	if (is_ptr) {
		// type *ptr => type *
		r_strbuf_append (&sb, " *");
	}
	while (ref > 0) {
		if (r_str_endswith (r_strbuf_get (&sb), "*")) { // type * => type **
			r_strbuf_append (&sb, "*");
		} else { //  type => type *
			r_strbuf_append (&sb, " *");
		}
		ref--;
	}
	while (ref < 0) {
		char *s = r_strbuf_get (&sb);
		if (!s) {
			break;
		}
		r_str_trim (s);
		if (r_str_endswith (s, "*")) {
			r_strbuf_slice (&sb, 0, r_strbuf_length (&sb) - 1);
		}
		ref++;
	}

	char *tmp1 = r_strbuf_get (&sb);
	if (r_str_startswith (tmp1, "unsigned long long")) {
		r_strbuf_set (&sb, "uint64_t");
	} else if (r_str_startswith (tmp1, "unsigned")) {
		r_strbuf_set (&sb, "uint32_t");
	} else if (r_str_startswith (tmp1, "int")) {
		r_strbuf_set (&sb, "int32_t");
	}
	r_strbuf_trim (&sb);
	// a dereferenced void pointer carries no fact, and a void variable is unusable
	if (!strcmp (r_strbuf_get (&sb), "void")) {
		r_strbuf_fini (&sb);
		return NULL;
	}
	return r_strbuf_drain_nofree (&sb);
}

// applies newtype to the var and takes ownership of it as the recorded fact
static void tp_fact_apply(RAnal *anal, TPVarFact *fact, RAnalVar *var, char *newtype, int rank, ut64 baddr) {
	r_anal_var_set_type (anal, var, newtype);
	free (fact->type);
	fact->type = newtype;
	fact->rank = rank;
	fact->bb_addr = baddr;
}

// a fact for this var is already on record, so the lattice decides instead of the legacy default checks
static void tp_fact_retype(TPState *tps, ut64 baddr, TPVarFact *fact, RAnalVar *var,
		const char *vname, const char *type, int ref, bool pfx) {
	RAnal *anal = tps->anal;
	char *cand = tp_built_type (var, vname, type, ref, pfx);
	if (!cand) {
		// a prefix that cannot attach to the current spelling keeps the incumbent, like before the lattice
		return;
	}
	const int rank = pfx? 1: tp_rank (cand, true);
	if (!strcmp (cand, fact->type)) {
		free (cand);
		return;
	}
	if (fact->rank == 1 && rank == 1) {
		// legacy sign semantics: unsigned upgrades to signed, width kept from the current spelling
		tp_fact_apply (anal, fact, var, cand, 1, baddr);
		return;
	}
	if (rank == 1) {
		// sign hints come from weak compare heuristics and never weaken stronger facts
		free (cand);
		return;
	}
	if (fact->rank == 1) {
		// any real fact beats a sign hint, on any path
		tp_fact_apply (anal, fact, var, cand, rank, baddr);
		return;
	}
	if (fact->met || tp_facts_parallel (tps, fact->bb_addr, baddr)) {
		char *met = tp_type_meet (anal, fact->type, fact->rank, cand, rank);
		free (cand);
		fact->met = true;
		if (!met || !strcmp (met, fact->type)) {
			free (met);
			return;
		}
		tp_fact_apply (anal, fact, var, met, tp_rank (met, true), baddr);
	} else if (rank > fact->rank) {
		tp_fact_apply (anal, fact, var, cand, rank, baddr);
	} else {
		free (cand);
	}
}

// declared arg count of a callee, or -1 when undeclared so reverse-stack layouts stay unresolved
int tp_callee_argc(RAnal *anal, const char *name) {
	const int n = name? r_type_func_args_count (anal->sdb_types, name): 0;
	return n > 0? n: -1;
}

// concrete argloc value at the current emulated call site; stack slots read from the ESIL map
// argc is the callee's arg count, which reverse-stack layouts need to place their slots
bool tp_argloc_val(TPState *tps, const char *cc, int argno, int argc, ut64 *val) {
	return r_anal_cc_argval (tps->anal, tps->tt.reg, cc, argno, argc, false, 0, val);
}

// the op at idx must have materialized exactly the pointer value the size-fn call received
bool tp_selfsize_hit(TPState *tps, ut32 idx, RAnalVar *var, const char *rname, ut64 pv) {
	if (!var || var->isarg || (var->kind != R_ANAL_VAR_KIND_BPV && var->kind != R_ANAL_VAR_KIND_SPV)) {
		return false;
	}
	if (R_STR_ISEMPTY (rname) || etrace_have_memread (&tps->tt, idx)) {
		return false;
	}
	const TypeTraceAccess *a = etrace_find_access (&tps->tt, idx, etrace_is_regwrite_name, (void *)rname);
	return a && a->reg.value == pv;
}

// a memset-style call on a stack var's address states the object's exact size
void tp_selfsize_var(TPState *tps, ut64 baddr, RAnalVar *var, ut64 n) {
	RAnal *anal = tps->anal;
	TPVarFact *fact = ht_up_find (tps->var_facts, (ut64)(size_t)var, NULL);
	const char *cur = fact? fact->type: var->type;
	if (r_str_startswith (cur, "uint8_t [")) {
		// clears on parallel paths merge to the larger stated size, independent of sweep order
		if (n <= strtoull (cur + strlen ("uint8_t ["), NULL, 10)) {
			return;
		}
	} else {
		if (fact && fact->rank > 2) {
			return; // pointer facts are stronger evidence than a size
		}
		if (!tp_prim_scalar (cur)) {
			return; // named and debug-provided types stay
		}
		if (n * 8 < r_anal_type_bitsize (anal, cur)) {
			return; // a partial copy or clear cannot shrink the var below its own width
		}
	}
	char *nt = r_str_newf ("uint8_t [%" PFMT64u "]", n);
	if (!nt) {
		return;
	}
	if (fact) {
		// byte-array evidence sits on the pointer tier: above plain scalars, below typed pointers
		tp_fact_apply (anal, fact, var, nt, 3, baddr);
		return;
	}
	r_anal_var_set_type (anal, var, nt);
	TPVarFact *nf = R_NEW0 (TPVarFact);
	nf->type = nt;
	nf->rank = 3;
	nf->bb_addr = baddr;
	ht_up_insert (tps->var_facts, (ut64)(size_t)var, nf);
}

static void var_retype_impl(RAnal *anal, TPState *tps, ut64 baddr, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	R_LOG_DEBUG ("Var retype %s %s", var->name, type);
	R_RETURN_IF_FAIL (anal && var && type);
	// XXX types should be passed without spaces to trim
	type = r_str_trim_head_ro (type);
	// default type if none is provided
	if (!*type) {
		type = "int";
	}
	bool is_ptr = (vname && *vname == '*');
	// removing this return makes 64bit vars become 32bit
	if (r_str_startswith (type, "int") || (!is_ptr && !strcmp (type, "void"))) {
		// default or void type carries no fact
		return;
	}
	TPVarFact *fact = tps? ht_up_find (tps->var_facts, (ut64)(size_t)var, NULL): NULL;
	if (fact) {
		tp_fact_retype (tps, baddr, fact, var, vname, type, ref, pfx);
		return;
	}
	bool is_default = strstr (tp_expand_int (var->type), "int") != NULL;
	if (!is_default && !r_str_startswith (var->type, "void")) {
		// type is already propagated; only "void *" => "char *" stays possible
		return;
	}
	char *nt = tp_built_type (var, vname, type, ref, pfx);
	if (!nt) {
		return;
	}
	r_anal_var_set_type (anal, var, nt);
	if (tps) {
		TPVarFact *nf = R_NEW0 (TPVarFact);
		nf->type = nt;
		nf->rank = pfx? 1: tp_rank (nt, true);
		nf->bb_addr = baddr;
		ht_up_insert (tps->var_facts, (ut64)(size_t)var, nf);
	} else {
		free (nt);
	}
}

// lattice-exempt path for callee-side retypes that carry no per-block fact
void var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	var_retype_impl (anal, NULL, UT64_MAX, var, vname, type, ref, pfx);
}

void tp_var_retype(TPState *tps, ut64 baddr, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	var_retype_impl (tps->anal, tps, baddr, var, vname, type, ref, pfx);
}

void get_src_regname_from_esil(RAnal *anal, const char *op_esil, ut64 addr, char *regname, int size) {
	if (!anal || !op_esil || !regname || size < 1) {
		return;
	}
	regname[0] = 0;
	if (!*op_esil) {
		return;
	}
	char src[64];
	const char *comma = strchr (op_esil, ',');
	size_t src_len = comma? (size_t)(comma - op_esil): strlen (op_esil);
	if (src_len >= sizeof (src)) {
		return;
	}
	memcpy (src, op_esil, src_len);
	src[src_len] = 0;
	RRegItem *ri = r_reg_get (anal->reg, src, -1);
	if (ri) {
		const char *s = src;
		if ((anal->config->bits == 64) && (ri->size == 32)) {
			const char *reg = r_reg_32_to_64 (anal->reg, src);
			if (reg) {
				s = reg;
			}
		}
		if (s) {
			r_str_ncpy (regname, s, size);
		}
		R_LOG_DEBUG ("===================regitem %s", regname);
		r_unref (ri);
	} else {
		R_LOG_DEBUG ("no regitem %s at 0x%" PFMT64x, src, addr);
	}
}

ut64 get_addr(TypeTrace *et, const char *regname, int idx) {
	if (R_STR_ISEMPTY (regname)) {
		return 0;
	}
	/// r_strf_var (query, 64, "%d.reg.read.%s", idx, regname);
	// return r_num_math (NULL, sdb_const_get (trace, query, 0));
	return etrace_regread_value (et, idx, regname);
}

static bool is_reg_token_char(char ch) {
	return ch == '_' || isalnum ((ut8)ch);
}

bool reg_token_contains_len(const char *regs, const char *reg, size_t reg_len) {
	if (R_STR_ISEMPTY (regs) || !reg || !reg_len) {
		return false;
	}
	const char *end = regs + strlen (regs);
	const char *ptr = regs;
	for (; *ptr; ptr++) {
		if (ptr + reg_len > end) {
			break;
		}
		if ((ptr == regs || !is_reg_token_char (ptr[-1])) && !strncmp (ptr, reg, reg_len) && !is_reg_token_char (ptr[reg_len])) {
			return true;
		}
	}
	return false;
}

bool reg_token_contains(const char *regs, const char *reg) {
	return R_STR_ISNOTEMPTY (reg)? reg_token_contains_len (regs, reg, strlen (reg)): false;
}

RAnalCondType cond_invert(RAnal *anal, RAnalCondType cond) {
	switch (cond) {
	case R_ANAL_CONDTYPE_LE:
		return R_ANAL_CONDTYPE_GT;
	case R_ANAL_CONDTYPE_LT:
		return R_ANAL_CONDTYPE_GE;
	case R_ANAL_CONDTYPE_GE:
		return R_ANAL_CONDTYPE_LT;
	case R_ANAL_CONDTYPE_GT:
		return R_ANAL_CONDTYPE_LE;
	case R_ANAL_CONDTYPE_AL:
		return R_ANAL_CONDTYPE_NV;
	case R_ANAL_CONDTYPE_NV:
		return R_ANAL_CONDTYPE_AL;
	case R_ANAL_CONDTYPE_EQ:
		return R_ANAL_CONDTYPE_NE;
	case R_ANAL_CONDTYPE_NE:
		return R_ANAL_CONDTYPE_EQ;
	default:
		R_LOG_WARN ("unhandled condition for swapping %d", cond);
		break;
	}
	return 0; // 0 is COND_ALways...
	/* I haven't looked into it but I suspect that this might be confusing:
	the opposite of any condition not in the list above is "always"? */
}

bool parse_format(TPState *tps, const char *fmt, RVecString *vec) {
	if (R_STR_ISEMPTY (fmt)) {
		return false;
	}

	Sdb *s = tps->anal->sdb_fmts;
	char arr[32] = { 0 };
	const char *ptr = strchr (fmt, '%');
	while (ptr) {
		ptr++;
		// strip [width] specifier
		ptr = r_str_trim_head_digits (ptr);
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (isalpha (*tmp)) {
			tmp++;
		}
		*tmp = '\0';
		const char *type = sdb_const_getf (s, NULL, "spec.%s.%s", tps->cfg_spec, arr);
		if (type) {
			RVecString_push_back (vec, &type);
		}
		// ptr = strchr (ptr + (tmp-arr), '%');
		ptr = strchr (ptr, '%');
	}

	return true;
}

static void retype_callee_arg(RAnal *anal, const char *callee_name, bool in_stack, const char *place, int soff, const char *type, int ref) {
	R_LOG_DEBUG (">>> CALLE ARG");
	if (!type) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_function_byname (anal, callee_name);
	if (!fcn) {
		return;
	}
	if (in_stack) {
		if (soff < 0) {
			return; // a register-homed arg has no stack slot, whatever the earlier args used
		}
		RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, soff - fcn->bp_off + 8);
		if (!var) {
			return;
		}
		// callee vars belong to another function, so their facts stay out of this pass's lattice
		var_retype (anal, var, NULL, type, ref, false);
	} else {
		if (R_STR_ISEMPTY (place)) {
			return;
		}
		RRegItem *item = r_reg_get (anal->reg, place, -1);
		if (!item) {
			return;
		}
		RAnalVar *rvar = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, item->index);
		if (!rvar) {
			r_unref (item);
			return;
		}
		char *t = strdup (type);
		var_retype (anal, rvar, NULL, type, ref, false);
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		if (lvar) {
			var_retype (anal, lvar, NULL, t, ref, false);
		}
		free (t);
		r_unref (item);
	}
}

static void propagate_arg_type(TPState *tps, ut64 baddr, RAnalVar *var, const char *name, const char *type,
		int var_memref, int callee_ref, const char *fcn_name, bool in_stack, const char *place,
		int soff, ut64 addr, bool userfnc) {
	RAnal *anal = tps->anal;
	if (userfnc) {
		retype_callee_arg (anal, fcn_name, in_stack, place, soff, var->type, -callee_ref);
	} else {
		tp_var_retype (tps, baddr, var, name, type, var_memref, false);
		var_rename (anal, var, name, addr);
	}
}

// the prefix must end at a word boundary so named types like printer_t do not rank as scalars
static bool tp_prim_scalar(const char *t) {
	static const char * const prims[] = {
		"int", "uint", "char", "short", "long", "signed", "unsigned",
		"size_t", "ssize_t", "bool", "float", "double", NULL
	};
	size_t i;
	for (i = 0; prims[i]; i++) {
		if (r_str_startswith (t, prims[i])) {
			const char c = t[strlen (prims[i])];
			if (!c || c == ' ' || isdigit ((ut8)c)) {
				return true;
			}
		}
	}
	return false;
}

#define TP_TYPEDEF_MAX 4

static const char *tp_skip_kind_prefix(const char *t) {
	for (;;) {
		const char *old = t;
		t = r_str_skip_prefix (r_str_trim_head_ro (t), "const ");
		t = r_str_skip_prefix (r_str_trim_head_ro (t), "volatile ");
		t = r_str_skip_prefix (r_str_trim_head_ro (t), "restrict ");
		if (old == t) {
			break;
		}
	}
	t = r_str_skip_prefix (t, "struct ");
	return r_str_skip_prefix (t, "union ");
}

// follow typedef aliases to the underlying type name; the bound keeps cycles from hanging
static char *tp_unwrap_typedef(RAnal *anal, const char *name) {
	char *cur = strdup (name);
	int depth;
	for (depth = 0; cur && depth < TP_TYPEDEF_MAX; depth++) {
		const char *tgt = sdb_const_getf (anal->sdb_types, NULL, "typedef.%s", cur);
		if (!tgt) {
			break;
		}
		char *next = strdup (tp_skip_kind_prefix (tgt));
		free (cur);
		cur = next;
	}
	return cur;
}

// r_anal_type_bitsize handles the pointer width, this adds the typedef unwrap
static ut64 tp_type_bits(RAnal *anal, const char *t) {
	if (R_STR_ISEMPTY (t)) {
		return 0;
	}
	char *name = tp_unwrap_typedef (anal, t);
	if (!name) {
		return 0;
	}
	const ut64 bits = r_anal_type_bitsize (anal, name);
	free (name);
	return bits;
}

// reject retypes that would overlap the next member; growing the last member is fine
static bool tp_member_fits(RAnal *anal, RAnalBaseType *bt, const RAnalTypeMember *m, const char *type) {
	const ut64 bits = tp_type_bits (anal, type);
	if (!bits) {
		return false;
	}
	ut64 next = UT64_MAX;
	RAnalTypeMember *it;
	R_VEC_FOREACH (r_anal_base_type_members (bt), it) {
		if (it->offset > m->offset && it->offset < next) {
			next = it->offset;
		}
	}
	return next == UT64_MAX || m->offset + (bits / 8) <= next;
}

// resolve "struct Foo *" / "Foo *" (typedef chains allowed) to the struct base type behind it
static RAnalBaseType *tp_resolve_ptr_base(RAnal *anal, const char *ptr_type) {
	if (R_STR_ISEMPTY (ptr_type)) {
		return NULL;
	}
	char *t = strdup (ptr_type);
	if (!t) {
		return NULL;
	}
	r_str_trim (t);
	char *star = strrchr (t, '*');
	if (!star || star[1]) {   // must be a single-level pointer "... *"
		free (t);
		return NULL;
	}
	*star = 0;
	r_str_trim (t);
	char *name = tp_unwrap_typedef (anal, tp_skip_kind_prefix (t));
	free (t);
	if (!name) {
		return NULL;
	}
	RAnalBaseType *bt = r_anal_get_base_type (anal, name);
	free (name);
	if (bt && bt->kind != R_ANAL_BASE_TYPE_KIND_STRUCT && bt->kind != R_ANAL_BASE_TYPE_KIND_UNION) {
		r_anal_base_type_free (bt);
		return NULL;
	}
	return bt;
}

// the single member at off; a nonzero width disambiguates union members sharing their offset
static RAnalTypeMember *tp_pick_member(RAnal *anal, RAnalBaseType *bt, ut64 off, int width) {
	RAnalTypeMember *m, *cand = NULL;
	R_VEC_FOREACH (r_anal_base_type_members (bt), m) {
		if (m->offset != off) {
			continue;
		}
		if (width && tp_type_bits (anal, m->type) != (ut64)width * 8) {
			continue;
		}
		if (cand) {
			return NULL;
		}
		cand = m;
	}
	// an array member is a deliberate type, neither retype nor follow it
	return (cand && !cand->count)? cand: NULL;
}

// walk deref hops through nested struct pointers and retype the member behind the last one
static bool tp_retype_field_chain(RAnal *anal, const char *ptr_type, const TPHopSeq *seq, const char *type, int width, bool store_dir) {
	if (seq->len < 1 || R_STR_ISEMPTY (type)) {
		return false;
	}
	char *pt = strdup (ptr_type);
	if (!pt) {
		return false;
	}
	bool changed = false;
	int i;
	for (i = 0; i < seq->len; i++) {
		RAnalBaseType *bt = tp_resolve_ptr_base (anal, pt);
		if (!bt) {
			break;
		}
		const bool last = i == seq->len - 1;
		const bool is_union = bt->kind == R_ANAL_BASE_TYPE_KIND_UNION;
		RAnalTypeMember *m = tp_pick_member (anal, bt, seq->off[i], (is_union && last)? width: 0);
		if (!m) {
			r_anal_base_type_free (bt);
			break;
		}
		if (last) {
			// a store into the member disproves an inferred const qualifier
			if (store_dir && r_str_startswith (m->type, "const ")) {
				char *demoted = strdup (r_str_skip_prefix (m->type, "const "));
				if (demoted) {
					free (m->type);
					m->type = demoted;
					changed = true;
				}
			}
			// overlap only matters for structs; union members all start at their shared offset
			const bool fits = is_union || tp_member_fits (anal, bt, m, type);
			if (fits && tp_rank (type, false) > tp_rank (m->type, false)) {
				char *nt = strdup (type);
				if (nt) {
					free (m->type);
					m->type = nt;
					changed = true;
				}
			}
			if (changed) {
				r_anal_save_base_type (anal, bt);
			}
		} else {
			free (pt);
			pt = strdup (m->type);
		}
		r_anal_base_type_free (bt);
		if (!pt) {
			break;
		}
	}
	free (pt);
	return changed;
}

// small positive displacements are plausible field offsets; indexed addressing is array access
static bool tp_field_disp_ok(const RAnalOp *op) {
	return op->disp != UT64_MAX && op->disp < 0x10000 && !op->ireg;
}

// hops were collected walking backwards, so append them outermost-first
static void tp_seq_from_chain(TPHopSeq *seq, const TPFieldChain *chain) {
	// the seq must hold a full chain plus the one hop call sites push themselves
	R_STATIC_ASSERT (R_ARRAY_SIZE (((TPHopSeq *)0)->off) >= R_ARRAY_SIZE (((TPFieldChain *)0)->hops) + 1);
	int i;
	for (i = chain->len - 1; i >= 0; i--) {
		seq->off[seq->len++] = chain->hops[i];
	}
}

// follow the base register of a plain base+disp load and record the disp as a deref hop
bool tp_chain_collect(TypeTrace *tt, int idx, RAnalOp *op, TPFieldChain *chain, char *regname, int size) {
	if (!chain->ok || !etrace_have_memread (tt, idx)) {
		return false;
	}
	const ut32 ot = op->type & R_ANAL_OP_TYPE_MASK;
	if (ot != R_ANAL_OP_TYPE_MOV && ot != R_ANAL_OP_TYPE_LOAD && ot != R_ANAL_OP_TYPE_PUSH) {
		chain->ok = false;
		return false;
	}
	const RArchValue *v = RVecRArchValue_at (&op->srcs, 0);
	if (!v || !v->reg || !v->memref || v->regdelta) {
		chain->ok = false;
		return false;
	}
	// a stack pointer base is a stack slot, not a field deref
	const char *sp = r_reg_alias_getname (tt->reg, R_REG_ALIAS_SP);
	const char *bp = r_reg_alias_getname (tt->reg, R_REG_ALIAS_BP);
	if ((sp && !strcmp (v->reg, sp)) || (bp && !strcmp (v->reg, bp))) {
		chain->ok = false;
		return false;
	}
	if (!tp_field_disp_ok (op)) {
		chain->ok = false;
		return false;
	}
	if (!chain->len) {
		etrace_memread_first_addr (tt, idx, &chain->slot_addr);
		chain->width = v->memref;
	}
	// a chain deeper than the budget is abandoned, truncating would mistype
	if (chain->len >= (int)R_ARRAY_SIZE (chain->hops)) {
		chain->ok = false;
		return false;
	}
	chain->hops[chain->len++] = op->disp;
	r_str_ncpy (regname, v->reg, size);
	return true;
}

// when a call arg was loaded through struct-pointer derefs, retype the member it came from
static void tp_field_from_arg(TPState *tps, int idx, RAnalVar *var, RAnalOp *op, TPFieldChain *chain, const char *type, bool userfnc) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	if (userfnc || !var || R_STR_ISEMPTY (var->type) || R_STR_ISEMPTY (type)) {
		return;
	}
	if (!chain->ok) {
		return;
	}
	TPHopSeq seq = { .len = 0 };
	ut64 lea_off = 0;
	const ut32 ot = op->type & R_ANAL_OP_TYPE_MASK;
	const bool reg_kind = var->kind == R_ANAL_VAR_KIND_REG;
	const bool memread = etrace_have_memread (tt, idx);
	ut64 slot = chain->len? chain->slot_addr: UT64_MAX;
	if (reg_kind && ot == R_ANAL_OP_TYPE_LEA) {
		if (!tp_field_disp_ok (op)) {
			return;
		}
		if (!chain->len) {
			// out-param: &ctx->field passed to a callee taking T** means the field is a T*
			const char *star = strrchr (type, '*');
			char *deref = star? r_str_ndup (type, star - type): NULL;
			if (deref) {
				r_str_trim (deref);
				const TPHopSeq hop = { .off = { op->disp }, .len = 1 };
				tp_retype_field_chain (anal, var->type, &hop, deref, 0, false);
				free (deref);
			}
			return;
		}
		// lea base+d1 followed by [reg+d2] is a single deref at d1+d2
		lea_off = op->disp;
	} else if (memread) {
		if (ot != R_ANAL_OP_TYPE_LOAD && ot != R_ANAL_OP_TYPE_MOV) {
			return;
		}
		if (reg_kind) {
			// indexed addressing is array access, not a field deref
			if (!tp_field_disp_ok (op)) {
				return;
			}
			if (!chain->len) {
				etrace_memread_first_addr (tt, idx, &slot);
			}
			seq.off[seq.len++] = op->disp;
		}
	} else if (!reg_kind || ot != R_ANAL_OP_TYPE_MOV) {
		return;
	}
	tp_seq_from_chain (&seq, chain);
	if (!seq.len) {
		return;
	}
	if (lea_off) {
		// a lea can only start the chain, so the folded disp lands on the first hop
		seq.off[0] += lea_off;
	}
	const int width = chain->len? chain->width: op->refptr;
	if (r_str_startswith (type, "const ")) {
		const char *unconst = r_str_skip_prefix (type, "const ");
		if (slot == UT64_MAX) {
			// no slot to gather write evidence for, so the qualifier cannot be kept
			tp_retype_field_chain (anal, var->type, &seq, unconst, width, false);
			return;
		}
		// the trace only reaches the call site here, so retype once the whole function ran
		TPPendingConst pc = {
			.ptr_type = strdup (var->type),
			.type = strdup (unconst),
			.seq = seq,
			.slot = slot,
			.width = width
		};
		if (pc.ptr_type && pc.type) {
			RVecTPPendingConst_push_back (&tps->pending_const, &pc);
		} else {
			tp_pending_const_fini (&pc);
		}
		return;
	}
	tp_retype_field_chain (anal, var->type, &seq, type, width, false);
}

// a value that arrived from memory: mov, cmov, load, or a memory-operand push, counted
// only when the trace confirms the read happened, so an untaken cmov never counts
bool tp_op_loads_value(TypeTrace *tt, RAnalOp *op, ut32 j) {
	switch ((op->type & R_ANAL_OP_TYPE_MASK) & ~R_ANAL_OP_TYPE_COND) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
		return etrace_have_memread (tt, j);
	}
	return false;
}

// with a deref chain the var holds the base pointer, so only its member is typed
void tp_apply_arg_type(TPState *tps, ut64 baddr, int j, RAnalVar *var, RAnalOp *op, TPFieldChain *chain,
		const char *name, const char *type, int memref, bool lea_adjust,
		const char *fcn_name, bool in_stack, const char *place, int soff, ut64 addr, bool userfnc) {
	if (!tps->cfg_fields || !chain->len) {
		int var_memref = var->isarg? 0: memref;
		int callee_ref = memref;
		if (lea_adjust) {
			const bool regvar = var->kind == R_ANAL_VAR_KIND_REG;
			// the copy chain counted its loads into memref, the hit op's own load is not in it yet
			if (regvar && tp_op_loads_value (&tps->tt, op, j)) {
				callee_ref++;
			}
			if ((op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_LEA) {
				var_memref--;
				// address-of holds for a stack var; on a register var lea is pointer arithmetic
				if (!regvar && !strchr (var->type, '[')) {
					callee_ref--;
				}
			}
		}
		propagate_arg_type (tps, baddr, var, name, type, var_memref, callee_ref,
			fcn_name, in_stack, place, soff, addr, userfnc);
	}
	if (tps->cfg_fields) {
		tp_field_from_arg (tps, j, var, op, chain, type, userfnc);
	}
}

// keep a prototype const qualifier only when the field slot shows no write in the whole trace
void tp_flush_pending_const(TPState *tps) {
	TPPendingConst *pc;
	R_VEC_FOREACH (&tps->pending_const, pc) {
		const bool written = etrace_memwrite_at (&tps->tt, pc->slot, pc->width);
		char *t = written? strdup (pc->type): r_str_newf ("const %s", pc->type);
		if (t) {
			tp_retype_field_chain (tps->anal, pc->ptr_type, &pc->seq, t, pc->width, written);
			free (t);
		}
	}
	RVecTPPendingConst_clear (&tps->pending_const);
}

#define TP_REGCOPY_MAX 4

// resolve a register to the type of the reg arg it was copied from, following copies and deref hops
static char *tp_reg_var_type(TPState *tps, RAnalFunction *fcn, const char *reg, TPFieldChain *chain) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	char cur[REGNAME_SIZE] = { 0 };
	r_str_ncpy (cur, reg, sizeof (cur));
	int j = tt->cur_idx - 1;
	int steps = 0;
	int depth;
	for (depth = 0; depth < TP_REGCOPY_MAX; depth++) {
		const int w = etrace_last_regwrite (tt, cur, j);
		// w is -1 when nothing wrote cur; charge a step per entry skipped, as the old scan did
		const int walked = j - w;
		if (steps + ((w < 0)? j: walked) >= TYPE_MATCH_MAX_BACKTRACE) {
			// budget exhausted before reaching the write, or before proving there is none
			return NULL;
		}
		steps += walked;
		j = w;
		if (j < 0) {
			// no write since entry, so the reg arg's declared type still holds
			RRegItem *item = r_reg_get (anal->reg, cur, -1);
			if (item) {
				RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, item->index);
				r_unref (item);
				if (var && R_STR_ISNOTEMPTY (var->type)) {
					return strdup (var->type);
				}
			}
			return NULL;
		}
		RAnalOp *op = tp_anal_op (anal, etrace_addrof (tt, j), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
		if (!op) {
			return NULL;
		}
		const bool copy = (op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_MOV && !etrace_have_memread (tt, j);
		char src[REGNAME_SIZE] = { 0 };
		if (copy) {
			get_src_regname_from_esil (anal, r_strbuf_get (&op->esil), op->addr, src, sizeof (src));
		} else {
			// a base+disp load is a deref hop, keep following the base pointer
			tp_chain_collect (tt, j, op, chain, src, sizeof (src));
		}
		r_anal_op_free (op);
		if (!src[0]) {
			return NULL;
		}
		r_str_ncpy (cur, src, sizeof (cur));
		j--;
	}
	return NULL;
}

// a callee return value stored into *(struct-ptr + disp) types the member behind it
bool tp_field_from_ret(TPState *tps, RAnalFunction *fcn, RAnalOp *op, const char *ret_type) {
	RAnal *anal = tps->anal;
	if (!tps->cfg_fields || R_STR_ISEMPTY (ret_type) || op->direction != R_ANAL_OP_DIR_WRITE) {
		return false;
	}
	RAnalOp *vop = tp_anal_op (anal, op->addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_BASIC);
	if (!vop) {
		return false;
	}
	const RArchValue *dv = RVecRArchValue_at (&vop->dsts, 0);
	char base[REGNAME_SIZE] = { 0 };
	ut64 disp = UT64_MAX;
	// arch plugins may fold zero or large displacements out of op->disp, the dst value keeps them
	if (dv && dv->reg && dv->memref && !dv->regdelta && dv->delta >= 0 && dv->delta < 0x10000) {
		r_str_ncpy (base, dv->reg, sizeof (base));
		disp = dv->delta;
	}
	r_anal_op_free (vop);
	if (!base[0]) {
		return false;
	}
	TPFieldChain chain = { .slot_addr = UT64_MAX, .ok = true };
	char *ptr_type = tp_reg_var_type (tps, fcn, base, &chain);
	if (!ptr_type) {
		return false;
	}
	// the assignment itself disproves const on the member
	ret_type = r_str_skip_prefix (ret_type, "const ");
	TPHopSeq seq = { .len = 0 };
	tp_seq_from_chain (&seq, &chain);
	seq.off[seq.len++] = disp;
	const bool changed = tp_retype_field_chain (anal, ptr_type, &seq, ret_type, op->refptr, true);
	free (ptr_type);
	return changed;
}
