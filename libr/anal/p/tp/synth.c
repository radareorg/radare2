/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: afts native struct synthesis */

#include "tp.h"

static const char *synth_type_for_size(int sz) {
	switch (sz) {
	case 1: return "uint8_t";
	case 2: return "uint16_t";
	case 4: return "uint32_t";
	}
	return "uint64_t";
}

// malloc:// maps are demand-zero, so resident cost tracks the written SYNTH_DETW*nwin, not the full region
#define SYNTH_WINDOW 0x40000ULL // per-object sentinel window (field offsets capped at WINDOW/2)
#define SYNTH_MAXARGS 8 // args past this are not seeded (not recovered)
#define SYNTH_MAXRETS 8 // allocator call sites tracked per function, one window each
// allocator returns ride the window index space above the real args, so one region serves both
#define SYNTH_NWIN (SYNTH_MAXARGS + SYNTH_MAXRETS)
#define SYNTH_IS_RET(a) ((a) >= SYNTH_MAXARGS)
#define SYNTH_RET_SLOT(a) ((a) - SYNTH_MAXARGS)
#define SYNTH_REGION(nwin) (SYNTH_WINDOW * (nwin)) // sentinel region for the live windows
// per-object span scanned for pointer fields; a pointer field past this is not nested
#define SYNTH_DETW 0x1000ULL
// child-window size per pointer slot; a deref offset past this aliases the next slot and is lost
#define SYNTH_PSTRIDE 0x400ULL
#define SYNTH_SLOTS(psz) (SYNTH_DETW / (psz)) // detectable pointer slots per window
#define SYNTH_PSIZE(psz, nwin) (SYNTH_SLOTS (psz) * (nwin) * SYNTH_PSTRIDE) // whole poison region
#define SYNTH_MIN_FIELDS 2 // smallest field count worth emitting as a struct
#define SYNTH_ARR_MIN 4 // shortest constant-stride run collapsed into an array member
#define SYNTH_SPROOM 0x80ULL // stack-map room above SP for stack-arg sentinels (SYNTH_MAXARGS * 8 + slack)
#define SYNTH_MAXOPS 200000 // emulation budget, the recorded trace is partial beyond it
// a stated size past this is a buffer or a stale register, not a struct layout worth padding out to
#define SYNTH_MAXHINT 0x1000ULL

static int synth_key_cmp(const SynthField *x, const SynthField *y) {
	if (x->arg != y->arg) {
		return x->arg - y->arg;
	}
	if (x->off != y->off) {
		return (x->off < y->off)? -1: 1;
	}
	return 0;
}

static int synth_field_cmp(const SynthField *a, const SynthField *b) {
	const int d = synth_key_cmp (a, b);
	return d? d: b->size - a->size; // larger width first
}

// sort poison hits so all children of one pointer field are adjacent
static int synth_child_cmp(const SynthField *x, const SynthField *y) {
	int d = synth_key_cmp (x, y);
	if (!d && x->child != y->child) {
		d = (x->child < y->child)? -1: 1;
	}
	return d? d: y->size - x->size;
}

static char *synth_root_name(const char *fname, int arg) {
	return SYNTH_IS_RET (arg)? r_str_newf ("%s_ret%d", fname, SYNTH_RET_SLOT (arg))
		: r_str_newf ("%s_arg%d", fname, arg);
}

// object size stated by a size-fn call, with the call that stated it
typedef struct {
	ut64 size;
	ut64 site;
	const char *fn; // borrowed from the callee function/flag, outlives the emulation
} SynthWant;

// record the stated size only when its pad extended the struct beyond the observed accesses
static void synth_set_hint(SynthRec *rec, const SynthWant *w, bool clamped) {
	if (clamped && w->fn) {
		rec->hint_size = w->size;
		rec->hint_site = w->site;
		rec->hint_fn = strdup (w->fn);
	}
}

// the array member covering off, or NULL for a scalar access
static SynthArr *synth_arr_at(SynthRec *rec, ut64 off) {
	SynthArr *a;
	R_VEC_FOREACH (&rec->arrs, a) {
		if (off >= a->off && off < a->off + (ut64)a->elsize * a->count) {
			return a;
		}
	}
	return NULL;
}

static SynthRec *synth_rec_find(RVecSynthRec *recs, int arg, bool child, ut64 off) {
	SynthRec *r;
	R_VEC_FOREACH (recs, r) {
		if (r->child == child && r->arg == arg && (!child || r->off == off)) {
			return r;
		}
	}
	return NULL;
}

// remember each access site in its struct's rec, for hints and command emission
static void synth_collect_sites(RVecSynthRec *recs, RVecSynthField *fields, bool child) {
	SynthField *f;
	R_VEC_FOREACH (fields, f) {
		SynthRec *rc = synth_rec_find (recs, f->arg, child, child? f->off: 0);
		if (rc) {
			SynthSite *st = RVecSynthSite_emplace_back (&rc->sites);
			if (st) {
				*st = (SynthSite){ .off = child? f->child: f->off, .iaddr = f->iaddr };
			}
		}
	}
}

// make disasm render the member name at the accessing instruction
static void synth_hint(RAnal *anal, SynthRec *rec, ut64 off, ut64 iaddr) {
	const char *sname = rec->bt->name;
	char *memb = r_type_get_struct_memb (anal->sdb_types, sname, (int)off);
	if (!memb) {
		// interior of an atomic array member doesn't resolve; snap to its base
		SynthArr *a = synth_arr_at (rec, off);
		if (a) {
			memb = r_type_get_struct_memb (anal->sdb_types, sname, (int)a->off);
		}
	}
	if (off > 0) {
		if (memb) {
			r_anal_hint_set_offset (anal, iaddr, memb);
		}
	} else {
		// off 0 with no resolved member is a whole-struct access ([reg]); label it with the type
		r_meta_set_string (anal, R_META_TYPE_VARTYPE, iaddr, memb? memb: sname);
	}
	free (memb);
}

// takes ownership of type; returns the new end offset
static ut64 synth_add_member(RAnalBaseType *bt, const char *pfx, ut64 off, int size, int count, char *type) {
	RAnalTypeMember *m = RVecAnalTypeMember_emplace_back (&bt->struct_data.members);
	if (!m) {
		free (type);
		return off;
	}
	m->name = r_str_newf ("%s_0x%" PFMT64x, pfx, off);
	m->type = type;
	m->offset = off;
	m->bitsize = (size_t)size * 8;
	m->count = count;
	return off + (ut64)size;
}

// a size-fn call stated the exact object size: pad the unobserved tail out to it
static ut64 synth_pad_tail(RAnalBaseType *bt, RVecSynthArr *arrs, ut64 cur, ut64 want) {
	if (want <= cur) {
		return cur;
	}
	const int padlen = (int)(want - cur);
	SynthArr *pa = RVecSynthArr_emplace_back (arrs);
	if (pa) {
		*pa = (SynthArr){ .off = cur, .elsize = 1, .count = padlen };
	}
	synth_add_member (bt, "pad", cur, 1, padlen, strdup ("uint8_t"));
	return want;
}

static const char *synth_fcn_cc(RAnal *anal, RAnalFunction *fcn) {
	const char *cc = r_anal_function_cc (fcn);
	return cc? cc: r_anal_cc_default (anal);
}

// the cc's caller-saved register names, poisoned across skipped calls
static RList *synth_clobber_regs(RAnal *anal, const char *cc) {
	RList *list = NULL;
	RListIter *iter;
	RRegItem *item;
	r_list_foreach (anal->reg->regset[R_REG_TYPE_GPR].regs, iter, item) {
		if (r_anal_cc_isclobber (anal, cc, item->name)) {
			if (!list) {
				list = r_list_newf (free);
			}
			r_list_append (list, strdup (item->name));
		}
	}
	return list;
}

// how many of the convention's stack args sit below this slot; nregs, when given, counts the register-homed ones
static int synth_stack_rank(RAnal *anal, const char *cc, int argi, st64 off, int *nregs) {
	int i, rank = 0;
	for (i = 0; i < SYNTH_MAXARGS; i++) {
		RAnalCCArgSlot other;
		if (!r_anal_cc_argslot (anal, cc, i, SYNTH_MAXARGS, true, &other)) {
			continue;
		}
		if (other.reg) {
			if (nregs) {
				(*nregs)++;
			}
		} else if (i != argi && other.off < off) {
			rank++;
		}
	}
	return rank;
}

// the arg number to report for a window: the modeled count is a guess, so name registers by the
// index they hold without one, and stack slots by their rank upward from SP after those registers
static int synth_arg_label(RAnal *anal, const char *cc, int win) {
	RAnalCCArgSlot slot;
	if (SYNTH_IS_RET (win) || !r_anal_cc_argslot (anal, cc, win, SYNTH_MAXARGS, true, &slot)) {
		return win; // ret windows are not args, and stack-arg ccs answer for arg 8+
	}
	if (!slot.reg) {
		int nregs = 0;
		const int rank = synth_stack_rank (anal, cc, win, slot.off, &nregs);
		return nregs + rank;
	}
	int i;
	for (i = 0; i < SYNTH_MAXARGS; i++) {
		RAnalCCArgSlot other;
		if (r_anal_cc_argslot (anal, cc, i, -1, true, &other)
				&& other.reg && !strcmp (other.reg, slot.reg)) {
			return i;
		}
	}
	return win;
}

static RAnalVar *synth_reg_var(RAnal *anal, RAnalFunction *fcn, const char *rname) {
	RRegItem *ri = r_reg_get (anal->reg, rname, -1);
	if (!ri) {
		return NULL;
	}
	const int index = ri->index;
	r_unref (ri);
	return r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, index);
}

// resolve with the arg count the seeding used, or a reverse-stack cc maps to different slots here
static RAnalVar *synth_arg_var(RAnal *anal, RAnalFunction *fcn, const char *cc, int argi) {
	if (SYNTH_IS_RET (argi)) {
		return NULL; // a returned object binds to no argument, and stack-arg ccs answer for arg 8+
	}
	RAnalCCArgSlot slot;
	if (!r_anal_cc_argslot (anal, cc, argi, SYNTH_MAXARGS, true, &slot)) {
		return NULL;
	}
	if (slot.reg) {
		return synth_reg_var (anal, fcn, slot.reg);
	}
	// rank this slot among the stack args, so the n-th lowest maps to the n-th stack var in delta order
	const int nth = synth_stack_rank (anal, cc, argi, slot.off, NULL);
	RAnalVar *pick = NULL;
	int lastd = INT_MIN;
	int n;
	for (n = 0; n <= nth; n++) {
		pick = NULL;
		int bestd = INT_MAX;
		RAnalVar **vp;
		R_VEC_FOREACH (&fcn->vars, vp) {
			RAnalVar *v = *vp;
			if (v->kind == R_ANAL_VAR_KIND_REG || !v->isarg) {
				continue;
			}
			// BPV and SPV deltas use different bases, so normalize before ordering
			const int off = v->kind == R_ANAL_VAR_KIND_BPV? v->delta + fcn->bp_off: v->delta;
			if (off > lastd && off < bestd) {
				bestd = off;
				pick = v;
			}
		}
		if (!pick) {
			return NULL;
		}
		lastd = bestd;
	}
	return pick;
}

// the first traced write of a ret-window sentinel names the receiving var, so a later reassignment (p = NULL) cannot erase it
static RAnalVar *synth_ret_var(TPState *tps, RAnalFunction *fcn, ut64 want, ut64 spv, int psz) {
	RAnal *anal = tps->anal;
	TypeTraceAccess *a;
	R_VEC_FOREACH (&tps->tt.db.accesses, a) {
		if (!a->is_write) {
			continue;
		}
		if (a->is_reg) {
			if (a->reg.value != want) {
				continue;
			}
			RAnalVar *v = synth_reg_var (anal, fcn, a->reg.name);
			// an arg register still names the incoming argument, which the arg windows own
			if (v && !v->isarg) {
				return v;
			}
			continue;
		}
		if (a->mem.size != psz || a->mem.value != want) {
			continue;
		}
		const ut64 ma = a->mem.addr;
		if (ma < tps->stack_base || ma >= tps->stack_base + tps->stack_size) {
			continue;
		}
		// arg slots stay eligible: the seeding writes bypass the trace, so this store is the program's own
		const st64 delta = (st64)(ma - spv);
		RAnalVar **vp;
		R_VEC_FOREACH (&fcn->vars, vp) {
			RAnalVar *v = *vp;
			if (v->kind != R_ANAL_VAR_KIND_REG && v->delta == delta) {
				return v;
			}
		}
	}
	return NULL;
}

// the var a root rec binds to: the named ret receiver, or the cc-mapped argument
static RAnalVar *synth_rec_var(RAnal *anal, RAnalFunction *fcn, const char *cc, const SynthRec *rec) {
	if (SYNTH_IS_RET (rec->arg)) {
		return rec->var? r_anal_function_get_var_byname (fcn, rec->var): NULL;
	}
	return synth_arg_var (anal, fcn, cc, rec->arg);
}

// the first allocation storing into a reused local keeps it, so the name is not handed out twice
static bool synth_var_claimed(RVecSynthRec *recs, const SynthRec *rec, const char *name) {
	SynthRec *r;
	R_VEC_FOREACH (recs, r) {
		if (r == rec) {
			break;
		}
		if (!r->child && r->var && !strcmp (r->var, name)) {
			return true;
		}
	}
	return false;
}

// NULL when an earlier rec already resolved to this var, so arg and ret recs cannot both claim a slot
static RAnalVar *synth_bound_var(RAnal *anal, RAnalFunction *fcn, const char *cc, RVecSynthRec *recs, const SynthRec *rec) {
	RAnalVar *av = synth_rec_var (anal, fcn, cc, rec);
	if (!av) {
		return NULL;
	}
	SynthRec *r;
	R_VEC_FOREACH (recs, r) {
		if (r == rec) {
			break;
		}
		if (!r->child && synth_rec_var (anal, fcn, cc, r) == av) {
			return NULL;
		}
	}
	return av;
}

// the type may carry qualifiers and any pointer depth around the struct name
static bool synth_type_names(const char *vtype, const char *name) {
	const char *p = strstr (r_str_get (vtype), "struct ");
	if (!p) {
		return false;
	}
	p += strlen ("struct ");
	const size_t len = strlen (name);
	return strcspn (p, " *") == len && !strncmp (p, name, len);
}

// a member of a kept parent, so dropping it would dangle the parent rather than a var
static bool synth_member_names(RAnal *anal, const char *parent, const char *name) {
	RAnalBaseType *bt = r_anal_get_base_type (anal, parent);
	if (!bt) {
		return false;
	}
	bool hit = false;
	if (bt->kind == R_ANAL_BASE_TYPE_KIND_STRUCT) {
		RAnalTypeMember *m;
		R_VEC_FOREACH (&bt->struct_data.members, m) {
			if (synth_type_names (m->type, name)) {
				hit = true;
				break;
			}
		}
	}
	r_anal_base_type_free (bt);
	return hit;
}

// dropping a generated type a user-edited var still reaches would leave that var unresolvable
static bool synth_type_referenced(RAnal *anal, RAnalFunction *fcn, const char *name) {
	RAnalVar **vp;
	R_VEC_FOREACH (&fcn->vars, vp) {
		const char *vt = r_str_get ((*vp)->type);
		if (synth_type_names (vt, name)) {
			return true;
		}
		const char *p = strstr (vt, "struct ");
		if (!p) {
			continue;
		}
		p += strlen ("struct ");
		char *parent = r_str_ndup (p, strcspn (p, " *"));
		const bool hit = parent && synth_member_names (anal, parent, name);
		free (parent);
		if (hit) {
			return true;
		}
	}
	return false;
}

// a rerun may bind elsewhere or not at all, so put back the type each var had before we touched it
static void synth_restore_vars(RAnal *anal, RAnalFunction *fcn, Sdb *bookdb, const char *vkey) {
	char *vrec = sdb_get (bookdb, vkey, 0);
	if (!vrec) {
		return;
	}
	char *vp;
	sdb_aforeach (vp, vrec) {
		if (r_str_split (vp, ':') == 4) {
			RAnalVar *v = r_anal_function_get_var (fcn, *vp, atoi (r_str_word_get0 (vp, 1)));
			char *applied = (char *)sdb_decode (r_str_word_get0 (vp, 2), NULL);
			char *prev = (char *)sdb_decode (r_str_word_get0 (vp, 3), NULL);
			// only the exact type the last run applied is ours to replace
			if (v && applied && prev && !strcmp (r_str_get (v->type), applied)) {
				r_anal_var_set_type (anal, v, prev);
			}
			free (applied);
			free (prev);
		}
		sdb_aforeach_next (vp);
	}
	free (vrec);
}

// point the bound var at the synthesized struct, booking the replaced type so a rerun can undo it
static void synth_bind_var(RAnal *anal, RAnalFunction *fcn, const char *cc, RVecSynthRec *recs, SynthRec *rec, RStrBuf *vsb) {
	RAnalVar *av = synth_bound_var (anal, fcn, cc, recs, rec);
	if (!av) {
		return;
	}
	char *ty = r_str_newf ("struct %s *", rec->bt->name);
	if (ty) {
		char *ap64 = sdb_encode ((const ut8 *)ty, -1);
		char *pt64 = sdb_encode ((const ut8 *)r_str_get (av->type), -1);
		if (ap64 && pt64) {
			// keyed by location, so a later rename cannot orphan the record
			r_strbuf_appendf (vsb, "%s%c:%d:%s:%s",
				r_strbuf_length (vsb)? ",": "", av->kind, av->delta, ap64, pt64);
		}
		free (ap64);
		free (pt64);
		r_anal_var_set_type (anal, av, ty);
		free (ty);
	}
	if (!rec->var) {
		rec->var = strdup (av->name);
	}
}

// each pointer slot holds a strided poison pointer into its own child window (a deref decodes back to the parent offset); one level deep, child windows hold no further poison
static int synth_poison_map(RAnal *anal, ut64 sbase, int align, int psz, int nwin, ut64 *pbase) {
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	const int fd = tp_map_anon (anal, SYNTH_PSIZE (psz, nwin), align, pbase, NULL);
	if (fd < 0) {
		return -1;
	}
	ut8 *win = malloc (SYNTH_DETW);
	if (!win) {
		iob->fd_close (io, fd);
		return -1;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	int ai;
	for (ai = 0; ai < nwin; ai++) {
		ut64 o;
		for (o = 0; o < SYNTH_DETW; o += psz) {
			const ut64 slot = ((ut64)ai * SYNTH_SLOTS (psz)) + (o / psz);
			r_write_ble (win + o, *pbase + slot * SYNTH_PSTRIDE, be, psz * 8);
		}
		iob->write_at (io, sbase + (ut64)ai * SYNTH_WINDOW, win, (int)SYNTH_DETW);
	}
	free (win);
	return fd;
}

// seed each arg reg with a sentinel base and turn observed base+offset accesses into struct fields
// recs may be NULL when the caller only wants the apply side effects
typedef struct {
	TPState *tps;
	ut64 sbase;
	ut64 send; // end of the sentinel region, covering only the windows in play
	ut64 pbase;
	ut64 pend; // end of the poison region, equal to pbase when there is none
	SynthWant want[SYNTH_NWIN]; // stated object size + provenance, per window
	RVecSynthField childwant; // same, for dereferenced-field children keyed by (arg, off)
	const char *fn; // callee of the call being harvested
	ut64 site;
	ut64 ret_site[SYNTH_MAXRETS]; // allocator call site per ret slot
	int nrets;
	int psz;
	bool rets; // allocator entries exist, so every call resolves a return register
	bool retwarn;
} SynthSizeCtx;

// window index for a sentinel pointer, -1 when it lands outside the region
static int synth_window_arg(const SynthSizeCtx *c, ut64 pv, ut64 *woff) {
	if (pv < c->sbase || pv >= c->send) {
		return -1;
	}
	*woff = (pv - c->sbase) % SYNTH_WINDOW;
	return (int)((pv - c->sbase) / SYNTH_WINDOW);
}

static void synth_want_grow(SynthSizeCtx *c, int argi, ut64 size) {
	if (size > c->want[argi].size) {
		c->want[argi] = (SynthWant){ .size = size, .site = c->site, .fn = c->fn };
	}
}

static SynthWant synth_child_want(RVecSynthField *cw, int arg, ut64 off) {
	SynthWant w = { 0 };
	SynthField *f;
	R_VEC_FOREACH (cw, f) {
		if (f->arg == arg && f->off == off && (ut64)f->size > w.size) {
			w = (SynthWant){ .size = (ut64)f->size, .site = f->iaddr, .fn = f->fn };
		}
	}
	return w;
}

static void synth_size_entry(SynthSizeCtx *c, const char *cc, const TPSizeFn *sf) {
	ut64 pv = 0, n = 0;
	if (!tp_sizefn_read (c->tps, cc, sf, tp_callee_argc (c->tps->anal, c->fn), &pv, &n)) {
		return;
	}
	ut64 off = 0;
	const int argi = synth_window_arg (c, pv, &off);
	if (argi >= 0) {
		// interior pointers still bound the object: off + n bytes from the window base
		if (n < SYNTH_WINDOW / 2 && off + n < SYNTH_WINDOW / 2) { // n first, so a stale value cannot wrap the sum
			synth_want_grow (c, argi, off + n);
		}
		return;
	}
	// a dereferenced pointer field carries a poison value decoding to its parent (arg, offset)
	if (pv >= c->pbase && pv < c->pend) {
		const ut64 slot = (pv - c->pbase) / SYNTH_PSTRIDE;
		const ut64 coff = (pv - c->pbase) % SYNTH_PSTRIDE;
		if (n >= SYNTH_PSTRIDE / 2 || coff + n >= SYNTH_PSTRIDE / 2) {
			return; // the stride tail only ever holds negative offsets off the next slot
		}
		SynthField *cw = RVecSynthField_emplace_back (&c->childwant);
		if (cw) {
			*cw = (SynthField){
				.arg = (int)(slot / SYNTH_SLOTS (c->psz)),
				.off = (slot % SYNTH_SLOTS (c->psz)) * c->psz,
				.size = (int)(coff + n),
				.iaddr = c->site,
				.fn = c->fn,
			};
		}
	}
}

// stash a ret-window seed for an allocator call; the emulation loop applies it after the clobber
static void synth_ret_entry(SynthSizeCtx *c, const char *cc, const TPSizeFn *sf) {
	if (!c->tps->seed_reg) {
		return; // this convention returns no value in a register, so there is nothing to seed
	}
	ut64 pv = 0, n = 0;
	const int argc = tp_callee_argc (c->tps->anal, c->fn);
	if (!tp_sizefn_read (c->tps, cc, sf, argc, &pv, &n) || n >= SYNTH_MAXHINT) {
		n = 0;
	}
	if (sf->alias_arg >= 0) {
		ut64 av = 0, woff = 0;
		const int argi = tp_argloc_val (c->tps, cc, sf->alias_arg, argc, &av)
			? synth_window_arg (c, av, &woff): -1;
		if (argi >= 0) {
			// realloc returns the object it was given, so keep growing the window it points into
			c->tps->seed_val = av;
			if (n && woff + n < SYNTH_WINDOW / 2) {
				synth_want_grow (c, argi, woff + n);
			}
			return;
		}
	}
	int slot = 0;
	while (slot < c->nrets && c->ret_site[slot] != c->site) {
		slot++;
	}
	if (slot >= SYNTH_MAXRETS) {
		if (!c->retwarn) {
			R_LOG_WARN ("Struct synthesis tracks %d allocator sites per function; 0x%08" PFMT64x
				" and later are partial", SYNTH_MAXRETS, c->site);
			c->retwarn = true;
		}
		return; // the ret reg was already zeroed, so nothing folds into the last window
	}
	if (slot == c->nrets) {
		c->ret_site[c->nrets++] = c->site;
	}
	const int argi = SYNTH_MAXARGS + slot;
	if (n) {
		synth_want_grow (c, argi, n);
	}
	c->tps->seed_val = c->sbase + (ut64)argi * SYNTH_WINDOW;
}

// harvest object sizes at calls to size functions while the sentinel emulation runs
static void synth_size_cb(void *user, RAnalOp *aop, RAnalOp *next_op, ut64 addr, ut64 bb_addr) {
	SynthSizeCtx *c = user;
	RAnal *anal = c->tps->anal;
	const ut32 base = tp_op_call_base (aop->type);
	if (!base) {
		return;
	}
	RAnalFunction *fcn_call = NULL;
	const char *name = tp_call_target_name (anal, aop, base, &fcn_call);
	if (R_STR_ISEMPTY (name)) {
		return;
	}
	const char *cc = tp_call_cc (anal, fcn_call, name);
	if (!cc) {
		cc = r_anal_cc_default (anal);
	}
	if (!cc) {
		return;
	}
	c->fn = name;
	c->site = addr;
	R_FREE (c->tps->seed_reg);
	if (c->rets) {
		// every call leaves its return register defined, so no sentinel survives into an unrelated result
		const char *rr = r_anal_cc_ret (anal, cc, 0);
		c->tps->seed_reg = (R_STR_ISNOTEMPTY (rr) && *rr != '^')? strdup (rr): NULL;
		c->tps->seed_val = 0;
	}
	const TPSizeFn *sf;
	R_VEC_FOREACH (&c->tps->sizefns, sf) {
		if (!tp_sizefn_name_match (sf, name)) {
			continue;
		}
		if (sf->ptr_arg < 0) {
			synth_ret_entry (c, cc, sf);
		} else {
			synth_size_entry (c, cc, sf);
		}
	}
}

void type_synth(RAnal *anal, RAnalFunction *fcn, bool apply, RVecSynthRec *recs) {
	R_RETURN_IF_FAIL (anal && fcn);
	RVecSynthRec local;
	const bool own_recs = !recs;
	if (own_recs) {
		RVecSynthRec_init (&local);
		recs = &local;
	}
	TPState *tps = tps_init (anal);
	if (!tps) {
		if (own_recs) {
			RVecSynthRec_fini (recs);
		}
		return;
	}
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	const int align = R_MAX (1, r_arch_info (anal->arch, R_ARCH_INFO_DATA_ALIGN));
	// unseeded ret windows would still accept a stray pointer, so only map the ones in play
	const bool rets = tp_sizefns_have_rets (&tps->sizefns);
	const int nwin = rets? SYNTH_NWIN: SYNTH_MAXARGS;
	ut64 sbase = 0;
	const int sfd = tp_map_anon (anal, SYNTH_REGION (nwin), align, &sbase, NULL);
	if (sfd < 0) {
		tps_fini (tps);
		return;
	}
	const char *cc = synth_fcn_cc (anal, fcn);
	tps->clobber = synth_clobber_regs (anal, cc);
	// the poison slots and the sbuf[8] stack write assume <= 8 bytes
	const int psz = r_anal_cc_wordsize (anal, cc);
	int i;
	ut64 pbase = 0;
	const int pfd = synth_poison_map (anal, sbase, align, psz, nwin, &pbase);
	if (pfd < 0) {
		pbase = 0; // the locate step may have picked a base before the mapping failed
	}
	const ut64 pend = pbase? pbase + SYNTH_PSIZE (psz, nwin): 0;
	const bool sbe = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	// tps_init leaves only align * 8 bytes of map above SP
	const ut64 spv = r_reg_getv (tps->tt.reg, "SP") - SYNTH_SPROOM;
	r_reg_setv (tps->tt.reg, "SP", spv);
	r_reg_setv (tps->tt.reg, "BP", spv);
	for (i = 0; i < SYNTH_MAXARGS; i++) {
		RAnalCCArgSlot slot;
		// the modeled arg count keeps reverse-stack conventions (pascal, borland) resolvable
		if (!r_anal_cc_argslot (anal, cc, i, SYNTH_MAXARGS, true, &slot)) {
			continue;
		}
		const ut64 sval = sbase + (ut64)i * SYNTH_WINDOW;
		if (slot.reg) {
			r_reg_setv (tps->tt.reg, slot.reg, sval);
		} else {
			ut8 sbuf[8] = {0};
			r_write_ble (sbuf, sval, sbe, psz * 8);
			iob->write_at (io, spv + slot.off, sbuf, psz);
		}
	}
	// emulate the function linearly, letting the mem voyeurs record base+offset accesses
	SynthSizeCtx szctx = { .tps = tps, .sbase = sbase, .send = sbase + SYNTH_REGION (nwin),
		.pbase = pbase, .pend = pend, .psz = psz, .rets = rets };
	RVecSynthField_init (&szctx.childwant);
	const bool harvest = !RVecTPSizeFn_empty (&tps->sizefns);
	r_reg_setv (tps->tt.reg, "PC", fcn->addr);
	if (tp_emulate_linear (tps, fcn, SYNTH_MAXOPS, harvest? synth_size_cb: NULL, harvest? &szctx: NULL, false, false) == TP_EMU_BUDGET) {
		R_LOG_WARN ("Struct synthesis hit the %d-op budget at 0x%08" PFMT64x "; result is partial", SYNTH_MAXOPS, fcn->addr);
	}

	// collect accesses in the arg windows (fields) and the poison region (deref evidence)
	RVecSynthField vfields;
	RVecSynthField vporig;
	RVecSynthField_init (&vfields);
	RVecSynthField_init (&vporig);
	const ut32 nacc = VecAccess_length (&tps->tt.db.accesses);
	const ut32 nops = VecTraceOp_length (&tps->tt.db.ops);
	bool oom = false;
	ut32 oi;
	for (oi = 0; oi < nops && !oom; oi++) {
		TypeTraceOp *top = VecTraceOp_at (&tps->tt.db.ops, oi);
		const ut32 kend = R_MIN (top->end, nacc);
		ut32 k;
		for (k = top->start; k < kend; k++) {
			TypeTraceAccess *a = VecAccess_at (&tps->tt.db.accesses, k);
			if (!a || a->is_reg) {
				continue;
			}
			const ut64 ma = a->mem.addr;
			const int asz = a->mem.size > 0? a->mem.size: 1;
			if (ma >= pbase && ma < pend) {
				const ut64 choff = (ma - pbase) % SYNTH_PSTRIDE;
				if (choff >= SYNTH_PSTRIDE / 2) {
					continue; // as in the windows, the stride tail only holds negative offsets
				}
				// decode the poison slot back to the exact (arg, parent field offset)
				const ut64 slot = (ma - pbase) / SYNTH_PSTRIDE;
				SynthField *sf = RVecSynthField_emplace_back (&vporig);
				if (!sf) {
					oom = true;
					break;
				}
				*sf = (SynthField){
					.arg = (int)(slot / SYNTH_SLOTS (psz)),
					.off = (slot % SYNTH_SLOTS (psz)) * psz,
					.child = choff,
					.size = asz,
					.iaddr = top->addr,
				};
				continue;
			}
			ut64 woff = 0;
			const int argi = synth_window_arg (&szctx, ma, &woff);
			if (argi < 0 || woff >= SYNTH_WINDOW / 2) {
				continue; // negative offsets off a neighboring window land in the window tail
			}
			SynthField *sf = RVecSynthField_emplace_back (&vfields);
			if (!sf) {
				oom = true;
				break;
			}
			*sf = (SynthField){
				.arg = argi,
				.off = woff,
				.size = asz,
				.iaddr = top->addr,
			};
		}
	}
	RVecSynthField_sort (&vfields, synth_field_cmp);
	RVecSynthField_sort (&vporig, synth_child_cmp);
	const size_t nfields = RVecSynthField_length (&vfields);
	const size_t nporig = RVecSynthField_length (&vporig);
	SynthField *fields = R_VEC_START_ITER (&vfields);
	SynthField *porig = R_VEC_START_ITER (&vporig);
	// a field whose loaded value was dereferenced is a pointer; both arrays sort by (arg, off)
	size_t pi = 0, fi = 0;
	while (pi < nporig && fi < nfields) {
		const int d = synth_key_cmp (&porig[pi], &fields[fi]);
		if (d > 0) {
			fi++;
		} else if (d < 0) {
			pi++;
		} else {
			fields[fi++].is_ptr = true;
		}
	}
	// pointer fields with enough distinct child accesses get a nested child struct
	char *fname = r_str_sanitize_sdb_key (fcn->name);
	size_t ci = 0;
	while (ci < nporig) {
		const int carg = porig[ci].arg;
		const ut64 coff = porig[ci].off;
		RAnalBaseType *cbt = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		ut64 ccur = 0;
		int ccount = 0;
		size_t cj = ci;
		while (cj < nporig && porig[cj].arg == carg && porig[cj].off == coff) {
			const ut64 choff = porig[cj].child;
			const int csize = porig[cj].size;
			do {
				cj++;
			} while (cj < nporig && porig[cj].arg == carg && porig[cj].off == coff
				&& porig[cj].child == choff);
			if (choff < ccur) {
				continue; // overlaps the previous member (widest-wins, like the parent)
			}
			ccur = synth_add_member (cbt, "field", choff, csize, 0, strdup (synth_type_for_size (csize)));
			ccount++;
		}
		const SynthWant cwant = synth_child_want (&szctx.childwant, carg, coff);
		if (ccount >= SYNTH_MIN_FIELDS || (ccount > 0 && cwant.size > ccur)) {
			RVecSynthArr carrs;
			RVecSynthArr_init (&carrs);
			const ut64 preccur = ccur;
			ccur = synth_pad_tail (cbt, &carrs, ccur, cwant.size);
			const int clabel = synth_arg_label (anal, cc, carg);
			char *croot = synth_root_name (fname, clabel);
			cbt->name = r_str_newf ("%s_0x%" PFMT64x, croot, coff);
			free (croot);
			cbt->size = ccur * 8; // the base type holds bits
			SynthRec *rec = RVecSynthRec_emplace_back (recs);
			if (rec) {
				*rec = (SynthRec){ .arg = carg, .argno = clabel, .child = true, .off = coff, .bt = cbt };
				synth_set_hint (rec, &cwant, ccur > preccur);
				RVecSynthSite_init (&rec->sites);
				rec->arrs = carrs;
				cbt = NULL;
			} else {
				RVecSynthArr_fini (&carrs);
			}
		}
		if (cbt) {
			r_anal_base_type_free (cbt);
		}
		ci = cj;
	}

	// one struct per argument that accumulated enough non-overlapping fields
	size_t p = 0;
	while (p < nfields) {
		const int arg = fields[p].arg;
		RAnalBaseType *bt = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		ut64 cur = 0;
		int count = 0;
		size_t q = p;
		// unique members, widest access per offset wins; a narrower overlapping access is dropped (no union-ish layouts)
		RVecSynthField uniq;
		RVecSynthField_init (&uniq);
		while (q < nfields && fields[q].arg == arg) {
			const ut64 foff = fields[q].off;
			const int fsize = fields[q].size;
			const bool fptr = fields[q].is_ptr;
			do {
				q++; // skip duplicate offsets (largest width sorts first)
			} while (q < nfields && fields[q].arg == arg && fields[q].off == foff);
			if (foff < cur) {
				continue; // overlaps the previous member
			}
			cur = foff + fsize;
			SynthField *u = RVecSynthField_emplace_back (&uniq);
			if (u) {
				*u = (SynthField){ .arg = arg, .off = foff, .size = fsize, .is_ptr = fptr };
			}
		}
		// emit members, collapsing constant-stride non-pointer runs into arrays
		RVecSynthArr arrs;
		RVecSynthArr_init (&arrs);
		const size_t un = RVecSynthField_length (&uniq);
		cur = 0;
		size_t u = 0;
		while (u < un) {
			SynthField *m = RVecSynthField_at (&uniq, u);
			size_t run = 1;
			if (!m->is_ptr) {
				while (u + run < un) {
					SynthField *nx = RVecSynthField_at (&uniq, u + run);
					if (nx->is_ptr || nx->size != m->size
						|| nx->off != m->off + (ut64)m->size * run) {
						break;
					}
					run++;
				}
			}
			if (run >= SYNTH_ARR_MIN) {
				SynthArr *a = RVecSynthArr_emplace_back (&arrs);
				if (a) {
					*a = (SynthArr){ .off = m->off, .elsize = m->size, .count = (int)run };
				}
				synth_add_member (bt, "field", m->off, m->size, (int)run, strdup (synth_type_for_size (m->size)));
				cur = m->off + (ut64)m->size * run;
				count++;
				u += run;
			} else {
				const char *cty = NULL;
				if (m->is_ptr) {
					SynthRec *rc = synth_rec_find (recs, arg, true, m->off);
					if (rc) {
						cty = rc->bt->name;
					}
				}
				char *ty = cty? r_str_newf ("struct %s *", cty)
					: strdup (m->is_ptr? "void *": synth_type_for_size (m->size));
				cur = synth_add_member (bt, "field", m->off, m->size, 0, ty);
				count++;
				u++;
			}
		}
		RVecSynthField_fini (&uniq);
		// a single big array is still a meaningful struct; a size-fn stated size upgrades even one field
		SynthRec *rec = NULL;
		const SynthWant *aw = &szctx.want[arg];
		const bool emit = count >= SYNTH_MIN_FIELDS || !RVecSynthArr_empty (&arrs)
			|| (count > 0 && aw->size > cur);
		const ut64 precur = cur;
		const int label = synth_arg_label (anal, cc, arg);
		if (emit) {
			cur = synth_pad_tail (bt, &arrs, cur, aw->size);
			bt->name = synth_root_name (fname, label);
			bt->size = cur * 8; // the base type holds bits
			rec = RVecSynthRec_emplace_back (recs);
		}
		if (rec) {
			*rec = (SynthRec){ .arg = arg, .argno = label, .bt = bt };
			synth_set_hint (rec, aw, cur > precur);
			RVecSynthSite_init (&rec->sites);
			rec->arrs = arrs;
		} else {
			RVecSynthArr_fini (&arrs);
			r_anal_base_type_free (bt);
		}
		p = q;
	}
	// remember the access sites per struct, for hints and command emission
	synth_collect_sites (recs, &vfields, false);
	synth_collect_sites (recs, &vporig, true);
	// returned objects bind to no argument; the sentinel store names the receiving var instead
	SynthRec *rrec;
	R_VEC_FOREACH (recs, rrec) {
		if (rrec->child || !SYNTH_IS_RET (rrec->arg)) {
			continue;
		}
		RAnalVar *rv = synth_ret_var (tps, fcn, sbase + (ut64)rrec->arg * SYNTH_WINDOW, spv, psz);
		if (rv && !synth_var_claimed (recs, rrec, rv->name)) {
			rrec->var = strdup (rv->name);
		}
	}
	if (apply) {
		// bookkeeping lives in the root sdb to keep it out of the type namespace
		Sdb *bookdb = anal->sdb;
		char *key = r_str_newf ("synth.%08" PFMT64x, fcn->addr);
		char *vkey = r_str_newf ("synth.vars.%08" PFMT64x, fcn->addr);
		synth_restore_vars (anal, fcn, bookdb, vkey);
		// re-runs and function renames would leave stale types behind otherwise
		char *stale = sdb_get (bookdb, key, 0);
		if (stale) {
			char *sp;
			sdb_aforeach (sp, stale) {
				if (!synth_type_referenced (anal, fcn, sp)) {
					r_anal_remove_parsed_type (anal, sp);
				}
				sdb_aforeach_next (sp);
			}
			free (stale);
			sdb_unset (bookdb, key, 0);
		}
		sdb_unset (bookdb, vkey, 0);
		if (!RVecSynthRec_empty (recs)) {
			RStrBuf sb;
			RStrBuf vsb;
			r_strbuf_init (&sb);
			r_strbuf_init (&vsb);
			SynthRec *rec;
			R_VEC_FOREACH (recs, rec) {
				r_anal_save_base_type (anal, rec->bt);
				r_strbuf_appendf (&sb, "%s%s", r_strbuf_length (&sb)? ",": "", rec->bt->name);
				if (!rec->child) {
					synth_bind_var (anal, fcn, cc, recs, rec, &vsb);
				}
			}
			sdb_set (bookdb, key, r_strbuf_get (&sb), 0);
			if (r_strbuf_length (&vsb)) {
				sdb_set (bookdb, vkey, r_strbuf_get (&vsb), 0);
			}
			r_strbuf_fini (&sb);
			r_strbuf_fini (&vsb);
			// annotate the accessing instructions so disasm renders member names
			R_VEC_FOREACH (recs, rec) {
				SynthSite *st;
				R_VEC_FOREACH (&rec->sites, st) {
					synth_hint (anal, rec, st->off, st->iaddr);
				}
			}
		}
		free (key);
		free (vkey);
	}
	free (fname);
	RVecSynthField_fini (&szctx.childwant);
	RVecSynthField_fini (&vfields);
	RVecSynthField_fini (&vporig);
	iob->fd_close (io, sfd);
	if (pfd >= 0) {
		iob->fd_close (io, pfd);
	}
	tps_fini (tps);
	if (own_recs) {
		RVecSynthRec_fini (recs);
	}
}

char *synth_json(RVecSynthRec *recs) {
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	pj_a (pj);
	SynthRec *rec;
	R_VEC_FOREACH (recs, rec) {
		pj_o (pj);
		pj_ks (pj, "name", rec->bt->name);
		const bool isret = SYNTH_IS_RET (rec->arg);
		pj_ki (pj, "arg", isret? -1: rec->argno);
		if (isret) {
			pj_ki (pj, "ret", SYNTH_RET_SLOT (rec->arg));
		}
		pj_kb (pj, "child", rec->child);
		if (rec->child) {
			pj_kn (pj, "offset", rec->off);
		}
		if (rec->var) {
			pj_ks (pj, "var", rec->var);
		}
		pj_kn (pj, "size", rec->bt->size / 8); // bytes, like the offsets
		if (rec->hint_fn) {
			// the size came from a size function, so scripts can match it against a known type
			pj_ko (pj, "sizehint");
			pj_kn (pj, "size", rec->hint_size);
			pj_ks (pj, "from", rec->hint_fn);
			pj_kn (pj, "at", rec->hint_site);
			pj_end (pj);
		}
		pj_ka (pj, "members");
		RAnalTypeMember *m;
		R_VEC_FOREACH (&rec->bt->struct_data.members, m) {
			pj_o (pj);
			pj_ks (pj, "name", m->name);
			pj_ks (pj, "type", m->type);
			pj_kn (pj, "offset", m->offset);
			pj_kn (pj, "size", (ut64)m->bitsize / 8);
			SynthArr *a = synth_arr_at (rec, m->offset);
			if (a) {
				pj_ki (pj, "count", a->count);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
	}
	pj_end (pj);
	return pj_drain (pj);
}

// the same synthesis serialized as r2 commands instead of being applied
char *synth_commands(RAnal *anal, RAnalFunction *fcn, RVecSynthRec *recs) {
	const char *cc = synth_fcn_cc (anal, fcn);
	RStrBuf *sb = r_strbuf_new ("");
	SynthRec *rec;
	R_VEC_FOREACH (recs, rec) {
		r_strbuf_appendf (sb, "'td struct %s {", rec->bt->name);
		ut64 cur = 0;
		RAnalTypeMember *m;
		R_VEC_FOREACH (&rec->bt->struct_data.members, m) {
			if (m->offset > cur) {
				// pad the gaps so the C layout keeps the observed offsets
				r_strbuf_appendf (sb, "uint8_t pad_0x%" PFMT64x "[%" PFMT64u "];", cur, m->offset - cur);
			}
			SynthArr *a = synth_arr_at (rec, m->offset);
			if (a) {
				r_strbuf_appendf (sb, "%s %s[%d];", m->type, m->name, a->count);
				cur = m->offset + (ut64)a->elsize * a->count;
			} else {
				r_strbuf_appendf (sb, "%s %s;", m->type, m->name);
				cur = m->offset + m->bitsize / 8;
			}
		}
		r_strbuf_append (sb, "};\n");
	}
	R_VEC_FOREACH (recs, rec) {
		if (rec->child) {
			continue;
		}
		RAnalVar *av = synth_bound_var (anal, fcn, cc, recs, rec);
		if (!av) {
			continue;
		}
		if (av->kind == R_ANAL_VAR_KIND_REG) {
			RRegItem *ri = r_reg_index_get (anal->reg, av->delta);
			if (ri) {
				r_strbuf_appendf (sb, "'afvr %s %s struct %s *\n", ri->name, av->name, rec->bt->name);
			}
		} else {
			const st64 delta = r_anal_var_frame_delta (anal, fcn, av->kind, av->delta);
			r_strbuf_appendf (sb, "'afv%c %"PFMT64d" %s struct %s *\n", av->kind, delta, av->name, rec->bt->name);
		}
	}
	R_VEC_FOREACH (recs, rec) {
		SynthSite *st;
		R_VEC_FOREACH (&rec->sites, st) {
			// aht cannot address inside an atomic array, so only the base element is emitted (the applied path hints all)
			SynthArr *a = synth_arr_at (rec, st->off);
			if (a && st->off != a->off) {
				continue;
			}
			if (st->off > 0) {
				r_strbuf_appendf (sb, "'@0x%08" PFMT64x "'aht %s.field_0x%" PFMT64x "\n",
					st->iaddr, rec->bt->name, st->off);
			} else {
				r_strbuf_appendf (sb, "'@0x%08" PFMT64x "'Ct %s.field_0x0\n", st->iaddr, rec->bt->name);
			}
		}
	}
	char *res = r_strbuf_drain (sb);
	r_str_trim_tail (res);
	return res;
}

// true when type matching left an argument with a plain non-pointer type
bool synth_args_untyped(RAnalFunction *fcn) {
	RAnalVar **vp;
	R_VEC_FOREACH (&fcn->vars, vp) {
		RAnalVar *v = *vp;
		if (v->isarg && v->type && !strchr (v->type, '*') && !r_str_startswith (v->type, "struct")) {
			return true;
		}
	}
	return false;
}
