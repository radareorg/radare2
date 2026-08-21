/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: cfg order, block state restore and the esil emulation loop */

#include "tp.h"

static void tp_var_fact_kv_free(HtUPKv *kv) {
	TPVarFact *fact = kv->value;
	if (fact) {
		free (fact->type);
		free (fact);
	}
}

static void tp_reach_kv_free(HtUPKv *kv) {
	set_u_free (kv->value);
}

static void tp_mem_type_kv_free(HtUPKv *kv) {
	free (kv->value);
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr? 1: (a->addr < b->addr? -1: 0);
}

typedef struct {
	HtUP *blocks;
	HtUU *seen;
	RVecUT64 postorder;
} RpoCtx;

static bool rpo_visit(RAnalBlock *bb, void *user) {
	return true;
}

static bool rpo_collect(RAnalBlock *bb, void *user) {
	RpoCtx *ctx = user;
	if (ht_up_find (ctx->blocks, bb->addr, NULL)) {
		ht_uu_update (ctx->seen, bb->addr, 1);
		RVecUT64_push_back (&ctx->postorder, &bb->addr);
	}
	return true;
}

// reverse post-order via r_anal_block_recurse_depth_first's on_exit callback; returns the entry-reachable prefix length, 0 on failure
static size_t bblist_from_cfg(RAnalFunction *fcn, RVecUT64 *bblist) {
	RAnalBlock *bb;
	RAnalBlock *entry = NULL;
	RListIter *it;
	RpoCtx ctx = { ht_up_new0 (), ht_uu_new0 () };
	RVecUT64_init (&ctx.postorder);
	if (!ctx.blocks || !ctx.seen) {
		ht_up_free (ctx.blocks);
		ht_uu_free (ctx.seen);
		return 0;
	}
	r_list_foreach (fcn->bbs, it, bb) {
		ht_up_insert (ctx.blocks, bb->addr, bb);
		if (!entry && r_anal_block_contains (bb, fcn->addr)) {
			entry = bb;
		}
	}
	if (!entry) {
		ht_up_free (ctx.blocks);
		ht_uu_free (ctx.seen);
		return 0;
	}
	r_anal_block_recurse_depth_first (entry, rpo_visit, rpo_collect, &ctx);
	ht_up_free (ctx.blocks);
	const size_t reachable = RVecUT64_length (&ctx.postorder);
	ut64 *pa;
	R_VEC_FOREACH_PREV (&ctx.postorder, pa) {
		RVecUT64_push_back (bblist, pa);
	}
	RVecUT64_fini (&ctx.postorder);
	// blocks unreachable from the entry still get emulated, in address order
	r_list_foreach (fcn->bbs, it, bb) {
		bool found = false;
		ht_uu_find (ctx.seen, bb->addr, &found);
		if (!found) {
			RVecUT64_push_back (bblist, &bb->addr);
		}
	}
	ht_uu_free (ctx.seen);
	if (!reachable || RVecUT64_length (bblist) != r_list_length (fcn->bbs)) {
		RVecUT64_clear (bblist);
		return 0;
	}
	return reachable;
}

void tps_fini(TPState *tps) {
	R_RETURN_IF_FAIL (tps);
	r_list_free (tps->clobber);
	free (tps->seed_reg);
	RVecTPSizeFn_fini (&tps->sizefns);
	ht_up_free (tps->var_facts);
	ht_up_free (tps->reach_cache);
	ht_up_free (tps->mem_types);
	tp_flush_pending_const (tps);
	RVecTPPendingConst_fini (&tps->pending_const);
	type_trace_fini (&tps->tt, &tps->esil);
	r_esil_fini (&tps->esil);
	if (tps->anal->iob.fd_close) {
		tps->anal->iob.fd_close (tps->anal->iob.io, tps->stack_fd);
	}
	if (tps->anal->coreb.cmd) {
		if (tps->old_follow) {
			tps->anal->coreb.cmd (tps->anal->coreb.core, "e dbg.follow=true");
		} else {
			tps->anal->coreb.cmd (tps->anal->coreb.core, "e dbg.follow=false");
		}
	}
	// r_config_hold_restore (tps->hc);
	// r_config_hold_free (tps->hc);
	free (tps);
}

static bool tt_is_reg(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

static bool tt_reg_read(void *reg, const char *name, ut64 *val) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	if (val) {
		*val = r_reg_get_value ((RReg *)reg, ri);
	}
	r_unref (ri);
	return true;
}

static ut32 tt_reg_size(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return 0;
	}
	ut32 size = ri->size;
	r_unref (ri);
	return size;
}

static ut32 tt_reg_packed_size(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return 0;
	}
	const ut32 psize = ri->packed_size > 0 ? (ut32)ri->packed_size : 0;
	r_unref (ri);
	return psize;
}

static bool tt_reg_alias(void *reg, int alias, const char *name) {
	return r_reg_alias_setname ((RReg *)reg, alias, name);
}

static bool tt_mem_read(void *mem, ut64 addr, ut8 *buf, int len) {
	TPState *tps = (TPState *)mem;
	if (tps->anal->iob.read_at) {
		return tps->anal->iob.read_at (tps->anal->iob.io, addr, buf, len);
	}
	return false;
}

// ensures type trace esil engine only writes to it's designated stack map.
// writes outside of that itv will be assumed as valid and return true.
// this function assumes, that stack map has highest priority,
// or does not overlap with any other map.
static bool tt_mem_write(void *mem, ut64 addr, const ut8 *buf, int len) {
	TPState *tps = (TPState *)mem;
	RIOMap *map = tps->anal->iob.map_get? tps->anal->iob.map_get (tps->anal->iob.io, tps->stack_map): NULL;
	if (!map) {
		R_LOG_WARN ("stack map unavailable for type propagation writes");
		return false;
	}
	RInterval itv = { addr, len };
	if (!r_itv_overlap (map->itv, itv)) {
		return true;
	}
	itv = r_itv_intersect (map->itv, itv);
	if (tps->anal->iob.write_at) {
		return tps->anal->iob.write_at (tps->anal->iob.io, itv.addr, &buf[itv.addr - addr], (int)itv.size);
	}
	return false;
}

static bool tt_esil_reg_write(REsil *esil, const char *name, ut64 val) {
	TPState *tps = esil->user;
	if (!tps || !tps->reg_if.reg_read || !tps->reg_if.reg_write) {
		return false;
	}
	ut64 old = 0;
	if (!tps->reg_if.reg_read (tps->reg_if.reg, name, &old)) {
		return false;
	}
	if (!tps->reg_if.reg_write (tps->reg_if.reg, name, val)) {
		return false;
	}
	type_trace_voyeur_reg_write (&tps->tt, name, old, val);
	return true;
}

static bool tt_esil_reg_read(REsil *esil, const char *name, ut64 *val, int *size) {
	TPState *tps = esil->user;
	if (!tps || !tps->reg_if.reg_read) {
		return false;
	}
	ut64 tmp = 0;
	ut64 *out = val? val: &tmp;
	if (!tps->reg_if.reg_read (tps->reg_if.reg, name, out)) {
		return false;
	}
	if (size) {
		ut32 rsz = tps->reg_if.reg_size
			? tps->reg_if.reg_size (tps->reg_if.reg, name)
			: 0;
		*size = rsz? (int)rsz: 64;
	}
	type_trace_voyeur_reg_read (&tps->tt, name, *out);
	return true;
}

static bool tt_esil_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	TPState *tps = esil->user;
	if (!tps || !tps->mem_if.mem_read) {
		return false;
	}
	if (!tps->mem_if.mem_read (tps->mem_if.mem, addr, buf, len)) {
		return false;
	}
	type_trace_voyeur_mem_read (&tps->tt, addr, buf, len);
	return true;
}

static bool tt_esil_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	TPState *tps = esil->user;
	if (!tps || !tps->mem_if.mem_read || !tps->mem_if.mem_write) {
		return false;
	}
	ut8 *old = NULL;
	if (tps->tt.enable_rollback) {
		old = malloc (len);
		if (!old) {
			return false;
		}
		if (!tps->mem_if.mem_read (tps->mem_if.mem, addr, old, len)) {
			memset (old, 0xff, len);
		}
	}
	bool ret = tps->mem_if.mem_write (tps->mem_if.mem, addr, buf, len);
	if (ret) {
		type_trace_voyeur_mem_write (&tps->tt, addr, old, buf, len);
	}
	free (old);
	return ret;
}

// back a located address range with an anonymous malloc:// map; returns the fd or -1
int tp_map_anon(RAnal *anal, ut64 size, int align, ut64 *base, ut32 *map_id) {
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	if (iob->map_locate && !iob->map_locate (io, base, size, align)) {
		return -1;
	}
	char *uri = r_str_newf ("malloc://0x%" PFMT64x, size);
	const int fd = (uri && iob->fd_open)? iob->fd_open (io, uri, R_PERM_RW, 0): -1;
	free (uri);
	if (fd < 0) {
		return -1;
	}
	RIOMap *map = iob->map_add? iob->map_add (io, fd, R_PERM_RW, 0, *base, size): NULL;
	if (!map) {
		if (iob->fd_close) {
			iob->fd_close (io, fd);
		}
		return -1;
	}
	if (map_id) {
		*map_id = map->id;
	}
	return fd;
}

TPState *tps_init(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io && anal->esil, NULL);
	RIO *io = anal->iob.io;
	TPState *tps = R_NEW0 (TPState);
	tps->anal = anal;
	RVecTPPendingConst_init (&tps->pending_const);
	RVecTPSizeFn_init (&tps->sizefns);
	tps->var_facts = ht_up_new (NULL, tp_var_fact_kv_free, NULL);
	tps->reach_cache = ht_up_new (NULL, tp_reach_kv_free, NULL);
	tps->mem_types = ht_up_new (NULL, tp_mem_type_kv_free, NULL);
	int align = r_arch_info (anal->arch, R_ARCH_INFO_DATA_ALIGN);
	align = R_MAX (r_arch_info (anal->arch, R_ARCH_INFO_CODE_ALIGN), align);
	align = R_MAX (align, 1);
	tps->stack_base = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.addr"): 0x100000;
	ut64 stack_size = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.size"): 0xf0000;
	tps->stack_size = stack_size;
	// ideally this all would happen in a dedicated temporal io bank
	tps->stack_fd = tp_map_anon (anal, stack_size, align, &tps->stack_base, &tps->stack_map);
	if (tps->stack_fd < 0) {
		free (tps);
		return NULL;
	}
	// XXX: r_reg_clone should be invoked in type_trace_init
	RReg *reg = r_reg_clone (anal->reg);
	if (!reg) {
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->reg_if.reg = reg;
	tps->reg_if.is_reg = tt_is_reg;
	tps->reg_if.reg_read = tt_reg_read;
	tps->reg_if.reg_write = (REsilRegWrite)r_reg_setv;
	tps->reg_if.reg_alias = tt_reg_alias;
	tps->reg_if.reg_size = tt_reg_size;
	tps->reg_if.reg_packed_size = tt_reg_packed_size;
	tps->mem_if.mem = tps;
	tps->mem_if.mem_read = tt_mem_read;
	tps->mem_if.mem_write = tt_mem_write;
	ut64 sp = tps->stack_base + stack_size - (stack_size % align) - align * 8;
	// todo: this probably needs some boundary checks
	r_reg_setv (reg, "SP", sp);
	r_reg_setv (reg, "BP", sp);
	REsilOptions esil_opt = r_esil_options (NULL, NULL);
	// VM address width, not the decode width (config->bits is 16 on thumb); SP-reg width is the library-mode fallback
	ut64 aw = 64;
	if (anal->coreb.cfgGetI) {
		aw = anal->coreb.cfgGetI (anal->coreb.core, "esil.addr.size");
	} else {
		RRegItem *spri = r_reg_get (reg, "SP", -1);
		if (spri) {
			aw = spri->size? spri->size: aw;
			r_unref (spri);
		}
	}
	esil_opt.addrsize = aw;
	esil_opt.ifaces.reg = tps->reg_if;
	esil_opt.ifaces.mem = tps->mem_if;
	if (!r_esil_init (&tps->esil, &esil_opt)) {
		r_reg_free (reg);
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->esil.user = tps;
	tps->esil.cb.reg_read = tt_esil_reg_read;
	tps->esil.cb.reg_write = tt_esil_reg_write;
	tps->esil.cb.mem_read = tt_esil_mem_read;
	tps->esil.cb.mem_write = tt_esil_mem_write;

	if (!type_trace_init (&tps->tt, &tps->esil, reg)) {
		r_esil_fini (&tps->esil);
		r_reg_free (reg);
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->esil.anal = anal;
	// Config hold requires RConfig which we get through coreb.core
	void *core = anal->coreb.core;
	if (core && anal->coreb.cfgGet && anal->coreb.cfgGetB) {
		const char *spec = anal->coreb.cfgGet (core, "types.spec");
		tps->cfg_spec = spec? spec: "gcc";
		tps->cfg_breakoninvalid = anal->coreb.cfgGetB (core, "esil.breakoninvalid");
		tps->cfg_chk_constraint = anal->coreb.cfgGetB (core, "types.constraint");
		tps->cfg_fields = anal->coreb.cfgGetB (core, "types.fields");
		tps->cfg_rollback = anal->coreb.cfgGetB (core, "types.rollback");
		tps->cfg_bbstate = anal->coreb.cfgGetB (core, "types.bbstate");
		if (anal->coreb.cfgGetB (core, "types.sizes")) {
			tp_sizefns_init (&tps->sizefns, anal->coreb.cfgGet (core, "types.sizefns"));
		}
		if (anal->coreb.cfgGetI && anal->coreb.cmd) {
			tps->old_follow = anal->coreb.cfgGetI (core, "dbg.follow");
			anal->coreb.cmd (core, "e dbg.follow=0");
		}
	} else {
		tps->cfg_spec = "gcc";
		tps->cfg_breakoninvalid = false;
		tps->cfg_chk_constraint = false;
		tps->cfg_fields = false;
		tps->cfg_rollback = false;
		tps->cfg_bbstate = true;
	}
	tps->tt.enable_rollback = tps->cfg_rollback;
	tps->tt.be = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	return tps;
}

// how far back in emulation order a real predecessor is looked for before giving up
#define TP_PRED_SCAN_MAX 64

static void tp_bbstate_kv_free(HtUPKv *kv) {
	free (kv->value);
}

static bool tp_bb_edge_cb(ut64 addr, void *user) {
	return addr != *(ut64 *)user;
}

static bool tp_bb_leads_to(RAnal *anal, ut64 from, ut64 to) {
	RAnalBlock *bb = r_anal_get_block_at (anal, from);
	return bb && !r_anal_block_successor_addrs_foreach (bb, tp_bb_edge_cb, &to);
}

typedef struct {
	SetU *members; // loop blocks, header included
	RVecUT64 srcs; // back-edge sources
	size_t acc_start; // trace access range recorded while the header block was emulated
	size_t acc_end;
	bool has_call; // a call in the header writes registers the trace cannot see
} TPLoopHdr;

static void tp_loophdr_kv_free(HtUPKv *kv) {
	TPLoopHdr *hdr = kv->value;
	set_u_free (hdr->members);
	RVecUT64_fini (&hdr->srcs);
	free (hdr);
}

static void tp_u64vec_kv_free(HtUPKv *kv) {
	RVecUT64_free (kv->value);
}

typedef struct {
	HtUU *order;
	HtUP *headers;
	HtUP *preds;
	ut64 pos;
	ut64 src;
	bool oom; // a partial loop map must not drive restore decisions
} TPBackEdgeScan;

// push_back cannot report failure, so emplace and check the slot
static bool tp_vec_push(RVecUT64 *vec, ut64 addr) {
	ut64 *slot = RVecUT64_emplace_back (vec);
	if (slot) {
		*slot = addr;
	}
	return slot != NULL;
}

static bool tp_backedge_cb(ut64 addr, void *user) {
	TPBackEdgeScan *bs = user;
	bool found = false;
	const ut64 tpos = ht_uu_find (bs->order, addr, &found);
	if (!found || tpos > bs->pos) {
		return true;
	}
	TPLoopHdr *hdr = ht_up_find (bs->headers, addr, NULL);
	if (!hdr) {
		hdr = R_NEW0 (TPLoopHdr);
		if (!ht_up_insert (bs->headers, addr, hdr)) {
			free (hdr);
			bs->oom = true;
			return false;
		}
	}
	if (!tp_vec_push (&hdr->srcs, bs->src)) {
		bs->oom = true;
		return false;
	}
	return true;
}

static bool tp_pred_cb(ut64 addr, void *user) {
	TPBackEdgeScan *bs = user;
	bool found = false;
	ht_uu_find (bs->order, addr, &found);
	if (!found) {
		return true;
	}
	RVecUT64 *pv = ht_up_find (bs->preds, addr, NULL);
	if (!pv) {
		pv = RVecUT64_new ();
		if (!pv || !ht_up_insert (bs->preds, addr, pv)) {
			RVecUT64_free (pv);
			bs->oom = true;
			return false;
		}
	}
	if (!tp_vec_push (pv, bs->src)) {
		bs->oom = true;
		return false;
	}
	return true;
}

// grow the loop's member set backward from its back-edge sources, never crossing the header
static bool tp_loop_members_cb(void *user, const ut64 ha, const void *v) {
	TPBackEdgeScan *bs = user;
	TPLoopHdr *hdr = (TPLoopHdr *)v;
	bool found = false;
	const ut64 hpos = ht_uu_find (bs->order, ha, &found);
	hdr->members = found? set_u_new (): NULL;
	if (!hdr->members) {
		return true;
	}
	set_u_add (hdr->members, ha);
	// set_u_add cannot report failure; an unnoticed missing member would misapply the partial restore
	bool ok = set_u_contains (hdr->members, ha);
	RVecUT64 stack;
	RVecUT64_init (&stack);
	ut64 *pa;
	R_VEC_FOREACH (&hdr->srcs, pa) {
		ok &= tp_vec_push (&stack, *pa);
	}
	while (ok && !RVecUT64_empty (&stack)) {
		const ut64 cur = *RVecUT64_last (&stack);
		RVecUT64_pop_back (&stack);
		if (set_u_contains (hdr->members, cur)) {
			continue;
		}
		const ut64 cpos = ht_uu_find (bs->order, cur, &found);
		// a block before the header in rpo means irreducible flow, not a natural loop
		if (!found || cpos < hpos) {
			ok = false;
			break;
		}
		set_u_add (hdr->members, cur);
		ok &= set_u_contains (hdr->members, cur);
		RVecUT64 *pv = ht_up_find (bs->preds, cur, NULL);
		if (pv) {
			R_VEC_FOREACH (pv, pa) {
				ok &= tp_vec_push (&stack, *pa);
			}
		}
	}
	RVecUT64_fini (&stack);
	if (!ok) {
		// a NULL member set falls back to the full snapshot restore
		set_u_free (hdr->members);
		hdr->members = NULL;
	}
	return true;
}

static void tp_scan_edges(RAnal *anal, RVecUT64 *bblist, size_t reachable, RAnalAddrCb cb, TPBackEdgeScan *bs) {
	size_t i;
	for (i = 0; i < reachable && !bs->oom; i++) {
		bs->pos = i;
		bs->src = *RVecUT64_at (bblist, i);
		RAnalBlock *bb = r_anal_get_block_at (anal, bs->src);
		if (bb) {
			r_anal_block_successor_addrs_foreach (bb, cb, bs);
		}
	}
}

// mark emulation-order back-edge targets in the entry-reachable prefix and precompute each loop's member set
static HtUP *tp_loop_headers(RAnal *anal, RVecUT64 *bblist, size_t reachable) {
	if (!reachable) {
		return NULL;
	}
	HtUP *ret = NULL;
	TPBackEdgeScan bs = { ht_uu_new0 (), ht_up_new (NULL, tp_loophdr_kv_free, NULL), NULL };
	if (bs.order && bs.headers) {
		size_t i;
		for (i = 0; i < reachable; i++) {
			ht_uu_insert (bs.order, *RVecUT64_at (bblist, i), i);
		}
		tp_scan_edges (anal, bblist, reachable, tp_backedge_cb, &bs);
		// most functions have no loops: build the preds table only once a header exists
		if (!bs.oom && bs.headers->count) {
			bs.preds = ht_up_new (NULL, tp_u64vec_kv_free, NULL);
			if (bs.preds) {
				tp_scan_edges (anal, bblist, reachable, tp_pred_cb, &bs);
				if (!bs.oom) {
					ht_up_foreach (bs.headers, tp_loop_members_cb, &bs);
					ret = bs.headers;
				}
			}
		}
	}
	ht_uu_free (bs.order);
	ht_up_free (bs.preds);
	if (!ret) {
		ht_up_free (bs.headers);
	}
	return ret;
}

// restore only the registers the header block itself wrote; for the rest the live loop-body state is fresher than its snapshot
static void tp_restore_block_writes(TypeTrace *tt, TPLoopHdr *hdr, const ut8 *snap, int size) {
	RRegSet *rs = r_reg_regset_get (tt->reg, R_REG_TYPE_GPR);
	if (!rs || !rs->arena) {
		return;
	}
	r_reg_arena_materialize (rs->arena);
	ut8 *live = rs->arena->bytes;
	if (!live) {
		return;
	}
	const int n = R_MIN (rs->arena->size, size);
	size_t i;
	// walk the trace accesses instead of diffing snapshot bytes: a header rewriting the value a register already had must still override the loop body
	for (i = hdr->acc_start; i < hdr->acc_end; i++) {
		TypeTraceAccess *access = VecAccess_at (&tt->db.accesses, i);
		if (!access->is_reg || !access->is_write) {
			continue;
		}
		RRegItem *item = r_reg_get (tt->reg, access->reg.name, -1);
		if (!item) {
			continue;
		}
		if (item->arena == R_REG_TYPE_GPR && item->offset >= 0 && item->size > 0) {
			// copy whole containing bytes: some profiles keep lone bit registers in the gpr arena (ppc ca)
			const int off = item->offset / 8;
			const int sz = BITS2BYTES (item->offset + item->size) - off;
			if (off + sz <= n) {
				memcpy (live + off, snap + off, sz);
			}
		}
		r_unref (item);
	}
}

// memory is never rewound, so the stack keeps sibling branch writes
static bool tp_restore_pred_state(TPState *tps, RVecUT64 *bblist, int j, ut64 bbat, HtUP *bbstate, HtUP *loop_headers, int arena_size) {
	if (j < 1) {
		return false;
	}
	RAnal *anal = tps->anal;
	const ut64 prev = *RVecUT64_at (bblist, j - 1);
	// straight line: the live state is already this block's lineage
	if (tp_bb_leads_to (anal, prev, bbat)) {
		return false;
	}
	const int oldest = R_MAX (0, j - TP_PRED_SCAN_MAX);
	int k;
	for (k = j - 2; k >= oldest; k--) {
		const ut64 pa = *RVecUT64_at (bblist, k);
		if (!tp_bb_leads_to (anal, pa, bbat)) {
			continue;
		}
		ut8 *snap = ht_up_find (bbstate, pa, NULL);
		if (snap) {
			TPLoopHdr *hdr = ht_up_find (loop_headers, pa, NULL);
			// partial restore only at a loop exit fed by the loop's own live state; a call in the header has untraced effects
			if (hdr && !hdr->has_call && hdr->members && !set_u_contains (hdr->members, bbat) && set_u_contains (hdr->members, prev)) {
				tp_restore_block_writes (&tps->tt, hdr, snap, arena_size);
			} else {
				r_reg_arena_poke (tps->tt.reg, snap, arena_size);
			}
			return true;
		}
		// a predecessor without a snapshot (arena peek failed) is no reason to stop: an older one may have state
	}
	return false;
}

// step the type-trace esil over the linear ops of every block; op_cb also enables the one-op lookahead
TPEmuResult tp_emulate_linear(TPState *tps, RAnalFunction *fcn, int max_ops, TPEmulateOpCb op_cb, void *user, bool lookahead, bool restore_state) {
	RAnal *anal = tps->anal;
	const int op_tions = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_ESIL;
	const int minopcode = R_MAX (1, r_arch_info (anal->arch, R_ARCH_INFO_MINOP_SIZE));
	RAnalOp aop = { 0 };
	int ret, total = 0;
	TPEmuResult res = TP_EMU_DONE;
	RAnalOp *next_op = R_NEW0 (RAnalOp);
	RCons *cons = r_cons_singleton ();
	r_cons_break_push (cons, NULL, NULL);
	RVecBuf buf;
	RVecBuf_init (&buf);
	RVecUT64 bblist;
	RVecUT64_init (&bblist);
	r_list_sort (fcn->bbs, bb_cmpaddr);
	size_t bblist_size = r_list_length (fcn->bbs); // TODO: Use ut64
	RVecUT64_reserve (&bblist, bblist_size);
	RAnalBlock *bb;
	RListIter *it;
	const size_t reachable = bblist_from_cfg (fcn, &bblist);
	if (!reachable) {
		R_LOG_DEBUG ("cannot compute cfg order at 0x%08" PFMT64x ", using address order", fcn->addr);
		r_list_foreach (fcn->bbs, it, bb) {
			RVecUT64_push_back (&bblist, &bb->addr);
		}
	}
	int i, j;
	TypeTrace *etrace = &tps->tt;
	RIO *io = anal->iob.io;
	HtUP *bbstate = (restore_state && tps->cfg_bbstate)? ht_up_new (NULL, tp_bbstate_kv_free, NULL): NULL;
	HtUP *loop_headers = bbstate? tp_loop_headers (anal, &bblist, reachable): NULL;
	int arena_size = 0;
	for (j = 0; j < bblist_size; j++) {
		const ut64 bbat = *RVecUT64_at (&bblist, j);
		tps->lineage_reset = bbstate && tp_restore_pred_state (tps, &bblist, j, bbat, bbstate, loop_headers, arena_size);
		TPLoopHdr *cur_hdr = ht_up_find (loop_headers, bbat, NULL);
		if (cur_hdr) {
			cur_hdr->acc_start = VecAccess_length (&etrace->db.accesses);
		}
		bb = r_anal_get_block_at (anal, bbat);
		if (!bb) {
			R_LOG_WARN ("basic block at 0x%08" PFMT64x " was removed during analysis", bbat);
			res = TP_EMU_RETRY;
			goto beach;
		}
		ut64 bb_addr = bb->addr;
		ut64 bb_size = bb->size;
		const ut64 buf_size = bb->size + 32;
		if (!RVecBuf_reserve (&buf, buf_size)) {
			break;
		}
		ut8 *buf_ptr = R_VEC_START_ITER (&buf);
		if (!anal->iob.read_at || anal->iob.read_at (io, bb_addr, buf_ptr, bb_size) < 1) {
			break;
		}
		ut64 addr = bb_addr;
		bool have_cached_op = false;
		for (i = 0; i < bb_size;) {
			if (r_cons_is_breaked (cons)) {
				res = TP_EMU_BREAK;
				goto beach;
			}
			if (max_ops && ++total > max_ops) {
				res = TP_EMU_BUDGET;
				goto beach;
			}
			ut64 bb_left = bb_size - i;
			if ((addr >= bb_addr + bb_size) || (addr < bb_addr)) {
				// stop emulating this bb if pc is outside the basic block boundaries
				break;
			}
			if (have_cached_op) {
				// Reuse next_op from previous iteration instead of re-parsing
				aop = *next_op;
				memset (next_op, 0, sizeof (RAnalOp));
				ret = aop.size;
				have_cached_op = false;
			} else {
				ret = r_anal_op (anal, &aop, addr, buf_ptr + i, bb_left, op_tions);
				if (ret <= 0) {
					i += minopcode;
					addr += minopcode;
					r_anal_op_fini (&aop);
					continue;
				}
			}
			if (type_trace_loopcount (etrace, addr) > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				r_anal_op_fini (&aop);
				break;
			}
			type_trace_loopcount_increment (etrace, addr);
			r_reg_setv (etrace->reg, "PC", addr + aop.size);
			if (!r_anal_op_nonlinear (aop.type)) { // skip jmp/cjmp/trap/ret/call ops
				if (aop.type == R_ANAL_OP_TYPE_ILL || aop.type == R_ANAL_OP_TYPE_UNK) {
					if (tps->cfg_breakoninvalid) {
						R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
						r_anal_op_fini (&aop);
						res = TP_EMU_FAIL;
						goto beach;
					}
					goto skip_trace;
				}
				if (!type_trace_op (etrace, &tps->esil, &aop) && tps->cfg_breakoninvalid) {
					R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
					r_anal_op_fini (&aop);
					res = TP_EMU_RETRY;
					goto beach;
				}
			}
		skip_trace:
			if (op_cb) {
				// Parse next_op with full options so it can be reused as aop next iteration
				if (lookahead && i + aop.size < bb_size) {
					int left = bb_left - ret;
					if (left < 1) {
						r_anal_op_fini (&aop);
						break;
					}
					if (r_anal_op (anal, next_op, addr + ret, buf_ptr + i + ret, left, op_tions) < 1) {
						r_anal_op_fini (&aop);
						r_anal_op_fini (next_op);
						break;
					}
					have_cached_op = true;
				}
				op_cb (user, &aop, lookahead? next_op: NULL, addr, bb_addr);
			}
			if (tp_op_call_base (aop.type)) {
				if (cur_hdr) {
					cur_hdr->has_call = true;
				}
				if (tps->clobber) {
					// drop caller-saved sentinels after op_cb so a size-fn harvest still sees the live arg regs
					RListIter *cit;
					const char *rn;
					r_list_foreach (tps->clobber, cit, rn) {
						r_reg_setv (etrace->reg, rn, 0);
					}
				}
				if (tps->seed_reg) {
					r_reg_setv (etrace->reg, tps->seed_reg, tps->seed_val);
					R_FREE (tps->seed_reg);
				}
			}
			i += ret;
			addr += ret;
			r_anal_op_fini (&aop);
		}
		// Clean up any cached op that wasn't used (e.g., at end of BB)
		if (have_cached_op) {
			r_anal_op_fini (next_op);
		}
		if (cur_hdr) {
			cur_hdr->acc_end = VecAccess_length (&etrace->db.accesses);
		}
		if (tps->cfg_rollback) {
			type_trace_rollback_clear (etrace);
		}
		if (bbstate) {
			ut8 *snap = r_reg_arena_peek (etrace->reg, &arena_size);
			if (snap) {
				if (!ht_up_update (bbstate, bb_addr, snap)) {
					free (snap);
				}
			}
		}
	}
beach:
	ht_up_free (loop_headers);
	ht_up_free (bbstate);
	r_anal_op_fini (&aop);
	r_anal_op_free (next_op); // a cached lookahead op may still be live on a break/budget exit
	r_cons_break_pop (cons);
	RVecBuf_fini (&buf);
	RVecUT64_fini (&bblist);
	return res;
}
