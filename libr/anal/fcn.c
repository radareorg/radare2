/* radare - LGPL - Copyright 2010-2019 - nibble, alvaro, pancake */

#include <r_anal.h>
#include <r_parse.h>
#include <r_util.h>
#include <r_list.h>

extern int try_walkthrough_jmptbl(RAnal *anal, RAnalFunction *fcn, int depth, ut64 ip, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, int jmptbl_size, ut64 default_case, int ret0);
extern bool try_get_delta_jmptbl_info(RAnal *anal, RAnalFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case);
#define USE_SDB_CACHE 0
#define READ_AHEAD 1
#define SDB_KEY_BB "bb.0x%"PFMT64x ".0x%"PFMT64x
// XXX must be configurable by the user
#define JMPTBLSZ 512
#define JMPTBL_LEA_SEARCH_SZ 64
#define JMPTBL_MAXFCNSIZE 4096
#define BB_ALIGN 0x10

/* speedup analysis by removing some function overlapping checks */
#define JAYRO_04 1

// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

#define FIX_JMP_FWD 0
#define JMP_IS_EOB 1
#define JMP_IS_EOB_RANGE 64

// 64KB max size
// 256KB max function size
#define MAX_FCN_SIZE (1024 * 256)

#define DB a->sdb_fcns
#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);

#define FCN_CONTAINER(x) container_of ((RBNode*)(x), RAnalFunction, rb)
#define ADDR_FCN_CONTAINER(x) container_of ((RBNode*)(x), RAnalFunction, addr_rb)
#define fcn_tree_foreach_intersect(root, it, data, from, to)										\
	for ((it) = _fcn_tree_iter_first (root, from, to); (it).cur && ((data) = FCN_CONTAINER ((it).cur), 1); _fcn_tree_iter_next (&(it), from, to))

typedef struct fcn_tree_iter_t {
	int len;
	RBNode *cur;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
} FcnTreeIter;

#if USE_SDB_CACHE
static Sdb *HB = NULL;
#endif

R_API const char *r_anal_fcn_type_tostring(int type) {
	switch (type) {
	case R_ANAL_FCN_TYPE_NULL: return "null";
	case R_ANAL_FCN_TYPE_FCN: return "fcn";
	case R_ANAL_FCN_TYPE_LOC: return "loc";
	case R_ANAL_FCN_TYPE_SYM: return "sym";
	case R_ANAL_FCN_TYPE_IMP: return "imp";
	case R_ANAL_FCN_TYPE_INT: return "int"; // interrupt
	case R_ANAL_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

#if READ_AHEAD
static ut64 cache_addr = UT64_MAX;

// TODO: move into io :?
static int read_ahead(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	static ut8 cache[1024];
	const int cache_len = sizeof (cache);

	if (len < 1) {
		return 0;
	}
	if (len > cache_len) {
		int a = anal->iob.read_at (anal->iob.io, addr, buf, len); // double read
		memcpy (cache, buf, cache_len);
		cache_addr = addr;
		return a;
	}

	ut64 addr_end = UT64_ADD_OVFCHK (addr, len)? UT64_MAX: addr + len;
	ut64 cache_addr_end = UT64_ADD_OVFCHK (cache_addr, cache_len)? UT64_MAX: cache_addr + cache_len;
	bool isCached = ((addr != UT64_MAX) && (addr >= cache_addr) && (addr_end < cache_addr_end));
	if (isCached) {
		memcpy (buf, cache + (addr - cache_addr), len);
	} else {
		anal->iob.read_at (anal->iob.io, addr, cache, sizeof (cache));
		memcpy (buf, cache, len);
		cache_addr = addr;
	}
	return len;
}
#else
static int read_ahead(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	return anal->iob.read_at (anal->iob.io, addr, buf, len);
}
#endif

R_API void r_anal_fcn_invalidate_read_ahead_cache() {
#if READ_AHEAD
	cache_addr = UT64_MAX;
#endif
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return (a->addr - b->addr);
}

R_API void r_anal_fcn_update_tinyrange_bbs(RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	r_list_sort (fcn->bbs, &cmpaddr);
	r_tinyrange_fini (&fcn->bbr);
	r_list_foreach (fcn->bbs, iter, bb) {
		r_tinyrange_add (&fcn->bbr, bb->addr, bb->addr + bb->size);
	}
}

static void set_meta_min_if_needed(RAnalFunction *x) {
	if (x->meta.min == UT64_MAX) {
		ut64 min = UT64_MAX;
		ut64 max = UT64_MIN;
		RListIter *bbs_iter;
		RAnalBlock *bbi;
		r_list_foreach (x->bbs, bbs_iter, bbi) {
			if (min > bbi->addr) {
				min = bbi->addr;
			}
			if (max < bbi->addr + bbi->size) {
				max = bbi->addr + bbi->size;
			}
		}
		x->meta.min = min;
		x->meta.max = max;
		x->_size = max - min; // HACK TODO Fix af size calculation
	}
}

// _fcn_tree_{cmp,calc_max_addr,free,probe} are used by interval tree.
static int _fcn_tree_cmp(const void *a_, const RBNode *b_, void *user) {
	const RAnalFunction *a = (const RAnalFunction *)a_;
	const RAnalFunction *b = FCN_CONTAINER (b_);
	set_meta_min_if_needed ((RAnalFunction *)a);
	set_meta_min_if_needed ((RAnalFunction *)b);
	ut32 size0 = a->meta.max - a->meta.min, size1 = b->meta.max - b->meta.min;
	ut64 from0 = a->meta.min, to0 = a->meta.min + size0, addr0 = a->addr;
	ut64 from1 = b->meta.min, to1 = b->meta.min + size1, addr1 = b->addr;
	if (from0 != from1) {
		return from0 < from1 ? -1 : 1;
	}
	if (to0 != to1) {
		return to0 - 1 < to1 - 1 ? -1 : 1;
	}
	if (addr0 != addr1) {
		return addr0 < addr1 ? -1 : 1;
	}
	return 0;
}

static int _fcn_addr_tree_cmp(const void *a_, const RBNode *b_, void *user) {
	const RAnalFunction *a = (const RAnalFunction *)a_;
	const RAnalFunction *b = ADDR_FCN_CONTAINER (b_);
	ut64 from0 = a->addr, from1 = b->addr;
	if (from0 != from1) {
		return from0 < from1 ? -1 : 1;
	}
	return 0;
}

static void _fcn_tree_calc_max_addr(RBNode *node) {
	int i;
	RAnalFunction *fcn = FCN_CONTAINER (node);
	set_meta_min_if_needed (fcn);
	fcn->rb_max_addr = fcn->meta.min + (fcn->_size == 0 ? 0 : (fcn->meta.max - fcn->meta.min - 1));
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			RAnalFunction *fcn1 = FCN_CONTAINER (node->child[i]);
			if (fcn1->rb_max_addr > fcn->rb_max_addr) {
				fcn->rb_max_addr = fcn1->rb_max_addr;
			}
		}
	}
}

static void _fcn_tree_free(RBNode *node) {
	// TODO RB tree is an intrusive data structure by embedding RBNode into RAnalFunction.
	// Currently fcns takes the ownership of the resources.
	// If the ownership transfers from fcns to fcn_tree:
	//
	// r_anal_fcn_free (FCN_CONTAINER (node));
}

// Descent x_ to find the first node whose interval intersects [from, to)
static RBNode *_fcn_tree_probe(FcnTreeIter *it, RBNode *x_, ut64 from, ut64 to) {
	RAnalFunction *x = FCN_CONTAINER (x_), *y;
	RBNode *y_;
	for (;;) {
		if ((y_ = x_->child[0]) && (y = FCN_CONTAINER (y_), from <= y->rb_max_addr)) {
			it->path[it->len++] = x_;
			x_ = y_;
			x = y;
			continue;
		}
		if (x->meta.min <= to - 1) {
			if (from <= x->meta.min + (x->_size == 0 ? 0 : (x->meta.max - x->meta.min - 1))) {
				return x_;
			}
			if ((y_ = x_->child[1])) {
				x_ = y_;
				x = FCN_CONTAINER (y_);
				if (from <= x->rb_max_addr) {
					continue;
				}
			}
		}
		return NULL;
	}
}

R_API bool r_anal_fcn_tree_delete(RAnal *anal, RAnalFunction *fcn) {
	bool ret_min = !!r_rbtree_aug_delete (&anal->fcn_tree, fcn, _fcn_tree_cmp, _fcn_tree_free, _fcn_tree_calc_max_addr, NULL);
	bool ret_addr = !!r_rbtree_delete (&anal->fcn_addr_tree, fcn, _fcn_addr_tree_cmp, NULL, NULL);
	if (ret_min != ret_addr) {
		eprintf ("WARNING: r_anal_fcn_tree_delete: check 'ret_min == ret_addr' failed\n");
		return false;
	}
	// r_return_val_if_fail (ret_min == ret_addr, false);
	return ret_min;
}

R_API void r_anal_fcn_tree_insert(RAnal *anal, RAnalFunction *fcn) {
	r_rbtree_aug_insert (&anal->fcn_tree, fcn, &(fcn->rb), _fcn_tree_cmp, _fcn_tree_calc_max_addr, NULL);
	r_rbtree_insert (&anal->fcn_addr_tree, fcn, &(fcn->addr_rb), _fcn_addr_tree_cmp, NULL);
}

static void _fcn_tree_update_size(RAnal *anal, RAnalFunction *fcn) {
	r_rbtree_aug_update_sum (anal->fcn_tree, fcn, &(fcn->rb), _fcn_tree_cmp, _fcn_tree_calc_max_addr, NULL);
}

#if 0
static void _fcn_tree_print_dot_node(RBNode *n) {
	int i;
	RAnalFunction *fcn = FCN_CONTAINER (n);

	ut64 max_addr = fcn->addr + (fcn->_size == 0 ? 0 : fcn->_size - 1);
	for (i = 0; i < 2; i++) {
		if (n->child[i]) {
			RAnalFunction *fcn1 = FCN_CONTAINER (n->child[i]);
			if (fcn1->rb_max_addr > max_addr) {
				max_addr = fcn1->rb_max_addr;
			}
		}
	}

	bool valid = max_addr == fcn->rb_max_addr;

	r_cons_printf ("  \"%p\" [label=\"%p\\naddr: 0x%08"PFMT64x"\\nmax_addr: 0x%08"PFMT64x"\"%s];\n",
				   n, fcn, fcn->addr, fcn->rb_max_addr, valid ? "" : ", color=\"red\", fillcolor=\"white\"");

	for (i=0; i<2; i++) {
		if (n->child[i]) {
			_fcn_tree_print_dot_node (n->child[i]);
			bool valid = true;
			if (n->child[i]) {
				RAnalFunction *childfcn = FCN_CONTAINER (n->child[i]);
				if ((i == 0 && childfcn->addr >= fcn->addr) || (i == 1 && childfcn->addr <= fcn->addr)) {
					valid = false;
				}
			}
			r_cons_printf ("  \"%p\" -> \"%p\" [label=\"%d\"%s];\n", n, n->child[i], i, valid ? "" : ", style=\"bold\", color=\"red\"");
		} else {
			r_cons_printf ("  \"null_%p_%d\" [shape=point];\n", n, i);
			r_cons_printf ("  \"%p\" -> \"null_%p_%d\" [label=\"%d\"];\n", n, n, i, i);
		}
	}
}

static void _fcn_tree_print_dot(RBNode *n) {
	r_cons_print ("digraph fcn_tree {\n");
	if (n) {
		_fcn_tree_print_dot_node (n);
	}
	r_cons_print ("}\n");
}
#endif

// Find RAnalFunction whose addr is equal to addr
static RAnalFunction *_fcn_addr_tree_find_addr(RAnal *anal, ut64 addr) {
	RBNode *n = anal->fcn_addr_tree;
	while (n) {
		RAnalFunction *x = ADDR_FCN_CONTAINER (n);
		if (x->addr == addr) {
			return x;
		}
		n = n->child[x->addr < addr];
	}
	return NULL;
}

// _fcn_tree_{iter_first,iter_next} are used to iterate functions whose intervals intersect [from, to) in O(log(n) + |candidates|) time
static FcnTreeIter _fcn_tree_iter_first(RBNode *x_, ut64 from, ut64 to) {
	FcnTreeIter it = {0};
	it.len = 0;
	if (x_ && from <= FCN_CONTAINER (x_)->rb_max_addr) {
		it.cur = _fcn_tree_probe (&it, x_, from, to);
	} else {
		it.cur = NULL;
	}
	return it;
}

static void _fcn_tree_iter_next(FcnTreeIter *it, ut64 from, ut64 to) {
	RBNode *x_ = it->cur, *y_;
	RAnalFunction *x, *y;
	for (;;) {
		if ((y_ = x_->child[1]) && (y = FCN_CONTAINER (y_), from <= y->rb_max_addr)) {
			it->cur = _fcn_tree_probe (it, y_, from, to);
			break;
		}
		if (!it->len) {
			it->cur = NULL;
			break;
		}
		x_ = it->path[--it->len];
		x = FCN_CONTAINER (x_);
		if (to - 1 < x->meta.min) {
			it->cur = NULL;
			break;
		}
		if (from <= x->meta.min + (x->_size == 0 ? 0 : (x->meta.max - x->meta.min - 1))) {
			it->cur = x_;
			break;
		}
	}
}

R_API int r_anal_fcn_resize(RAnal *anal, RAnalFunction *fcn, int newsize) {
	RAnalBlock *bb;
	RListIter *iter, *iter2;

	r_return_val_if_fail (fcn, false);

	if (newsize < 1) {
		return false;
	}
	r_anal_fcn_set_size (anal, fcn, newsize);

	// XXX this is something we should probably do for all the archs
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + r_anal_fcn_size (fcn);
	r_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		if (bb->addr >= eof) {
			// already called by r_list_delete r_anal_bb_free (bb);
			r_list_delete (fcn->bbs, iter);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			bb->size = eof - bb->addr;
		}
		if (bb->jump != UT64_MAX && bb->jump >= eof) {
			bb->jump = UT64_MAX;
		}
		if (bb->fail != UT64_MAX && bb->fail >= eof) {
			bb->fail = UT64_MAX;
		}
	}
	r_anal_fcn_update_tinyrange_bbs (fcn);
	return true;
}

R_API RAnalFunction *r_anal_fcn_new() {
	RAnalFunction *fcn = R_NEW0 (RAnalFunction);
	if (!fcn) {
		return NULL;
	}
	/* Function return type */
	fcn->rets = 0;
	fcn->_size = 0;
	/* Function qualifier: static/volatile/inline/naked/virtual */
	fcn->fmod = R_ANAL_FQUALIFIER_NONE;
	/* Function calling convention: cdecl/stdcall/fastcall/etc */
	fcn->cc = NULL;
	/* Function attributes: weak/noreturn/format/etc */
	fcn->addr = UT64_MAX;
	fcn->fcn_locs = NULL;
	fcn->bbs = r_anal_bb_list_new ();
	fcn->fingerprint = NULL;
	fcn->diff = r_anal_diff_new ();
	fcn->has_changed = true;
	fcn->bp_frame = true;
	fcn->is_noreturn = false;
	r_tinyrange_init (&fcn->bbr);
	fcn->meta.min = UT64_MAX;
	return fcn;
}

R_API RList *r_anal_fcn_list_new() {
	return r_list_newf (r_anal_fcn_free);
}

R_API void r_anal_fcn_free(void *_fcn) {
	RAnalFunction *fcn = _fcn;
	if (!_fcn) {
		return;
	}
	fcn->_size = 0;
	free (fcn->name);
	free (fcn->attr);
	r_tinyrange_fini (&fcn->bbr);
	r_list_free (fcn->fcn_locs);
	if (fcn->bbs) {
		fcn->bbs->free = (RListFree)r_anal_bb_free;
		r_list_free (fcn->bbs);
		fcn->bbs = NULL;
	}
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	free (fcn->args);
	free (fcn);
}

static RAnalBlock *bbget(RAnalFunction *fcn, ut64 addr, bool jumpmid) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		ut64 eaddr = bb->addr + bb->size;
		if (((bb->addr >= eaddr && addr == bb->addr)
		     || r_anal_bb_is_in_offset (bb, addr))
		    && (!jumpmid || r_anal_bb_op_starts_at (bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

// TODO: split between bb.new and append_bb()
static RAnalBlock *appendBasicBlock(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	RAnalBlock *bb = r_anal_bb_new ();
	if (bb) {
		if (anal->verbose) {
			eprintf ("Append bb at 0x%08"PFMT64x" (fcn 0x%08"PFMT64x ")\n", addr, fcn->addr);
		}
		bb->addr = addr;
		bb->size = 0;
		bb->jump = UT64_MAX;
		bb->fail = UT64_MAX;
		bb->type = 0; // TODO
		r_anal_fcn_bbadd (fcn, bb);
		if (anal->cb.on_fcn_bb_new) {
			anal->cb.on_fcn_bb_new (anal, anal->user, fcn, bb);
		}
	}
	return bb;
}

#define FITFCNSZ() if (bb) {\
	st64 n = bb->addr + bb->size - fcn->addr;\
	if (n >= 0 && r_anal_fcn_size (fcn) < n) {\
		r_anal_fcn_set_size (NULL, fcn, n); }\
	}\
	if (r_anal_fcn_size (fcn) > MAX_FCN_SIZE) {\
		/* eprintf ("Function too big at 0x%"PFMT64x" + %d\n", bb->addr, fcn->size); */\
		r_anal_fcn_set_size (NULL, fcn, 0);\
		return R_ANAL_RET_ERROR;\
	}

#define gotoBeach(x) ret = x; goto beach;

static bool isInvalidMemory(RAnal *anal, const ut8 *buf, int len) {
	if (anal->opt.nonull > 0) {
		int i;
		const int count = R_MIN (len, anal->opt.nonull);
		for (i = 0; i < count; i++) {
			if (buf[i]) {
				break;
			}
		}
		if (i == count) {
			return true;
		}
	}
	return !memcmp (buf, "\xff\xff\xff\xff", R_MIN (len, 4));
}

static bool isSymbolNextInstruction(RAnal *anal, RAnalOp *op) {
	r_return_val_if_fail (anal && op && anal->flb.get_at, false);

	RFlagItem *fi = anal->flb.get_at (anal->flb.f, op->addr + op->size, false);
	return (fi && fi->name && (strstr (fi->name, "imp.") || strstr (fi->name, "sym.")
			|| strstr (fi->name, "entry") || strstr (fi->name, "main")));
}

static bool is_delta_pointer_table(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, RAnalOp *jmp_aop) {
	int i;
	ut64 dst;
	st32 jmptbl[64] = {0};
	/* check if current instruction is followed by an ujmp */
	ut8 buf[JMPTBL_LEA_SEARCH_SZ];
	RAnalOp *aop = jmp_aop;
	RAnalOp mov_aop = {0};
	RAnalOp add_aop = {0};

	read_ahead (anal, addr, (ut8*)buf, sizeof (buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
		int len = r_anal_op (anal, aop, at, buf + i, left, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		if (len < 1) {
			len = 1;
		}
		if (aop->type == R_ANAL_OP_TYPE_UJMP || aop->type == R_ANAL_OP_TYPE_RJMP) {
			isValid = true;
			break;
		}
		if (aop->type == R_ANAL_OP_TYPE_MOV) {
			mov_aop = *aop;
		}
		if (aop->type == R_ANAL_OP_TYPE_ADD) {
			add_aop = *aop;
		}
		r_anal_op_fini (aop);
		i += len - 1;
	}
	if (!isValid) {
		return false;
	}

	// check if we have a msvc 19xx style jump table using rva table entries
	// lea reg1, [base_addr]
	// mov reg2, sword [reg1 + tbl_off*4 + tbl_loc_off]
	// add reg2, reg1
	// jmp reg2
	if (mov_aop.type && add_aop.type && mov_aop.addr < add_aop.addr && add_aop.addr < jmp_aop->addr
	    && mov_aop.disp && mov_aop.disp != UT64_MAX) {
		// disp in this case should be tbl_loc_off
		*jmptbl_addr += mov_aop.disp;
	}
#if 0
	// required for the last jmptbl.. but seems to work without it and breaks other tests
	if (mov_aop.type && mov_aop.ptr) {
		*jmptbl_addr += mov_aop.ptr;
		// absjmptbl
		lea_ptr = mov_aop.ptr;
	}
#endif
	/* check if jump table contains valid deltas */
	read_ahead (anal, *jmptbl_addr, (ut8 *)&jmptbl, 64);
	for (i = 0; i < 3; i++) {
		dst = lea_ptr + (st32)r_read_le32 (jmptbl);
		if (!anal->iob.is_valid_offset (anal->iob.io, dst, 0)) {
			return false;
		}
		if (dst > fcn->addr + JMPTBL_MAXFCNSIZE) {
			return false;
		}
		if (anal->opt.jmpabove && dst < (fcn->addr < JMPTBL_MAXFCNSIZE ? 0 : fcn->addr - JMPTBL_MAXFCNSIZE)) {
			return false;
		}
	}
	return true;
}

static ut64 try_get_cmpval_from_parents(RAnal * anal, RAnalFunction *fcn, RAnalBlock *my_bb, const char * cmp_reg) {
	r_return_val_if_fail (fcn && fcn->bbs && cmp_reg, UT64_MAX);
	RListIter *iter;
	RAnalBlock *tmp_bb;
	r_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			if (tmp_bb->cmpreg == cmp_reg) {
				return tmp_bb->cmpval;
			}
		}
	}
	return UT64_MAX;
}

static bool regs_exist(RAnalValue *src, RAnalValue *dst) {
	r_return_val_if_fail (src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
static int skip_hp(RAnal *anal, RAnalFunction *fcn, RAnalOp *op, RAnalBlock *bb, ut64 addr,
                   char *tmp_buf, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!anal->flb.exist_at (anal->flb.f, "skip", 4, addr)) {
			snprintf (tmp_buf + 5, MAX_FLG_NAME_SIZE - 6, "%"PFMT64u, addr);
			anal->flb.set (anal->flb.f, tmp_buf, addr, oplen);
			fcn->addr += oplen;
			bb->size -= oplen;
			bb->addr += oplen;
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
}

R_API int r_anal_case(RAnal *anal, RAnalFunction *fcn, ut64 addr_bbsw, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	RAnalOp op = { 0 };
	int oplen, idx = 0;
	while (idx < len) {
		if ((len - idx) < 5) {
			break;
		}
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, addr + idx, buf + idx, len - idx, R_ANAL_OP_MASK_BASIC)) < 1) {
			return 0;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_RET:
		case R_ANAL_OP_TYPE_JMP:
			// eprintf ("CASE AT 0x%llx size %d\n", addr, idx + oplen);
			r_strbuf_appendf (anal->cmdtail, "afb+ 0x%"PFMT64x " 0x%"PFMT64x " %d\n",
				fcn->addr, addr, idx + oplen);
			r_strbuf_appendf (anal->cmdtail, "afbe 0x%"PFMT64x " 0x%"PFMT64x "\n",
				addr_bbsw, addr);
			return idx + oplen;
		}
		idx += oplen;
	}
	return idx;
}

static bool purity_checked(HtUP *ht, RAnalFunction *fcn) {
	bool checked;
	ht_up_find (ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RList *refs = r_anal_fcn_get_refs (anal, fcn);
	RAnalRef *ref;
	ht_up_insert (ht, fcn->addr, NULL);
	fcn->is_pure = true;
	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CALL || ref->type == R_ANAL_REF_TYPE_CODE) {
			RAnalFunction *called_fcn = r_anal_get_fcn_in (anal, ref->addr, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked (ht, called_fcn)) {
				check_purity (ht, anal, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (ref->type == R_ANAL_REF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	r_list_free (refs);
}

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
} leaddr_pair;

static int fcn_recurse(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int depth) {
	const int continue_after_jump = anal->opt.afterjmp;
	const int addrbytes = anal->iob.io ? anal->iob.io->addrbytes : 1;
	RAnalBlock *bb = NULL;
	RAnalBlock *bbg = NULL;
	int ret = R_ANAL_RET_END, skip_ret = 0;
	bool overlapped = false;
	RAnalOp op = {0};
	int oplen, idx = 0;
	static ut64 cmpval = UT64_MAX; // inherited across functions, otherwise it breaks :?
	bool varset = false;
	struct {
		int cnt;
		int idx;
		int after;
		int pending;
		int adjust;
		int un_idx; // delay.un_idx
	} delay = {
		0
	};
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	char tmp_buf[MAX_FLG_NAME_SIZE + 5] = "skip";
	bool is_x86 = is_arm? false: anal->cur->arch && !strncmp (anal->cur->arch, "x86", 3);
	bool is_dalvik = is_x86? false: anal->cur->arch && !strncmp (anal->cur->arch, "dalvik", 6);

	if (r_cons_is_breaked ()) {
		return R_ANAL_RET_END;
	}
	if (anal->sleep) {
		r_sys_usleep (anal->sleep);
	}

	if (depth < 1) {
		if (anal->verbose) {
			eprintf ("Anal went too deep at address 0x%"PFMT64x ".\n", addr);
		}
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	// check if address is readable //:
	if (!anal->iob.is_valid_offset (anal->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !anal->iob.io->va) {
			if (anal->verbose) {
				eprintf ("Invalid address 0x%"PFMT64x ". Try with io.va=true\n", addr);
			}
		}
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	RAnalFunction *fcn_at_addr = r_anal_get_fcn_at (anal, addr, 0);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return R_ANAL_RET_ERROR; // MUST BE NOT FOUND
	}
	bb = bbget (fcn, addr, anal->opt.jmpmid && is_x86);
	if (bb) {
		r_anal_fcn_split_bb (anal, fcn, bb, addr);
		if (anal->opt.recont) {
			return R_ANAL_RET_END;
		}
		if (anal->verbose) {
			eprintf ("r_anal_fcn_bb() fails at 0x%"PFMT64x ".\n", addr);
		}
		return R_ANAL_RET_ERROR; // MUST BE NOT DUP
	}

	static RList *leaddrs = NULL;
	if (!leaddrs) {
		leaddrs = r_list_new (); // TODO: leaks
		if (!leaddrs) {
			eprintf ("Cannot create leaddr list\n");
			return R_ANAL_RET_ERROR;
		}
	}
	static ut64 lea_jmptbl_ip = UT64_MAX;
	char *last_reg_mov_lea_name = NULL;
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (anal->limit && addr + idx < anal->limit->from) {
		gotoBeach (R_ANAL_RET_END);
	}
	RAnalFunction *tmp_fcn = r_anal_get_fcn_in (anal, addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		RList *list = r_anal_var_all_list (anal, tmp_fcn);
		if (!r_list_empty (list)) {
			varset = true;
		}
		r_list_free (list);
	}
	ut64 movdisp = UT64_MAX; // used by jmptbl when coded as "mov reg,[R*4+B]"
	ut8 buf[32]; // 32 bytes is enough to hold any instruction.
	int maxlen = len * addrbytes;
	if (is_dalvik) {
		bool skipAnalysis = false;
		if (!strncmp (fcn->name, "sym.", 4)) {
			if (!strncmp (fcn->name + 4, "imp.", 4)) {
				skipAnalysis = true;
			} else if (strstr (fcn->name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			ret = 0;
			gotoBeach (R_ANAL_RET_END);
		}
	}
	bb = appendBasicBlock (anal, fcn, addr);

	while (addrbytes * idx < maxlen) {
		if (!last_is_reg_mov_lea) {
			free (last_reg_mov_lea_name);
			last_reg_mov_lea_name = NULL;
		}
		if (anal->limit && anal->limit->to <= addr + idx) {
			break;
		}
repeat:
		if (r_cons_is_breaked ()) {
			break;
		}
		ut32 at_delta = addrbytes * idx;
		ut64 at = addr + at_delta;
		ut64 bytes_read = R_MIN (len - at_delta, sizeof (buf));
		ret = read_ahead (anal, at, buf, bytes_read);

		if (ret < 0) {
			eprintf ("Failed to read\n");
			break;
		}
		if (isInvalidMemory (anal, buf, bytes_read)) {
			FITFCNSZ ();
			if (anal->verbose) {
				eprintf ("Warning: FFFF opcode at 0x%08"PFMT64x "\n", at);
			}
			gotoBeach (R_ANAL_RET_ERROR)
		}
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, at, buf, bytes_read, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_HINT)) < 1) {
			if (anal->verbose) {
				eprintf ("Invalid instruction at 0x%"PFMT64x" with %d bits\n", at, anal->bits);
			}
			// gotoBeach (R_ANAL_RET_ERROR);
			// RET_END causes infinite loops somehow
			gotoBeach (R_ANAL_RET_END);
		}
		if (anal->opt.nopskip && fcn->addr == at) {
			RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
			if (!fi || strncmp (fi->name, "sym.", 4)) {
				if ((addr + delay.un_idx - oplen) == fcn->addr) {
					fcn->addr += oplen;
					bb->size -= oplen;
					bb->addr += oplen;
					idx = delay.un_idx;
					goto repeat;
				}
			}
			switch (op.type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_NOP:
				bb->addr = fcn->addr = addr = at + op.size;
				goto repeat;
			}
		}
		if (op.hint.new_bits) {
			r_anal_hint_set_bits (anal, op.jump, op.hint.new_bits);
		}
		if (idx > 0 && !overlapped) {
			bbg = bbget (fcn, at, anal->opt.jmpmid && is_x86);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (anal->opt.jmpmid && is_x86) {
					r_anal_fcn_split_bb (anal, fcn, bbg, at);
				}
				overlapped = true;
				if (anal->verbose) {
					eprintf ("Overlapped at 0x%08"PFMT64x "\n", at);
				}
				// return R_ANAL_RET_END;
			}
		}
		if (!overlapped) {
			r_anal_bb_set_offset (bb, bb->ninstr++, at - bb->addr);
			bb->size += oplen;
			fcn->ninstr++;
			// FITFCNSZ(); // defer this, in case this instruction is a branch delay entry
			// fcn->size += oplen; /// XXX. must be the sum of all the bblocks
		}
		if (anal->opt.trycatch) {
			const char *name = anal->coreb.getName (anal->coreb.core, at);
			if (name) {
				if (r_str_startswith (name, "try.") && r_str_endswith (name, ".from")) {
					char *handle = strdup (name);
					// handle = r_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = anal->coreb.numGet (anal->coreb.core, handle);
					handle = r_str_replace (handle, ".from", ".catch", 0);
					ut64 handle_addr = anal->coreb.numGet (anal->coreb.core, handle);
					bb->jump = at + oplen;
					if (from_addr != bb->addr) {
						bb->fail = handle_addr;
						ret = r_anal_fcn_bb (anal, fcn, handle_addr, depth);
						eprintf ("(%s) 0x%08"PFMT64x"\n", handle, handle_addr);
						bb = appendBasicBlock (anal, fcn, addr);
					}
				}
			}
		}
		idx += oplen;
		delay.un_idx = idx;
		if (anal->opt.delay && op.delay > 0 && !delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			if (anal->verbose) {
				eprintf("Enter branch delay at 0x%08"PFMT64x ". bb->sz=%d\n", at - oplen, bb->size);
			}
			delay.idx = idx - oplen;
			delay.cnt = op.delay;
			delay.pending = 1; // we need this in case the actual idx is zero...
			delay.adjust = !overlapped; // adjustment is required later to avoid double count
			continue;
		}

		if (delay.cnt > 0) {
			// if we had passed a branch delay instruction, keep
			// track of how many still to process.
			delay.cnt--;
			if (!delay.cnt) {
				if (anal->verbose) {
					eprintf("Last branch delayed opcode at 0x%08"PFMT64x ". bb->sz=%d\n", addr + idx - oplen, bb->size);
				}
				delay.after = idx;
				idx = delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (op.delay > 0 && delay.pending) {
			if (anal->verbose) {
				eprintf ("Revisit branch delay jump at 0x%08"PFMT64x ". bb->sz=%d\n", addr + idx - oplen, bb->size);
			}
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				bb->size -= oplen;
				fcn->ninstr--;
				if (anal->verbose) {
					eprintf ("Correct for branch delay @ %08"PFMT64x " bb.addr=%08"PFMT64x " corrected.bb=%d f.uncorr=%d\n",
					addr + idx - oplen, bb->addr, bb->size, r_anal_fcn_size (fcn));
				}
				FITFCNSZ ();
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			idx = delay.after;
			delay.pending = delay.after = delay.idx = delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		switch (op.stackop) {
		case R_ANAL_STACK_INC:
			if (R_ABS (op.stackptr) < 8096) {
				fcn->stack += op.stackptr;
				if (fcn->stack > fcn->maxstack) {
					fcn->maxstack = fcn->stack;
				}
			}
			bb->stackptr += op.stackptr;
			break;
		case R_ANAL_STACK_RESET:
			bb->stackptr = 0;
			break;
		}
		if (anal->opt.vars && !varset) {
			r_anal_extract_vars (anal, fcn, &op);
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters wtf
			r_anal_xrefs_set (anal, op.addr, op.ptr, R_ANAL_REF_TYPE_DATA);
		}
		switch (op.type & R_ANAL_OP_TYPE_MASK) {
		case R_ANAL_OP_TYPE_CMOV:
		case R_ANAL_OP_TYPE_MOV:
			last_is_reg_mov_lea = false;
			if (is_arm) { // mov lr, pc
				const char *esil = r_strbuf_get (&op.esil);
				if (!r_str_cmp (esil, "pc,lr,=", -1)) {
					last_is_mov_lr_pc = true;
				}
			}
			// Is this a mov of immediate value into a register?
			if (op.dst && op.dst->reg && op.dst->reg->name && op.val > 0 && op.val != UT64_MAX) {
				free (last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
					last_reg_mov_lea_val = op.val;
					last_is_reg_mov_lea = true;
				}
			}
			// skip mov reg, reg
			if (anal->opt.jmptbl) {
				if (op.scale && op.ireg) {
					movdisp = op.disp;
				}
			}
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, addr, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_LEA:
			last_is_reg_mov_lea = false;
			// if first byte in op.ptr is 0xff, then set leaddr assuming its a jumptable
			{
				ut8 buf[4];
				anal->iob.read_at (anal->iob.io, op.ptr, buf, sizeof (buf));
				if ((buf[2] == 0xff || buf[2] == 0xfe) && buf[3] == 0xff) {
					leaddr_pair *pair = R_NEW (leaddr_pair);
					if (!pair) {
						eprintf ("Cannot create leaddr_pair\n");
						gotoBeach (R_ANAL_RET_ERROR);
					}
					pair->op_addr = op.addr;
					pair->leaddr = op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
					r_list_append (leaddrs, pair);
				}
				if (op.dst && op.dst->reg && op.dst->reg->name && op.ptr > 0 && op.ptr != UT64_MAX) {
					free (last_reg_mov_lea_name);
					if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
						last_reg_mov_lea_val = op.ptr;
						last_is_reg_mov_lea = true;
					}
				}
			}
			// skip lea reg,[reg]
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, at, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			if (anal->opt.jmptbl) {
				RAnalOp jmp_aop = {0};
				ut64 jmptbl_addr = op.ptr;
				if (is_delta_pointer_table (anal, fcn, op.addr, op.ptr, &jmptbl_addr, &jmp_aop)) {
					ut64 table_size, default_case = 0;
					// we require both checks here since try_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// try_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with try_get_jmptbl_info
					if (try_get_jmptbl_info (anal, fcn, jmp_aop.addr, bb, &table_size, &default_case)
						|| try_get_delta_jmptbl_info (anal, fcn, jmp_aop.addr, op.addr, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, depth, jmp_aop.addr, jmptbl_addr, op.ptr, 4, table_size, default_case, 4);
						if (ret) {
							lea_jmptbl_ip = jmp_aop.addr;
						}
					}
				}
				r_anal_op_fini (&jmp_aop);
			}
			break;
		case R_ANAL_OP_TYPE_LOAD:
			if (anal->opt.loads) {
				if (anal->iob.is_valid_offset (anal->iob.io, op.ptr, 0)) {
					r_meta_add (anal, R_META_TYPE_DATA, op.ptr, op.ptr + 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case R_ANAL_OP_TYPE_ADD:
			if (anal->opt.ijmp) {
				if ((op.size + 4 <= bytes_read) && !memcmp (buf + op.size, "\x00\x00\x00\x00", 4)) {
					bb->size -= oplen;
					op.type = R_ANAL_OP_TYPE_RET;
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_ILL:
			gotoBeach (R_ANAL_RET_END);
		case R_ANAL_OP_TYPE_TRAP:
			gotoBeach (R_ANAL_RET_END);
		case R_ANAL_OP_TYPE_NOP:
			// do nothing, because the nopskip goes before this switch
			break;
		case R_ANAL_OP_TYPE_JMP:
			if (op.jump == UT64_MAX) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				RFlagItem *fi = anal->flb.get_at (anal->flb.f, op.jump, false);
				if (fi && strstr (fi->name, "imp.")) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			if (r_cons_is_breaked ()) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (anal->opt.jmpref) {
				(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CODE);
			}
			if (!anal->opt.jmpabove && (op.jump < fcn->addr)) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (r_anal_noreturn_at (anal, op.jump)) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				bool must_eob = anal->opt.eobjmp;
				if (!must_eob) {
					RIOMap *map = anal->iob.map_get (anal->iob.io, addr);
					if (map) {
						must_eob = (op.jump < map->itv.addr || op.jump >= map->itv.addr + map->itv.size);
					} else {
						must_eob = true;
					}
				}
				if (must_eob) {
					FITFCNSZ ();
					op.jump = UT64_MAX;
					gotoBeach (R_ANAL_RET_END);
				}
			}
#if FIX_JMP_FWD
			bb->jump = op.jump;
			bb->fail = UT64_MAX;
			FITFCNSZ ();
			return R_ANAL_RET_END;
#else
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = UT64_MAX;
			}
			ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
			FITFCNSZ ();

			goto beach;
#endif
			break;
		case R_ANAL_OP_TYPE_SUB:
			if (op.val != UT64_MAX && op.val > 0) {
				// if register is not stack
				cmpval = op.val;
			}
			break;
		case R_ANAL_OP_TYPE_CMP: {
			ut64 val = is_x86 ? op.val : op.ptr;
			if (val) {
				cmpval = val;
				bb->cmpval = cmpval;
				bb->cmpreg = op.reg;
			}
		}
			break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_MCJMP:
		case R_ANAL_OP_TYPE_RCJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			if (anal->opt.cjmpref) {
				(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CODE);
			}
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = op.fail;
			}
			if (anal->opt.jmptbl) {
				if (op.ptr != UT64_MAX) {
					ut64 table_size, default_case;
					table_size = cmpval + 1;
					default_case = op.fail; // is this really default case?
					if (cmpval != UT64_MAX && default_case != UT64_MAX && (op.reg || op.ireg)) {
						if (op.ireg) {
							ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						} else { // op.reg
							ret = walkthrough_arm_jmptbl_style (anal, fcn, depth, op.addr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						}
						// check if op.jump and op.fail contain jump table location
						// clear jump address, because it's jump table location
						if (op.jump == op.ptr) {
							op.jump = UT64_MAX;
						} else if (op.fail == op.ptr) {
							op.fail = UT64_MAX;
						}
						cmpval = UT64_MAX;
					}
				}
			}
			if (continue_after_jump) {
				r_anal_fcn_bb (anal, fcn, op.jump, depth);
				ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
			} else {
				// This code seems to break #1519
				if (anal->opt.eobjmp) {
#if JMP_IS_EOB
					if (!overlapped) {
						bb->jump = op.jump;
						bb->fail = UT64_MAX;
					}
					FITFCNSZ ();
					r_anal_fcn_bb (anal, fcn, op.jump, depth);
					ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
					gotoBeach (R_ANAL_RET_END);
#else
					// hardcoded jmp size // must be checked at the end wtf?
					// always fitfcnsz and retend
					if (op.jump > fcn->addr + JMP_IS_EOB_RANGE) {
						ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
						/* jump inside the same function */
						gotoBeach (R_ANAL_RET_END);
					} else if (op.jump < fcn->addr - JMP_IS_EOB_RANGE) {
						ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
						/* jump inside the same function */
						gotoBeach (R_ANAL_RET_END);
					} else {
						if (op.jump < addr - JMP_IS_EOB_RANGE) {
							gotoBeach (R_ANAL_RET_END);
						}
						if (op.jump > addr + JMP_IS_EOB_RANGE) {
							gotoBeach (R_ANAL_RET_END);
						}
					}
#endif
				}
				ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
				ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
				if (!anal->opt.eobjmp) {
					if (op.jump < fcn->addr) {
						if (!overlapped) {
							bb->jump = op.jump;
							bb->fail = UT64_MAX;
						}
						gotoBeach (R_ANAL_RET_END);
					}
				}
			}

			// XXX breaks mips analysis too !op.delay
			// this will be all x86, arm (at least)
			// without which the analysis is really slow,
			// presumably because each opcode would get revisited
			// (and already covered by a bb) many times
			goto beach;
			// For some reason, branch delayed code (MIPS) needs to continue
			break;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void) r_anal_xrefs_set (anal, op.addr, op.ptr, R_ANAL_REF_TYPE_CALL);

			if (op.ptr != UT64_MAX && r_anal_noreturn_at (anal, op.ptr)) {
				RAnalFunction *f = r_anal_get_fcn_at(anal, op.ptr, 0);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_CALL:
			/* call dst */
			(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CALL);

			if (r_anal_noreturn_at (anal, op.jump)) {
				RAnalFunction *f = r_anal_get_fcn_at(anal, op.jump, 0);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
			if (is_arm && last_is_mov_lr_pc) {
				break;
			}
			/* fall through */
		case R_ANAL_OP_TYPE_MJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (anal->opt.ijmp && isSymbolNextInstruction (anal, &op)) {
				gotoBeach (R_ANAL_RET_END);
			}
			// switch statement
			if (anal->opt.jmptbl && lea_jmptbl_ip != op.addr) {
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (op.ptr != UT64_MAX && op.ireg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
				} else if (op.ptr != UT64_MAX && op.reg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
				} else if (movdisp == 0) {
					ut64 jmptbl_base = UT64_MAX;
					ut64 lea_op_off = UT64_MAX;
					RListIter *lea_op_iter = NULL;
					RListIter *iter;
					leaddr_pair *pair;
					// find nearest candidate leaddr before op.addr
					r_list_foreach (leaddrs, iter, pair) {
						if (pair->op_addr >= op.addr) {
							continue;
						}
						if (lea_op_off == UT64_MAX || lea_op_off > op.addr - pair->op_addr) {
							lea_op_off = op.addr - pair->op_addr;
							jmptbl_base = pair->leaddr;
							lea_op_iter = iter;
						}
					}
					if (lea_op_iter) {
						r_list_delete (leaddrs, lea_op_iter);
					}
					ut64 table_size = cmpval + 1;
					ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, jmptbl_base, jmptbl_base, 4, table_size, -1, ret);
					cmpval = UT64_MAX;
				} else if (movdisp != UT64_MAX) {
					ut64 table_size, default_case;

					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						op.ptr = movdisp;
						ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
					movdisp = UT64_MAX;
				} else if (is_arm) {
					if (op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						int tablesize = 0;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.addr + op.size,
							op.addr + 4, 1, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize);
					}
					if (op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						int tablesize = 1;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, depth, op.addr, op.addr + op.size,
							op.addr + 4, 2, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize * 2);
					}
				}
			}
			if (lea_jmptbl_ip == op.addr) {
				lea_jmptbl_ip = UT64_MAX;
			}
			if (anal->opt.ijmp) {
				if (continue_after_jump) {
					r_anal_fcn_bb (anal, fcn, op.jump, depth);
					ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
					if (overlapped) {
						goto analopfinish;
					}
				}
				if (r_anal_noreturn_at (anal, op.jump) || op.eob) {
					goto analopfinish;
				}
			} else {
analopfinish:
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		/* fallthru */
		case R_ANAL_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op.val;
			if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
				(void) r_anal_xrefs_set (anal, op.addr, last_push_addr, R_ANAL_REF_TYPE_DATA);
			}
			break;
		case R_ANAL_OP_TYPE_UPUSH:
			if ((op.type & R_ANAL_OP_TYPE_REG) && last_is_reg_mov_lea && op.src[0] && op.src[0]->reg
				&& op.src[0]->reg->name && !strcmp (op.src[0]->reg->name, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
					(void) r_anal_xrefs_set (anal, op.addr, last_push_addr, R_ANAL_REF_TYPE_DATA);
				}
			}
			break;
		case R_ANAL_OP_TYPE_RET:
			if (op.family == R_ANAL_OP_FAMILY_PRIV) {
				fcn->type = R_ANAL_FCN_TYPE_INT;
			}
			if (last_is_push && anal->opt.pushret) {
				op.type = R_ANAL_OP_TYPE_JMP;
				op.jump = last_push_addr;
				bb->jump = op.jump;
				ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
				goto beach;
			}
			if (!op.cond) {
				if (anal->verbose) {
					eprintf ("RET 0x%08"PFMT64x ". overlap=%s %d %d\n",
						addr + delay.un_idx - oplen, r_str_bool (overlapped),
						bb->size, r_anal_fcn_size (fcn));
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		}
		if (op.type != R_ANAL_OP_TYPE_MOV && op.type != R_ANAL_OP_TYPE_CMOV && op.type != R_ANAL_OP_TYPE_LEA) {
			last_is_reg_mov_lea = false;
		}
		if (op.type != R_ANAL_OP_TYPE_PUSH && op.type != R_ANAL_OP_TYPE_RPUSH) {
			last_is_push = false;
		}
		if (is_arm && op.type != R_ANAL_OP_TYPE_MOV) {
			last_is_mov_lr_pc = false;
		}
	}
beach:
	r_anal_op_fini (&op);
	FITFCNSZ ();
	free (last_reg_mov_lea_name);
	return ret;
}

R_API int r_anal_fcn_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, int depth) {
	int ret = fcn_recurse (anal, fcn, addr, anal->opt.bb_max_size, depth - 1);
	r_anal_fcn_update_tinyrange_bbs (fcn);
	if (ret != -1) {
		r_anal_fcn_set_size (anal, fcn, r_anal_fcn_size (fcn));
	}
	return ret;
}

static bool check_preludes(ut8 *buf, ut16 bufsz) {
	if (bufsz < 10) {
		return false;
	}
	if (!memcmp (buf, (const ut8 *) "\x55\x89\xe5", 3)) {
		return true;
	} else if (!memcmp (buf, (const ut8 *) "\x55\x8b\xec", 3)) {
		return true;
	} else if (!memcmp (buf, (const ut8 *) "\x8b\xff", 2)) {
		return true;
	} else if (!memcmp (buf, (const ut8 *) "\x55\x48\x89\xe5", 4)) {
		return true;
	} else if (!memcmp (buf, (const ut8 *) "\x55\x48\x8b\xec", 4)) {
		return true;
	}
	return false;
}

R_API bool r_anal_check_fcn(RAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RAnalOp op = {
		0
	};
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (check_preludes (buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, addr + i, buf + i, bufsz - i, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT)) < 1) {
			return false;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
		case R_ANAL_OP_TYPE_RPUSH:
			pushcnt++;
			break;
		case R_ANAL_OP_TYPE_MOV:
		case R_ANAL_OP_TYPE_CMOV:
			movcnt++;
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			if (op.jump < low || op.jump >= high) {
				return false;
			}
			brcnt++;
			break;
		case R_ANAL_OP_TYPE_UNK:
			return false;
		}
	}
	return (pushcnt + movcnt + brcnt > 5);
}

static void fcnfit(RAnal *a, RAnalFunction *f) {
	// find next function
	RAnalFunction *next = r_anal_fcn_next (a, f->addr);
	if (next) {
		if ((f->addr + r_anal_fcn_size (f)) > next->addr) {
			r_anal_fcn_resize (a, f, (next->addr - f->addr));
		}
	}
}

R_API void r_anal_fcn_fit_overlaps(RAnal *anal, RAnalFunction *fcn) {
	if (fcn) {
		fcnfit (anal, fcn);
	} else {
		RAnalFunction *f;
		RListIter *iter;
		r_list_foreach (anal->fcns, iter, f) {
			if (r_cons_is_breaked ()) {
				break;
			}
			fcnfit (anal, f);
		}
	}
}

R_API void r_anal_trim_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	RAnalRef *ref;
	RList *refs = r_anal_fcn_get_refs (anal, fcn);
	RListIter *iter;
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86"); // HACK

	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CODE && r_anal_fcn_is_in_offset (fcn, ref->addr)
		    && (!is_x86 || !r_anal_fcn_is_in_offset (fcn, ref->at))) {
			r_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	r_list_free (refs);
}

R_API void r_anal_del_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	RAnalRef *ref;
	RList *refs = r_anal_fcn_get_refs (anal, fcn);
	RListIter *iter;

	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CODE) {
			r_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	r_list_free (refs);
}

/* Does NOT invalidate read-ahead cache. */
R_API int r_anal_fcn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int reftype) {
	RList *list = r_meta_find_list_in (anal, addr, -1, 4);
	RListIter *iter;
	RAnalMetaItem *meta;
	r_list_foreach (list, iter, meta) {
		switch (meta->type) {
		case R_META_TYPE_DATA:
		case R_META_TYPE_STRING:
		case R_META_TYPE_FORMAT:
			r_list_free (list);
			return 0;
		}
	}
	r_list_free (list);
	if (anal->opt.norevisit) {
		if (!anal->visited) {
			anal->visited = set_u_new ();
		}
		if (set_u_contains (anal->visited, addr)) {
			eprintf ("r_anal_fcn: anal.norevisit at 0x%08"PFMT64x" %c\n", addr, reftype);
			return R_ANAL_RET_END;
		}
		set_u_add (anal->visited, addr);
	} else {
		if (anal->visited) {
			set_u_free (anal->visited);
			anal->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == R_ANAL_REF_TYPE_CODE) ? R_ANAL_FCN_TYPE_LOC : R_ANAL_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	if (anal->cur && anal->cur->fcn) {
		int result = anal->cur->fcn (anal, fcn, addr, reftype);
		if (anal->use_ex && anal->cur->custom_fn_anal) {
			return result;
		}
	}
	r_anal_fcn_set_size (NULL, fcn, 0); // fcn is not yet in anal => pass NULL
	fcn->maxstack = 0;
	int ret = r_anal_fcn_bb (anal, fcn, addr, anal->opt.depth);
	if (ret == -1) {
		if (anal->verbose) {
			eprintf ("Failed to analyze basic block at 0x%"PFMT64x"\n", addr);
		}
	}
	if (anal->opt.endsize && ret == R_ANAL_RET_END && r_anal_fcn_size (fcn)) {   // cfg analysis completed
		RListIter *iter;
		RAnalBlock *bb;
		ut64 endaddr = fcn->addr;
		const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");

		// set function size as length of continuous sequence of bbs
		r_list_sort (fcn->bbs, &cmpaddr);
		r_list_foreach (fcn->bbs, iter, bb) {
			if (endaddr == bb->addr) {
				endaddr += bb->size;
			} else if ((endaddr < bb->addr && bb->addr - endaddr < BB_ALIGN)
			           || (anal->opt.jmpmid && is_x86 && endaddr > bb->addr
			               && bb->addr + bb->size > endaddr)) {
				endaddr = bb->addr + bb->size;
			} else {
				break;
			}
		}
#if JAYRO_04
		// fcn is not yet in anal => pass NULL
		r_anal_fcn_resize (anal, fcn, endaddr - fcn->addr);
#endif
		r_anal_trim_jmprefs (anal, fcn);
	}
	return ret;
}

// TODO: need to implement r_anal_fcn_remove(RAnal *anal, RAnalFunction *fcn);
R_API int r_anal_fcn_insert(RAnal *anal, RAnalFunction *fcn) {
	// RAnalFunction *f = r_anal_get_fcn_in (anal, fcn->addr, R_ANAL_FCN_TYPE_ROOT);
	RAnalFunction *f = r_anal_get_fcn_at (anal, fcn->addr, R_ANAL_FCN_TYPE_ROOT);
	if (f) {
		return false;
	}
	/* TODO: sdbization */
	r_list_append (anal->fcns, fcn);
	r_anal_fcn_tree_insert (anal, fcn);
	if (anal->cb.on_fcn_new) {
		anal->cb.on_fcn_new (anal, anal->user, fcn);
	}
	if (anal->flg_fcn_set) {
		anal->flg_fcn_set (anal->flb.f, fcn->name, fcn->addr, r_anal_fcn_size (fcn));
	}
	return true;
}

R_API int r_anal_fcn_add(RAnal *a, ut64 addr, ut64 size, const char *name, int type, RAnalDiff *diff) {
	bool append = false;
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, R_ANAL_FCN_TYPE_ROOT);
	if (!fcn) {
		if (!(fcn = r_anal_fcn_new ())) {
			return false;
		}
		append = true;
	}
	fcn->addr = fcn->meta.min = addr;
	fcn->cc = r_str_const (r_anal_cc_default (a));
	fcn->bits = a->bits;
	r_anal_fcn_set_size (append ? NULL : a, fcn, size);
	free (fcn->name);
	if (name) {
		fcn->name = strdup (name);
	} else {
		const char *fcnprefix = a->coreb.cfgGet? a->coreb.cfgGet (a->coreb.core, "anal.fcnprefix"): NULL;
		if (!fcnprefix) {
			fcnprefix = "fcn";
		}
		fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnprefix, fcn->addr);
	}
	fcn->type = type;
	if (diff) {
		fcn->diff->type = diff->type;
		fcn->diff->addr = diff->addr;
		R_FREE (fcn->diff->name);
		if (diff->name) {
			fcn->diff->name = strdup (diff->name);
		}
	}
	return append? r_anal_fcn_insert (a, fcn): true;
}

R_API int r_anal_fcn_del_locs(RAnal *anal, ut64 addr) {
	RListIter *iter, *iter2;
	RAnalFunction *fcn, *f = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ROOT);
	if (!f) {
		return false;
	}
	r_list_foreach_safe (anal->fcns, iter, iter2, fcn) {
		if (fcn->type != R_ANAL_FCN_TYPE_LOC) {
			continue;
		}
		if (r_anal_fcn_in (fcn, addr)) {
			if (!r_anal_fcn_tree_delete (anal, fcn)) {
				return false;
			}
			r_list_delete (anal->fcns, iter);
		}
	}
	r_anal_fcn_del (anal, addr);
	return true;
}

R_API int r_anal_fcn_del(RAnal *a, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter, *iter_tmp;
	r_list_foreach_safe (a->fcns, iter, iter_tmp, fcni) {
		if (r_anal_fcn_in (fcni, addr) || fcni->addr == addr) {
			if (a->cb.on_fcn_delete) {
				a->cb.on_fcn_delete (a, a->user, fcni);
			}
			if (!r_anal_fcn_tree_delete (a, fcni)) {
				return false;
			}
			r_list_delete (a->fcns, iter);
		}
	}
	return true;
}

R_API RList *r_anal_get_fcn_in_list(RAnal *anal, ut64 addr, int type) {
	RList *list = r_list_newf (NULL);
	// Interval tree query
	RAnalFunction *fcn;
	FcnTreeIter it;
	fcn_tree_foreach_intersect (anal->fcn_tree, it, fcn, addr, addr + 1) {
		if (!type || (fcn && fcn->type & type)) {
			if (r_tinyrange_in (&fcn->bbr, addr) || fcn->addr == addr) {
				r_list_append (list, fcn);
			}
		}
	}
	return list;
}

R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type) {
#if 0
  // Linear scan
	RAnalFunction *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (r_tinyrange_in (&fcn->bbr, addr) || fcn->addr == addr) {
				ret = fcn;
				break;
			}
		}
	}
	return ret;

#else
	// Interval tree query
	RAnalFunction *fcn;
	FcnTreeIter it;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		return _fcn_addr_tree_find_addr (anal, addr);
	}
	fcn_tree_foreach_intersect (anal->fcn_tree, it, fcn, addr, addr + 1) {
		if (!type || (fcn && fcn->type & type)) {
			if (r_tinyrange_in (&fcn->bbr, addr) || fcn->addr == addr) {
				return fcn;
			}
		}
	}
	return NULL;
#endif
}

R_API bool r_anal_fcn_in(RAnalFunction *fcn, ut64 addr) {
	return fcn? r_tinyrange_in (&fcn->bbr, addr): false;
}

R_API RAnalFunction *r_anal_get_fcn_in_bounds(RAnal *anal, ut64 addr, int type) {
	RAnalFunction *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (r_anal_fcn_in (fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

R_API RAnalFunction *r_anal_fcn_find_name(RAnal *anal, const char *name) {
	RAnalFunction *fcn = NULL;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!strcmp (name, fcn->name)) {
			return fcn;
		}
	}
	return NULL;
}

/* rename RAnalFunctionBB.add() */
R_API bool r_anal_fcn_add_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, int type, RAnalDiff *diff) {
	RAnalBlock *bb = NULL, *bbi;
	RListIter *iter;
	bool mid = false;
	st64 n;
	if (size == 0) { // empty basic blocks allowed?
		eprintf ("Warning: empty basic block at 0x%08"PFMT64x" is not allowed. pending discussion.\n", addr);
		r_warn_if_reached ();
		return false;
	}
	if (size > anal->opt.bb_max_size) {
		eprintf ("Warning: can't allocate such big bb of %"PFMT64d" bytes at 0x%08"PFMT64x"\n", (st64)size, addr);
		r_warn_if_reached ();
		return false;
	}

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr) {
			bb = bbi;
			mid = false;
			break;
		}
		if ((addr > bbi->addr) && (addr < bbi->addr + bbi->size)) {
			mid = true;
		}
	}
	if (mid) {
		// eprintf ("Basic Block overlaps another one that should be shrunk\n");
		if (bbi) {
			/* shrink overlapped basic block */
			bbi->size = addr - (bbi->addr);
			r_anal_fcn_update_tinyrange_bbs (fcn);
		}
	}
// TODO fix this x86-ism
#if 1
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	if (is_x86) {
		if (bb) {
			r_list_delete_data (fcn->bbs, bb);
		}
		r_anal_fcn_invalidate_read_ahead_cache ();
		fcn_recurse (anal, fcn, addr, size, 1);
		r_anal_fcn_update_tinyrange_bbs (fcn);
		r_anal_fcn_set_size (anal, fcn, r_anal_fcn_size (fcn));
		bb = r_anal_fcn_bbget_at (fcn, addr);
		if (!bb) {
			if (fcn->addr == addr) {
				return true;
			}
			if (anal->verbose) {
				eprintf ("Warning: r_anal_fcn_add_bb failed in fcn 0x%08"PFMT64x" at 0x%08"PFMT64x"\n", fcn->addr, addr);
			}
			return false;
		}
	} else {
		if (!bb) {
			bb = appendBasicBlock (anal, fcn, addr);
			if (!bb) {
				eprintf ("appendBasicBlock failed\n");
				return false;
			}
		}
		bb->addr = addr;
	}
#else
	if (!bb) {
		bb = appendBasicBlock (anal, fcn, addr);
		if (!bb) {
			eprintf ("appendBasicBlock failed\n");
			return false;
		}
	}
	bb->addr = addr;
	r_anal_fcn_invalidate_read_ahead_cache ();
	fcn_recurse (anal, fcn, addr, size, 1);
	r_anal_fcn_update_tinyrange_bbs (fcn);
	r_anal_fcn_set_size (anal, fcn, r_anal_fcn_size (fcn));
#endif
	bb->size = size;
	bb->jump = jump;
	bb->fail = fail;
	bb->type = type;
	if (diff) {
		if (!bb->diff) {
			bb->diff = r_anal_diff_new ();
		}
		if (bb->diff) {
			bb->diff->type = diff->type;
			bb->diff->addr = diff->addr;
			if (diff->name) {
				R_FREE (bb->diff->name);
				bb->diff->name = strdup (diff->name);
			}
		}
	}
	r_anal_fcn_update_tinyrange_bbs (fcn);
	n = bb->addr + bb->size - fcn->addr;
	if (n >= 0 && r_anal_fcn_size (fcn) < n) {
		// If fcn is in anal->fcn_tree (which reflects anal->fcns), update fcn_tree because fcn->_size has changed.
		r_anal_fcn_set_size (anal, fcn, n);
	}
	return true;
}

// TODO: rename fcn_bb_split()
R_API int r_anal_fcn_split_bb(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bbi, ut64 addr) {
	int new_bbi_instr, i;
	r_return_val_if_fail (bbi && addr >= bbi->addr && addr < bbi->addr + bbi->size + 1, 0);
	if (addr == UT64_MAX) {
		return 0;
	}
	if (addr == bbi->addr) {
		return R_ANAL_RET_DUP;
	}
	RAnalBlock *bb = appendBasicBlock (anal, fcn, addr);
	if (bb) {
		bb->size = bbi->addr + bbi->size - addr;
		bb->jump = bbi->jump;
		bb->fail = bbi->fail;
		bb->conditional = bbi->conditional;
	}
	FITFCNSZ ();
	bbi->size = addr - bbi->addr;
	bbi->jump = addr;
	bbi->fail = -1;
	bbi->conditional = false;
	if (bbi->type & R_ANAL_BB_TYPE_HEAD) {
		bb->type = bbi->type ^ R_ANAL_BB_TYPE_HEAD;
		bbi->type = R_ANAL_BB_TYPE_HEAD;
	} else {
		bb->type = bbi->type;
		bbi->type = R_ANAL_BB_TYPE_BODY;
	}
	// recalculate offset of instructions in both bb and bbi
	i = 0;
	while (i < bbi->ninstr && r_anal_bb_offset_inst (bbi, i) < bbi->size) {
		i++;
	}
	new_bbi_instr = i;
	if (bb->addr - bbi->addr == r_anal_bb_offset_inst (bbi, i)) {
		bb->ninstr = 0;
		while (i < bbi->ninstr) {
			ut16 off_op = r_anal_bb_offset_inst (bbi, i);
			if (off_op >= bbi->size + bb->size) {
				break;
			}
			r_anal_bb_set_offset (bb, bb->ninstr, off_op - bbi->size);
			bb->ninstr++;
			i++;
		}
	}
	bbi->ninstr = new_bbi_instr;
	return R_ANAL_RET_END;
}

// TODO: rename fcn_bb_overlap()
R_API int r_anal_fcn_bb_overlaps(RAnalFunction *fcn, RAnalBlock *bb) {
	RAnalBlock *bbi;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, bbi) {
		if (bb->addr + bb->size > bbi->addr && bb->addr + bb->size <= bbi->addr + bbi->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			bb->conditional = false;
			if (bbi->type & R_ANAL_BB_TYPE_HEAD) {
				bb->type = R_ANAL_BB_TYPE_HEAD;
				bbi->type = bbi->type ^ R_ANAL_BB_TYPE_HEAD;
			} else {
				bb->type = R_ANAL_BB_TYPE_BODY;
			}
			r_list_append (fcn->bbs, bb);
			return R_ANAL_RET_END;
		}
	}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_fcn_loops(RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 loops = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops ++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops ++;
		}
	}
	return loops;
}

R_API int r_anal_fcn_cc(RAnal *anal, RAnalFunction *fcn) {
/*
        CC = E - N + 2P
        E = the number of edges of the graph.
        N = the number of nodes of the graph.
        P = the number of connected components (exit nodes).
 */
	int E = 0, N = 0, P = 0;
	RListIter *iter;
	RAnalBlock *bb;

	r_list_foreach (fcn->bbs, iter, bb) {
		N++; // nodes
		if ((!anal || anal->verbose) && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			eprintf ("Warning: invalid bb jump/fail pair at 0x%08"PFMT64x" (fcn 0x%08"PFMT64x"\n", bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->cases) { // dead code ?
			E += r_list_length (bb->cases);
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += r_list_length (bb->switch_op->cases);
		}
	}

	int result = E - N + (2 * P);
	if (result < 1 && (!anal || anal->verbose)) {
		eprintf ("Warning: CC = E(%d) - N(%d) + (2 * P(%d)) < 1 at 0x%08"PFMT64x"\n", E, N, P, fcn->addr);
	}
	// r_return_val_if_fail (result > 0, 0);
	return result;
}

R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFunction *fs) {
	return NULL;
}

/* set function signature from string */
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *sig) {
	r_return_val_if_fail (a || f || sig, false);
	char *error_msg = NULL;
	const char *out = r_parse_c_string (a, sig, &error_msg);
	if (out) {
		r_anal_save_parsed_type (a, out);
	}
	if (error_msg) {
		eprintf ("%s", error_msg);
		free (error_msg);
	}

	return true;
}

R_API RAnalFunction *r_anal_get_fcn_at(RAnal *anal, ut64 addr, int type) {
#if 0
	// Linear scan
	RAnalFunction *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn->type & type)) {
			if (addr == fcn->addr) {
				ret = fcn;
			}
		}
	}
	return ret;
#else
	// Interval tree query
	RAnalFunction *fcn;
	FcnTreeIter it;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		return _fcn_addr_tree_find_addr (anal, addr);
	}
	fcn_tree_foreach_intersect (anal->fcn_tree, it, fcn, addr, addr + 1) {
		if (!type || (fcn && fcn->type & type)) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
	}
	return NULL;
#endif
}

R_API RAnalFunction *r_anal_fcn_next(RAnal *anal, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter;
	RAnalFunction *closer = NULL;
	r_list_foreach (anal->fcns, iter, fcni) {
		// if (fcni->addr == addr)
		if (fcni->addr > addr && (!closer || fcni->addr < closer->addr)) {
			closer = fcni;
		}
	}
	return closer;
}

R_API int r_anal_fcn_is_in_offset(RAnalFunction *fcn, ut64 addr) {
	if (r_list_empty (fcn->bbs)) {
		// r_anal_fcn_size (fcn);
		return addr >= fcn->addr && addr < fcn->addr + fcn->_size;
	}
	if (r_anal_fcn_in (fcn, addr)) {
		return true;
	}
	return false;
}

R_API int r_anal_fcn_count(RAnal *anal, ut64 from, ut64 to) {
	int n = 0;
	RAnalFunction *fcni;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcni) {
		if (fcni->addr >= from && fcni->addr < to) {
			n++;
		}
	}
	return n;
}

/* return the basic block in fcn found at the given address.
 * NULL is returned if such basic block doesn't exist. */
R_API RAnalBlock *r_anal_fcn_bbget_in(const RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (anal && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr >= bb->addr && addr < (bb->addr + bb->size)
		    && (!anal->opt.jmpmid || !is_x86 || r_anal_bb_op_starts_at (bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

R_API RAnalBlock *r_anal_fcn_bbget_at(RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (fcn && addr != UT64_MAX, NULL);
#if USE_SDB_CACHE
	return sdb_ptr_get (HB, sdb_fmt (SDB_KEY_BB, fcn->addr, addr), NULL);
#else
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
#endif
}


R_API bool r_anal_fcn_bbadd(RAnalFunction *fcn, RAnalBlock *bb) {
#if USE_SDB_CACHE
	return sdb_ptr_set (HB, sdb_fmt (SDB_KEY_BB, fcn->addr, bb->addr), bb, NULL);
#endif
	r_list_append (fcn->bbs, bb);
	return true;
}


/* directly set the size of the function
 * if fcn is in ana RAnal's fcn_tree, the anal MUST be passed,
 * otherwise it can be NULL
 * IMPORTANT: this function should be removed, since it makes no sense to
 * change the size of a function independently of its basic blocks */
R_API void r_anal_fcn_set_size(RAnal *anal, RAnalFunction *fcn, ut32 size) {
	r_return_if_fail (fcn);
	fcn->_size = size;
	if (anal && r_anal_get_fcn_at (anal, fcn->addr, R_ANAL_FCN_TYPE_ROOT)) {
		_fcn_tree_update_size (anal, fcn);
	}
}

/* returns the size of the function.
 * IMPORTANT: this will change, one day, because it doesn't have much sense */
R_API ut32 r_anal_fcn_size(const RAnalFunction *fcn) {
	return fcn? fcn->_size: 0;
}

/* return the "real" size of the function, that is the sum of the size of the
 * basicblocks this function is composed of.
 * IMPORTANT: this will become, one day, the only size of a function */
R_API ut32 r_anal_fcn_realsize(const RAnalFunction *fcn) {
	RListIter *iter, *fiter;
	RAnalBlock *bb;
	RAnalFunction *f;
	ut32 sz = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		sz += bb->size;
	}
	r_list_foreach (fcn->fcn_locs, fiter, f) {
		r_list_foreach (f->bbs, iter, bb) {
			sz += bb->size;
		}
	}
	return sz;
}

// continious function size without loc.*
R_API ut32 r_anal_fcn_contsize(const RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 sz = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		/* TODO: this if is an ugly hack and should be removed when r2 will be
		* able to handle BBs that comes before the function emtry point.
		* Another way to remove this is to throw away BBs before the function
		* entry point at the analysis time in the r_anal_fcn.   */
		if (bb->addr >= fcn->addr) {
			sz += bb->size;
		}
	}
	return sz;
}

// compute the cyclomatic cost
R_API ut32 r_anal_fcn_cost(RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		RAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			memset (&op, 0, sizeof (op));
			(void) r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ANAL_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			r_anal_op_fini (&op);
		}
		free (buf);
	}
	return totalCycles;
}

R_API int r_anal_fcn_count_edges(const RAnalFunction *fcn, int *ebbs) {
	RListIter *iter;
	RAnalBlock *bb;
	int edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges ++;
			}
			if (bb->fail != UT64_MAX) {
				edges ++;
			}
		}
	}
	return edges;
}

R_API bool r_anal_fcn_get_purity(RAnal *anal, RAnalFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new (NULL, NULL, NULL);
		if (ht) {
			check_purity (ht, anal, fcn);
			ht_up_free (ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RAnal *anal, RAnalOp* op) {
	RAnalValue *dst = op->dst;
	RAnalValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = anal->reg->name[R_REG_NAME_BP];
	bool is_bp_dst = opdreg && !dst->memref && !strcmp (opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp (opsreg, bp_name);
	if (op->type == R_ANAL_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}
/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
R_API void r_anal_fcn_check_bp_use(RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	char str_to_find[40] = "\"type\":\"reg\",\"value\":\"";
	char *pos;
	strcat (str_to_find, anal->reg->name[R_REG_NAME_BP]);
	if (!fcn) {
		return;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		RAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_OPEX);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case R_ANAL_OP_TYPE_MOV:
				if (can_affect_bp (anal, &op) && op.src[0] && op.src[0]->reg && op.src[0]->reg->name
				&& strcmp (op.src[0]->reg->name, anal->reg->name[R_REG_NAME_SP])) {
					fcn->bp_frame = false;
				}
				break;
			case R_ANAL_OP_TYPE_LEA:
				if (can_affect_bp (anal, &op)) {
					fcn->bp_frame = false;
				}
				break;
			case R_ANAL_OP_TYPE_ADD:
			case R_ANAL_OP_TYPE_AND:
			case R_ANAL_OP_TYPE_CMOV:
			case R_ANAL_OP_TYPE_NOT:
			case R_ANAL_OP_TYPE_OR:
			case R_ANAL_OP_TYPE_ROL:
			case R_ANAL_OP_TYPE_ROR:
			case R_ANAL_OP_TYPE_SAL:
			case R_ANAL_OP_TYPE_SAR:
			case R_ANAL_OP_TYPE_SHR:
			case R_ANAL_OP_TYPE_SUB:
			case R_ANAL_OP_TYPE_XOR:
			case R_ANAL_OP_TYPE_SHL:
// op.dst is not filled for these operations, so for now, check for bp as dst looks like this; in the future it may be just replaced with call to can_affect_bp
 				pos = op.opex.ptr ? strstr (op.opex.ptr, str_to_find) : NULL;
				if (pos && pos - op.opex.ptr < 60) {
					fcn->bp_frame = false;
				}
				break;
			case R_ANAL_OP_TYPE_XCHG:
				if (op.opex.ptr && strstr (op.opex.ptr, str_to_find)) {
					fcn->bp_frame = false;
    				}
				break;
			case R_ANAL_OP_TYPE_POP:
				break;
			}
			idx += op.size;
			at += op.size;
			r_anal_op_fini (&op);
		}
		free (buf);
	}
}

R_API const char *r_anal_label_at(RAnal *a, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (fcn) {
		return r_anal_fcn_label_at (a, fcn, addr);
	}
	return NULL;
}
