/* radare - LGPL - Copyright 2013-2023 - pancake */

#include <r_anal.h>

// Common base-struct for hints which affect an entire range as opposed to only one single address
// They are saved in a RBTree per hint type.
// Each ranged record in a tree affects every address address greater or equal to its specified address until
// the next record or the end of the address space.
typedef struct r_anal_ranged_hint_record_base_t {
	RBNode rb;
	ut64 addr;
} RAnalRangedHintRecordBase;

typedef struct r_anal_arch_hint_record_t {
	RAnalRangedHintRecordBase base; // MUST be the first member!
	char *arch; // NULL => reset to global
} RAnalArchHintRecord;

typedef struct r_anal_bits_hint_record_t {
	RAnalRangedHintRecordBase base; // MUST be the first member!
	int bits; // 0 => reset to global
} RAnalBitsHintRecord;

static int ranged_hint_record_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 addr = *(const ut64 *)incoming;
	const RAnalRangedHintRecordBase *in_tree_record = container_of (in_tree, const RAnalRangedHintRecordBase, rb);
	if (addr < in_tree_record->addr) {
		return -1;
	} else if (addr > in_tree_record->addr) {
		return 1;
	}
	return 0;
}

static void addr_hint_record_fini(void *element, void *user) {
	(void)user;
	RAnalAddrHintRecord *record = element;
	switch (record->type) {
	case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
		free (record->type_offset);
		break;
	case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
		free (record->syntax);
		break;
	case R_ANAL_ADDR_HINT_TYPE_OPCODE:
		free (record->opcode);
		break;
	case R_ANAL_ADDR_HINT_TYPE_ESIL:
		free (record->esil);
		break;
	default:
		break;
	}
}

static void addr_hint_record_vec_clear(RVecAnalAddrHintRecord *records) {
	RAnalAddrHintRecord *record;
	R_VEC_FOREACH (records, record) {
		addr_hint_record_fini (record, NULL);
	}
	RVecAnalAddrHintRecord_clear (records);
}

static void addr_hint_record_vec_free(RVecAnalAddrHintRecord *records) {
	if (records) {
		addr_hint_record_vec_clear (records);
		RVecAnalAddrHintRecord_free (records);
	}
}

static void addr_hint_record_ht_free(HtUPKv *kv) {
	addr_hint_record_vec_free (kv->value);
}

static void bits_hint_record_free_rb(RBNode *node, void *user) {
	free (container_of (node, RAnalRangedHintRecordBase, rb));
}

static void arch_hint_record_free_rb(RBNode *node, void *user) {
	if (node) {
		RAnalArchHintRecord *record = (RAnalArchHintRecord *)container_of (node, RAnalRangedHintRecordBase, rb);
		if (record) {
			free (record->arch);
			free (record);
		}
	}
}

// used in anal.c, but no API needed
void r_anal_hint_storage_init(RAnal *a) {
	a->addr_hints = ht_up_new (NULL, addr_hint_record_ht_free, NULL);
	a->arch_hints = NULL;
	a->bits_hints = NULL;
}

// used in anal.c, but no API needed
void r_anal_hint_storage_fini(RAnal *a) {
	ht_up_free (a->addr_hints);
	r_rbtree_free (a->arch_hints, arch_hint_record_free_rb, NULL);
	r_rbtree_free (a->bits_hints, bits_hint_record_free_rb, NULL);
}

// R2_590 - add argument to specify the type of hint to remove
R_API void r_anal_hint_clear(RAnal *a) {
	r_anal_hint_storage_fini (a);
	r_anal_hint_storage_init (a);
}

typedef struct {
	HtUP *ht;
	ut64 addr;
	ut64 size;
} DeleteRangeCtx;

static bool addr_hint_range_delete_cb(void *user, const ut64 key, const void *value) {
	DeleteRangeCtx *ctx = user;
	if (key < ctx->addr || key >= ctx->addr + ctx->size) {
		return true;
	}
	ht_up_delete (ctx->ht, key);
	return true;
}

R_API void r_anal_hint_del(RAnal *a, ut64 addr, ut64 size) {
	if (size <= 1) {
		// only single address
		ht_up_delete (a->addr_hints, addr);
		r_anal_hint_unset_arch (a, addr);
		r_anal_hint_unset_bits (a, addr);
		return;
	}
	// ranged delete
	DeleteRangeCtx ctx = { a->addr_hints, addr, size };
	ht_up_foreach (a->addr_hints, addr_hint_range_delete_cb, &ctx);
	while (true) { // arch
		RBNode *node = r_rbtree_lower_bound (a->arch_hints, &addr, ranged_hint_record_cmp, NULL);
		if (!node) {
			return;
		}
		RAnalRangedHintRecordBase *base = container_of (node, RAnalRangedHintRecordBase, rb);
		if (base->addr >= addr + size) {
			break;
		}
		r_anal_hint_unset_arch (a, base->addr);
	}
	while (true) { // bits
		RBNode *node = r_rbtree_lower_bound (a->bits_hints, &addr, ranged_hint_record_cmp, NULL);
		if (!node) {
			return;
		}
		RAnalRangedHintRecordBase *base = container_of (node, RAnalRangedHintRecordBase, rb);
		if (base->addr >= addr + size) {
			break;
		}
		r_anal_hint_unset_bits (a, base->addr);
	}
}

static void unset_addr_hint_record(RAnal *anal, RAnalAddrHintType type, ut64 addr) {
	RVecAnalAddrHintRecord *records = ht_up_find (anal->addr_hints, addr, NULL);
	if (!records) {
		return;
	}
	size_t i;
	for (i = 0; i < RVecAnalAddrHintRecord_length (records); i++) {
		RAnalAddrHintRecord *record = RVecAnalAddrHintRecord_at (records, i);
		if (record->type == type) {
			addr_hint_record_fini (record, NULL);
			RVecAnalAddrHintRecord_remove (records, i);
			return;
		}
	}
}

// create or return the existing addr hint record of the given type at addr
static RAnalAddrHintRecord *ensure_addr_hint_record(RAnal *anal, RAnalAddrHintType type, ut64 addr) {
	RVecAnalAddrHintRecord *records = ht_up_find (anal->addr_hints, addr, NULL);
	if (!records) {
		records = RVecAnalAddrHintRecord_new ();
		if (!records) {
			return NULL;
		}
		ht_up_insert (anal->addr_hints, addr, records);
	}
	RAnalAddrHintRecord *pos;
	R_VEC_FOREACH (records, pos) {
		RAnalAddrHintRecord *record = pos;
		if (record->type == type) {
			return record;
		}
	}
	RAnalAddrHintRecord *record = RVecAnalAddrHintRecord_emplace_back (records);
	if (record) {
		memset (record, 0, sizeof (*record));
		record->type = type;
	}
	return record;
}

#define SET_HINT(type, setcode) do { \
	RAnalAddrHintRecord *r = ensure_addr_hint_record (a, type, addr); \
	if (!r) { \
		break; \
	} \
	setcode \
} while (0)

static RAnalRangedHintRecordBase *ensure_ranged_hint_record(RBTree *tree, ut64 addr, size_t sz) {
	RBNode *node = r_rbtree_find (*tree, &addr, ranged_hint_record_cmp, NULL);
	if (node) {
		return container_of (node, RAnalRangedHintRecordBase, rb);
	}
	RAnalRangedHintRecordBase *record = calloc (sz, 1);
	if (record) {
		record->addr = addr;
		r_rbtree_insert (tree, &addr, &record->rb, ranged_hint_record_cmp, NULL);
	}
	return record;
}

R_API void r_anal_hint_set_offset(RAnal *a, ut64 addr, const char *typeoff) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET,
		free (r->type_offset);
		r->type_offset = strdup (typeoff);
	);
}

R_API void r_anal_hint_set_nword(RAnal *a, ut64 addr, int nword) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_NWORD, r->nword = nword;);
}

R_API void r_anal_hint_set_jump(RAnal *a, ut64 addr, ut64 jump) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_JUMP, r->jump = jump;);
}

R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 fail) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_FAIL, r->fail = fail;);
}

R_API void r_anal_hint_set_newbits(RAnal *a, ut64 addr, int bits) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_NEW_BITS, r->newbits = bits;);
}

R_API void r_anal_hint_set_high(RAnal *a, ut64 addr) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_HIGH,);
}

R_API void r_anal_hint_set_immbase(RAnal *a, ut64 addr, int base) {
	if (base) {
		SET_HINT (R_ANAL_ADDR_HINT_TYPE_IMMBASE, r->immbase = base;);
	} else {
		unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_IMMBASE, addr);
	}
}

R_API void r_anal_hint_set_pointer(RAnal *a, ut64 addr, ut64 ptr) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_PTR, r->ptr = ptr;);
}

R_API void r_anal_hint_set_ret(RAnal *a, ut64 addr, ut64 val) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_RET, r->retval = val;);
}

R_API void r_anal_hint_set_syntax(RAnal *a, ut64 addr, const char *syn) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_SYNTAX,
			  free (r->syntax);
		r->syntax = strdup (syn);
	);
}

R_API void r_anal_hint_set_opcode(RAnal *a, ut64 addr, const char *opcode) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_OPCODE,
			  free (r->opcode);
		r->opcode = strdup (opcode);
	);
}

R_API void r_anal_hint_set_esil(RAnal *a, ut64 addr, const char *esil) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_ESIL,
			  free (r->esil);
		r->esil = strdup (esil);
	);
}

R_API void r_anal_hint_set_type(RAnal *a, ut64 addr, int type) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_OPTYPE, r->optype = type;);
}

R_API void r_anal_hint_set_size(RAnal *a, ut64 addr, ut64 size) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_SIZE, r->size = size;);
}

R_API void r_anal_hint_set_stackframe(RAnal *a, ut64 addr, ut64 size) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_STACKFRAME, r->stackframe = size;);
}

R_API void r_anal_hint_set_val(RAnal *a, ut64 addr, ut64 v) {
	SET_HINT (R_ANAL_ADDR_HINT_TYPE_VAL, r->val = v;);
}

R_API void r_anal_hint_set_arch(RAnal *a, ut64 addr, const char *arch) {
	RAnalArchHintRecord *record = (RAnalArchHintRecord *)ensure_ranged_hint_record (&a->arch_hints, addr, sizeof (RAnalArchHintRecord));
	if (!record) {
		return;
	}
	free (record->arch);
	record->arch = arch ? strdup (arch) : NULL;
}

R_API void r_anal_hint_set_bits(RAnal *a, ut64 addr, int bits) {
	RAnalBitsHintRecord *record = (RAnalBitsHintRecord *)ensure_ranged_hint_record (&a->bits_hints, addr, sizeof (RAnalBitsHintRecord));
	if (record) {
		record->bits = bits;
		if (a->hint_cbs.on_bits) {
			a->hint_cbs.on_bits (a, addr, bits, true);
		}
	}
}

R_API void r_anal_hint_unset_size(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_SIZE, addr);
}

R_API void r_anal_hint_unset_esil(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_ESIL, addr);
}

R_API void r_anal_hint_unset_opcode(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_OPCODE, addr);
}

R_API void r_anal_hint_unset_high(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_HIGH, addr);
}

R_API void r_anal_hint_unset_immbase(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_IMMBASE, addr);
}

R_API void r_anal_hint_unset_nword(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_NWORD, addr);
}

R_API void r_anal_hint_unset_syntax(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_SYNTAX, addr);
}

R_API void r_anal_hint_unset_pointer(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_PTR, addr);
}

R_API void r_anal_hint_unset_ret(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_RET, addr);
}

R_API void r_anal_hint_unset_offset(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET, addr);
}

R_API void r_anal_hint_unset_jump(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_JUMP, addr);
}

R_API void r_anal_hint_unset_fail(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_FAIL, addr);
}

R_API void r_anal_hint_unset_newbits(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_NEW_BITS, addr);
}

R_API void r_anal_hint_unset_val(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_VAL, addr);
}

R_API void r_anal_hint_unset_type(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_OPTYPE, addr);
}

R_API void r_anal_hint_unset_stackframe(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_ADDR_HINT_TYPE_STACKFRAME, addr);
}

R_API void r_anal_hint_unset_arch(RAnal *a, ut64 addr) {
	r_rbtree_delete (&a->arch_hints, &addr, ranged_hint_record_cmp, NULL, arch_hint_record_free_rb, NULL);
}

HEAPTYPE (ut64);

static bool filter_hints(ut64 addr, int bits, void *user) {
	RList *list = (RList *)user;
	r_list_append (list, ut64_new (addr));
	return true;
}

R_API void r_anal_hint_unset_bits(RAnal *a, ut64 addr) {
	if (addr == UT64_MAX) {
		// delete all bits hints
		RList *list = r_list_newf (free);
		r_anal_bits_hints_foreach (a, filter_hints, list);
		ut64 *n;
		RListIter *iter;
		r_list_foreach (list, iter, n) {
			ut64 addr = *n;
			r_rbtree_delete (&a->bits_hints, &addr, ranged_hint_record_cmp, NULL, bits_hint_record_free_rb, NULL);
		}
		r_list_free (list);
		// delete all bits
	} else {
		r_rbtree_delete (&a->bits_hints, &addr, ranged_hint_record_cmp, NULL, bits_hint_record_free_rb, NULL);
	}
}

R_API void r_anal_hint_free(RAnalHint *h) {
	if (h) {
		free (h->arch);
		free (h->esil);
		free (h->opcode);
		free (h->syntax);
		free (h->offset);
		free (h);
	}
}

R_API R_BORROW const char * R_NULLABLE r_anal_hint_arch_at(RAnal *anal, ut64 addr, ut64 * R_NULLABLE hint_addr) {
	RBNode *node = r_rbtree_upper_bound (anal->arch_hints, &addr, ranged_hint_record_cmp, NULL);
	if (R_LIKELY (node)) {
		RAnalArchHintRecord *record = (RAnalArchHintRecord *)container_of (node, RAnalRangedHintRecordBase, rb);
		if (hint_addr) {
			*hint_addr = record->base.addr;
		}
		return record->arch;
	}
	if (hint_addr) {
		*hint_addr = UT64_MAX;
	}
	return NULL;
}

R_API int r_anal_hint_bits_at(RAnal *anal, ut64 addr, ut64 * R_NULLABLE hint_addr) {
	RBNode *node = r_rbtree_upper_bound (anal->bits_hints, &addr, ranged_hint_record_cmp, NULL);
	if (!node) {
		if (hint_addr) {
			*hint_addr = UT64_MAX;
		}
		return 0;
	}
	RAnalBitsHintRecord *record = (RAnalBitsHintRecord *)container_of (node, RAnalRangedHintRecordBase, rb);
	if (hint_addr) {
		*hint_addr = record->base.addr;
	}
	return record->bits;
}

R_API const RVecAnalAddrHintRecord * R_NULLABLE r_anal_addr_hints_at(RAnal *anal, ut64 addr) {
	return ht_up_find (anal->addr_hints, addr, NULL);
}

typedef struct {
	RAnalAddrHintRecordsCb cb;
	void *user;
} AddrHintForeachCtx;

static bool addr_hint_foreach_cb(void *user, const ut64 key, const void *value) {
	AddrHintForeachCtx *ctx = user;
	return ctx->cb (key, value, ctx->user);
}

R_API void r_anal_addr_hints_foreach(RAnal *anal, RAnalAddrHintRecordsCb cb, void *user) {
	AddrHintForeachCtx ctx = { cb, user };
	ht_up_foreach (anal->addr_hints, addr_hint_foreach_cb, &ctx);
}

R_API void r_anal_arch_hints_foreach(RAnal *anal, RAnalArchHintCb cb, void *user) {
	RBIter iter;
	RAnalRangedHintRecordBase *record;
	r_rbtree_foreach (anal->arch_hints, iter, record, RAnalRangedHintRecordBase, rb) {
		bool cont = cb (record->addr, ((RAnalArchHintRecord *)record)->arch, user);
		if (!cont) {
			break;
		}
	}
}

R_API void r_anal_bits_hints_foreach(RAnal *anal, RAnalBitsHintCb cb, void *user) {
	RBIter iter;
	RAnalRangedHintRecordBase *record;
	r_rbtree_foreach (anal->bits_hints, iter, record, RAnalRangedHintRecordBase, rb) {
		bool cont = cb (record->addr, ((RAnalBitsHintRecord *)record)->bits, user);
		if (!cont) {
			break;
		}
	}
}

static void hint_merge(RAnalHint *hint, RAnalAddrHintRecord *record) {
	switch (record->type) {
	case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
		hint->immbase = record->immbase;
		break;
	case R_ANAL_ADDR_HINT_TYPE_JUMP:
		hint->jump = record->jump;
		break;
	case R_ANAL_ADDR_HINT_TYPE_FAIL:
		hint->fail = record->fail;
		break;
	case R_ANAL_ADDR_HINT_TYPE_STACKFRAME:
		hint->stackframe = record->stackframe;
		break;
	case R_ANAL_ADDR_HINT_TYPE_PTR:
		hint->ptr = record->ptr;
		break;
	case R_ANAL_ADDR_HINT_TYPE_NWORD:
		hint->nword = record->nword;
		break;
	case R_ANAL_ADDR_HINT_TYPE_RET:
		hint->ret = record->retval;
		break;
	case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
		hint->new_bits = record->newbits;
		break;
	case R_ANAL_ADDR_HINT_TYPE_SIZE:
		hint->size = record->size;
		break;
	case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
		hint->syntax = record->syntax ? strdup (record->syntax) : NULL;
		break;
	case R_ANAL_ADDR_HINT_TYPE_OPTYPE:
		hint->type = record->optype;
		break;
	case R_ANAL_ADDR_HINT_TYPE_OPCODE:
		hint->opcode = record->opcode ? strdup (record->opcode) : NULL;
		break;
	case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
		hint->offset = record->type_offset ? strdup (record->type_offset) : NULL;
		break;
	case R_ANAL_ADDR_HINT_TYPE_ESIL:
		hint->esil = record->esil ? strdup (record->esil) : NULL;
		break;
	case R_ANAL_ADDR_HINT_TYPE_HIGH:
		hint->high = true;
		break;
	case R_ANAL_ADDR_HINT_TYPE_VAL:
		hint->val = record->val;
		break;
	}
}

R_API RAnalHint *r_anal_hint_get(RAnal *a, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (a, NULL);
	const char *arch = r_anal_hint_arch_at (a, addr, NULL);
	const int bits = r_anal_hint_bits_at (a, addr, NULL);
	const RVecAnalAddrHintRecord *records = r_anal_addr_hints_at (a, addr);
	if ((!records || RVecAnalAddrHintRecord_empty (records)) && !arch && !bits) {
		// no hints found
		return NULL;
	}

	RAnalHint *hint = R_NEW0 (RAnalHint);
	hint->addr = addr;
	hint->jump = UT64_MAX;
	hint->fail = UT64_MAX;
	hint->ret = UT64_MAX;
	hint->val = UT64_MAX;
	// hint->ptr = UT64_MAX; some test fail. ptr 0 should be valid if we do it properly
	hint->stackframe = UT64_MAX;
	if (records) {
		RAnalAddrHintRecord *record;
		R_VEC_FOREACH (records, record) {
			hint_merge (hint, record);
		}
	}
	hint->arch = arch ? strdup (arch) : NULL;
	hint->bits = bits;
	return hint;
}
