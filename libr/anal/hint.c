/* radare - LGPL - Copyright 2013-2019 - pancake */

#include <r_anal.h>

typedef enum r_anal_hint_type_t {
	R_ANAL_HINT_TYPE_IMMBASE,
	R_ANAL_HINT_TYPE_JUMP,
	R_ANAL_HINT_TYPE_FAIL,
	R_ANAL_HINT_TYPE_STACKFRAME,
	R_ANAL_HINT_TYPE_PTR,
	R_ANAL_HINT_TYPE_NWORD,
	R_ANAL_HINT_TYPE_RET,
	//R_ANAL_HINT_TYPE_BITS,
	R_ANAL_HINT_TYPE_NEW_BITS,
	R_ANAL_HINT_TYPE_SIZE,
	R_ANAL_HINT_TYPE_SYNTAX,
	R_ANAL_HINT_TYPE_OPTYPE,
	R_ANAL_HINT_TYPE_OPCODE,
	R_ANAL_HINT_TYPE_TYPE_OFFSET,
	R_ANAL_HINT_TYPE_ESIL,
	//R_ANAL_HINT_TYPE_ARCH,
	R_ANAL_HINT_TYPE_HIGH,
	R_ANAL_HINT_TYPE_VAL
} RAnalAddrHintType;

typedef struct r_anal_addr_hint_record_t {
	RAnalAddrHintType type;
	union {
		char *type_offset;
		int nword;
		ut64 jump;
		ut64 fail;
		int newbits;
		int immbase;
		ut64 ptr;
		ut64 retval;
		//char *arch;
		char *syntax;
		char *opcode;
		char *esil;
		int optype;
		//int bits;
		ut64 size;
		ut64 stackframe;
		ut64 val;
	};
} RAnalAddrHintRecord;

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
	case R_ANAL_HINT_TYPE_TYPE_OFFSET:
		free (record->type_offset);
		break;
	case R_ANAL_HINT_TYPE_SYNTAX:
		free (record->syntax);
		break;
	case R_ANAL_HINT_TYPE_OPCODE:
		free (record->opcode);
		break;
	case R_ANAL_HINT_TYPE_ESIL:
		free (record->esil);
		break;
	default:
		break;
	}
}

static void addr_hint_record_ht_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

static void ranged_hint_record_free(RBNode *node, void *user) {
	free (container_of (node, RAnalRangedHintRecordBase, rb));
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
	r_rbtree_free (a->arch_hints, ranged_hint_record_free, NULL);
	r_rbtree_free (a->bits_hints, ranged_hint_record_free, NULL);
}

R_API void r_anal_hint_clear(RAnal *a) {
	r_anal_hint_storage_fini (a);
	r_anal_hint_storage_init (a);
}

static void interval_tree_list(RIntervalNode *node, void *user) {
	RList *r = user;
	r_list_push (r, user);
}

R_API void r_anal_hint_del(RAnal *a, ut64 addr, ut64 size) {
#if 0 // TODO
	RList *candidates = r_list_new ();
	if (!candidates) {
		return;
	}
	ut64 end = addr + (size ? size -1 : 0);
	if (size > 1) {
		r_interval_tree_all_intersect (&a->hints, addr, end, true, interval_tree_list, candidates);
	} else {
		r_interval_tree_all_at (&a->hints, addr, interval_tree_list, candidates);
	}
	RListIter *it;
	RIntervalNode *node;
	r_list_foreach (candidates, it, node) {
		if (node->start >= addr && node->end <= end) {
			r_interval_tree_delete (&a->hints, node, true);
		}
	}
	r_list_free (candidates);
#endif
}

static void unset_addr_hint_record(RAnal *anal, RAnalAddrHintType type, ut64 addr) {
	RVector *records = ht_up_find (anal->addr_hints, addr, NULL);
	if (!records) {
		return;
	}
	size_t i;
	for (i = 0; i < records->len; i++) {
		RAnalAddrHintRecord *record = r_vector_index_ptr (records, i);
		if (record->type == type) {
			addr_hint_record_fini (record, NULL);
			r_vector_remove_at (records, i, NULL);
			return;
		}
	}
}

// create or return the existing addr hint record of the given type at addr
static RAnalAddrHintRecord *ensure_addr_hint_record(RAnal *anal, RAnalAddrHintType type, ut64 addr) {
	RVector *records = ht_up_find (anal->addr_hints, addr, NULL);
	if (!records) {
		records = r_vector_new (sizeof (RAnalAddrHintRecord), addr_hint_record_fini, NULL);
		if (!records) {
			return NULL;
		}
		ht_up_insert (anal->addr_hints, addr, records);
	}
	void *pos;
	r_vector_foreach (records, pos) {
		RAnalAddrHintRecord *record = pos;
		if (record->type == type) {
			return record;
		}
	}
	RAnalAddrHintRecord *record = r_vector_push (records, NULL);
	memset (record, 0, sizeof (*record));
	record->type = type;
	return record;
}

#define SET_HINT(type, setcode) do { \
	RAnalAddrHintRecord *r = ensure_addr_hint_record (a, type, addr); \
	if (!r) { \
		break; \
	} \
	setcode \
} while(0)

static void unset_ranged_hint_record(RBTree *tree, ut64 addr) {
	r_rbtree_delete (tree, &addr, ranged_hint_record_cmp, NULL, ranged_hint_record_free, NULL);
}

static RAnalRangedHintRecordBase *ensure_ranged_hint_record(RBTree *tree, ut64 addr, size_t sz) {
	RBNode *node = r_rbtree_find (*tree, &addr, ranged_hint_record_cmp, NULL);
	if (node) {
		return container_of (node, RAnalRangedHintRecordBase, rb);
	}
	RAnalRangedHintRecordBase *record = malloc (sz);
	memset (record, 0, sz);
	if (!record) {
		return NULL;
	}
	record->addr = addr;
	r_rbtree_insert (tree, &addr, &record->rb, ranged_hint_record_cmp, NULL);
	return record;
}

R_API void r_anal_hint_set_offset(RAnal *a, ut64 addr, const char *typeoff) {
	SET_HINT (R_ANAL_HINT_TYPE_TYPE_OFFSET,
		free (r->type_offset);
		r->type_offset = strdup (typeoff);
	);
}

R_API void r_anal_hint_set_nword(RAnal *a, ut64 addr, int nword) {
	SET_HINT (R_ANAL_HINT_TYPE_NWORD, r->nword = nword;);
}

R_API void r_anal_hint_set_jump(RAnal *a, ut64 addr, ut64 jump) {
	SET_HINT (R_ANAL_HINT_TYPE_JUMP, r->jump = jump;);
}

R_API void r_anal_hint_set_newbits(RAnal *a, ut64 addr, int bits) {
	SET_HINT (R_ANAL_HINT_TYPE_NEW_BITS, r->newbits = bits;);
}

// TODO: add helpers for newendian and newbank

R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 fail) {
	SET_HINT (R_ANAL_HINT_TYPE_FAIL, r->fail = fail;);
}

R_API void r_anal_hint_set_high(RAnal *a, ut64 addr) {
	SET_HINT (R_ANAL_HINT_TYPE_HIGH,);
}

R_API void r_anal_hint_set_immbase(RAnal *a, ut64 addr, int base) {
	if (base) {
		SET_HINT (R_ANAL_HINT_TYPE_IMMBASE, r->immbase = base;);
	} else {
		unset_addr_hint_record (a, R_ANAL_HINT_TYPE_IMMBASE, addr);
	}
}

R_API void r_anal_hint_set_pointer(RAnal *a, ut64 addr, ut64 ptr) {
	SET_HINT (R_ANAL_HINT_TYPE_PTR, r->ptr = ptr;);
}

R_API void r_anal_hint_set_ret(RAnal *a, ut64 addr, ut64 val) {
	SET_HINT (R_ANAL_HINT_TYPE_RET, r->retval = val;);
}

R_API void r_anal_hint_set_syntax(RAnal *a, ut64 addr, const char *syn) {
	SET_HINT (R_ANAL_HINT_TYPE_SYNTAX,
		free (r->syntax);
		r->syntax = strdup (syn);
	);
	//setHint (a, "Syntax:", addr, syn, 0);
}

R_API void r_anal_hint_set_opcode(RAnal *a, ut64 addr, const char *opcode) {
	SET_HINT (R_ANAL_HINT_TYPE_OPCODE,
		free (r->opcode);
		r->opcode = strdup (opcode);
	);
	//setHint (a, "opcode:", addr, r_str_trim_ro (opcode), 0);
}

R_API void r_anal_hint_set_esil(RAnal *a, ut64 addr, const char *esil) {
	SET_HINT (R_ANAL_HINT_TYPE_ESIL,
		free (r->esil);
		r->esil = strdup (esil);
	);
	//setHint (a, "esil:", addr, r_str_trim_ro (esil), 0);
}

R_API void r_anal_hint_set_type (RAnal *a, ut64 addr, int type) {
	SET_HINT (R_ANAL_HINT_TYPE_OPTYPE, r->type = type;);
	//setHint (a, "type:", addr, NULL, (ut64)type);
}

R_API void r_anal_hint_set_size(RAnal *a, ut64 addr, ut64 size) {
	SET_HINT (R_ANAL_HINT_TYPE_SIZE, r->size = size;);
	//setHint (a, "size:", addr, NULL, size);
}

R_API void r_anal_hint_set_stackframe(RAnal *a, ut64 addr, ut64 size) {
	SET_HINT (R_ANAL_HINT_TYPE_STACKFRAME, r->stackframe = size;);
	//setHint (a, "Frame:", addr, NULL, size);
}

R_API void r_anal_hint_set_val(RAnal *a, ut64 addr, ut64 v) {
	SET_HINT (R_ANAL_HINT_TYPE_VAL, r->val = v;);
	//setHint (a, "val:", addr, NULL, v);
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
	if (!record) {
		return;
	}
	record->bits = bits;
	if (a->hint_cbs.on_bits) {
		a->hint_cbs.on_bits (a, addr, bits, true);
	}
}

R_API void r_anal_hint_unset_size(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_SIZE, addr);
	//unsetHint(a, "size:", addr);
}

R_API void r_anal_hint_unset_esil(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_ESIL, addr);
	//unsetHint(a, "esil:", addr);
}

R_API void r_anal_hint_unset_opcode(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_OPCODE, addr);
	//unsetHint(a, "opcode:", addr);
}

R_API void r_anal_hint_unset_high(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_HIGH, addr);
	//unsetHint(a, "high:", addr);
}

R_API void r_anal_hint_unset_nword(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_NWORD, addr);
	//unsetHint(a, "nword:", addr);
}

R_API void r_anal_hint_unset_syntax(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_SYNTAX, addr);
	//unsetHint(a, "Syntax:", addr);
}

R_API void r_anal_hint_unset_pointer(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_PTR, addr);
	//unsetHint(a, "ptr:", addr);
}

R_API void r_anal_hint_unset_ret(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_RET, addr);
	//unsetHint(a, "ret:", addr);
}

R_API void r_anal_hint_unset_offset(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_TYPE_OFFSET, addr);
	//unsetHint (a, "Offset:", addr);
}

R_API void r_anal_hint_unset_jump(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_JUMP, addr);
	//unsetHint (a, "jump:", addr);
}

R_API void r_anal_hint_unset_fail(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_FAIL, addr);
	//unsetHint (a, "fail:", addr);
}

R_API void r_anal_hint_unset_val (RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_VAL, addr);
	//unsetHint (a, "val:", v);
}

R_API void r_anal_hint_unset_type (RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_OPTYPE, addr);
	//unsetHint (a, "type:", addr);
}

R_API void r_anal_hint_unset_stackframe(RAnal *a, ut64 addr) {
	unset_addr_hint_record (a, R_ANAL_HINT_TYPE_STACKFRAME, addr);
	//unsetHint (a, "Frame:", addr);
}

R_API void r_anal_hint_unset_arch(RAnal *a, ut64 addr) {
	unset_ranged_hint_record(&a->arch_hints, addr);
}

R_API void r_anal_hint_unset_bits(RAnal *a, ut64 addr) {
	unset_ranged_hint_record(&a->bits_hints, addr);
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

#if 0
// TODO: missing to_string ()
R_API RAnalHint *r_anal_hint_from_string(RAnal *a, ut64 addr, const char *str) {
	char *r, *nxt, *nxt2;
	int token = 0;
	RAnalHint *hint = R_NEW0 (RAnalHint);
	if (!hint) {
		return NULL;
	}
	hint->jump = UT64_MAX;
	hint->fail = UT64_MAX;
	hint->ret = UT64_MAX;
	hint->val = UT64_MAX;
	hint->stackframe = UT64_MAX;
	char *s = strdup (str);
	if (!s) {
		free (hint);
		return NULL;
	}
	hint->addr = addr;
	token = *s;
	for (r = s; ; r = nxt2) {
		r = sdb_anext (r, &nxt);
		if (!nxt) {
			break;
		}
		sdb_anext (nxt, &nxt2); // tokenize value
		if (token) {
			switch (token) {
			case 'i': hint->immbase = sdb_atoi (nxt); break;
			case 'j': hint->jump = sdb_atoi (nxt); break;
			case 'f': hint->fail = sdb_atoi (nxt); break;
			case 'F': hint->stackframe = sdb_atoi (nxt); break;
			case 'p': hint->ptr = sdb_atoi (nxt); break;
			case 'n': hint->nword = sdb_atoi (nxt); break;
			case 'r': hint->ret = sdb_atoi (nxt); break;
			case 'b': hint->bits = sdb_atoi (nxt); break;
			case 'B': hint->new_bits = sdb_atoi (nxt); break;
			case 's': hint->size = sdb_atoi (nxt); break;
			case 'S': hint->syntax = (char*)sdb_decode (nxt, 0); break;
			case 't': hint->type = r_num_get (NULL, nxt);  break;
			case 'o': hint->opcode = (char*)sdb_decode (nxt, 0); break;
			case 'O': hint->offset = (char*)sdb_decode (nxt, 0); break;
			case 'e': hint->esil = (char*)sdb_decode (nxt, 0); break;
			case 'a': hint->arch = (char*)sdb_decode (nxt, 0); break;
			case 'h': hint->high = sdb_atoi (nxt); break;
			case 'v': hint->val = sdb_atoi (nxt); break;
			}
		}
		if (!nxt || !nxt2) {
			break;
		}
		token = *nxt2;
	}
	free (s);
	return hint;
}
#endif

static void hint_merge(RAnalHint *hint, RAnalAddrHintRecord *record) {
	switch (record->type) {
	case R_ANAL_HINT_TYPE_IMMBASE:
		hint->immbase = record->immbase;
		break;
	case R_ANAL_HINT_TYPE_JUMP:
		hint->jump = record->jump;
		break;
	case R_ANAL_HINT_TYPE_FAIL:
		hint->fail = record->fail;
		break;
	case R_ANAL_HINT_TYPE_STACKFRAME:
		hint->stackframe = record->stackframe;
		break;
	case R_ANAL_HINT_TYPE_PTR:
		hint->ptr = record->ptr;
		break;
	case R_ANAL_HINT_TYPE_NWORD:
		hint->nword = record->nword;
		break;
	case R_ANAL_HINT_TYPE_RET:
		hint->ret = record->retval;
		break;
// TODO	case R_ANAL_HINT_TYPE_BITS:
// TODO		hint->bits = record->bits;
// TODO		break;
	case R_ANAL_HINT_TYPE_NEW_BITS:
		hint->new_bits = record->newbits;
		break;
	case R_ANAL_HINT_TYPE_SIZE:
		hint->size = record->size;
		break;
	case R_ANAL_HINT_TYPE_SYNTAX:
		hint->syntax = record->syntax ? strdup (record->syntax) : NULL;
		break;
	case R_ANAL_HINT_TYPE_OPTYPE:
		hint->type = record->optype;
		break;
	case R_ANAL_HINT_TYPE_OPCODE:
		hint->opcode = record->opcode ? strdup (record->opcode) : NULL;
		break;
	case R_ANAL_HINT_TYPE_TYPE_OFFSET:
		hint->offset = record->type_offset ? strdup (record->type_offset) : NULL;
		break;
	case R_ANAL_HINT_TYPE_ESIL:
		hint->esil = record->esil ? strdup (record->esil) : NULL;
		break;
// TODO	case R_ANAL_HINT_TYPE_ARCH:
// TODO		hint->arch = record->arch ? strdup (record->arch) : NULL;
// TODO		break;
	case R_ANAL_HINT_TYPE_HIGH:
		hint->high = true;
		break;
	case R_ANAL_HINT_TYPE_VAL:
		hint->val = record->val;
		break;
	}
}

R_API RAnalHint *r_anal_hint_get(RAnal *a, ut64 addr) {
	RAnalHint *hint = R_NEW0 (RAnalHint);
	if (!hint) {
		return NULL;
	}
	hint->jump = UT64_MAX;
	hint->fail = UT64_MAX;
	hint->ret = UT64_MAX;
	hint->val = UT64_MAX;
	hint->stackframe = UT64_MAX;
	RVector *records = ht_up_find (a->addr_hints, addr, NULL);
	if (records) {
		RAnalAddrHintRecord *record;
		r_vector_foreach (records, record) {
			hint_merge (hint, record);
		}
	}
	// TODO: arch, bits
	return hint;
}

typedef struct {
	int bits;
	const char *arch;
} ArchBitsCtx;

static void arch_bits_cb(RIntervalNode *node, void *user) {
	ArchBitsCtx *ctx = user;
	RAnalAddrHintRecord *record = node->data;
//	switch (record->type) {
//	case R_ANAL_HINT_TYPE_BITS:
//		ctx->bits = record->bits;
//		break;
//	case R_ANAL_HINT_TYPE_ARCH:
//		ctx->arch = record->arch;
//		break;
//	default:
//		break;
//	}
}

R_API void r_anal_hint_arch_bits_at(RAnal *a, ut64 addr, R_OUT R_NULLABLE int *bits, R_OUT R_BORROW R_NULLABLE const char **arch) {
	if (!bits && !arch) {
		return;
	}
	ArchBitsCtx ctx = { 0 };
	//r_interval_tree_all_in (&a->hints, addr, true, arch_bits_cb, &ctx);
	if (bits) {
		*bits = ctx.bits;
	}
	if (arch) {
		*arch = ctx.arch;
	}
}
