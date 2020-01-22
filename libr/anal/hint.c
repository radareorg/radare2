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
	R_ANAL_HINT_TYPE_BITS,
	R_ANAL_HINT_TYPE_NEW_BITS,
	R_ANAL_HINT_TYPE_SIZE,
	R_ANAL_HINT_TYPE_SYNTAX,
	R_ANAL_HINT_TYPE_OPTYPE,
	R_ANAL_HINT_TYPE_OPCODE,
	R_ANAL_HINT_TYPE_TYPE_OFFSET,
	R_ANAL_HINT_TYPE_ESIL,
	R_ANAL_HINT_TYPE_ARCH,
	R_ANAL_HINT_TYPE_HIGH,
	R_ANAL_HINT_TYPE_VAL
} RAnalHintType;

typedef struct r_anal_hint_record_t {
	RAnalHintType type;
	union {
		char *type_offset;
		int nword;
		ut64 jump;
		ut64 fail;
		int newbits;
		int immbase;
		ut64 ptr;
		ut64 retval;
		char *arch;
		char *syntax;
		char *opcode;
		char *esil;
		int optype;
		int bits;
		ut64 size;
		ut64 stackframe;
		ut64 val;
	};
} RAnalHintRecord;

#define setf(x,...) snprintf(x,sizeof(x)-1,##__VA_ARGS__)

static RAnalHintRecord *hint_record_new(RAnalHintType type) {
	RAnalHintRecord *r = R_NEW0 (RAnalHintRecord);
	if (!r) {
		return NULL;
	}
	r->type = type;
	return r;
}

static void hint_record_free(RAnalHintRecord *record) {
	if (!record) {
		return;
	}
	free (record);
	switch (record->type) {
	case R_ANAL_HINT_TYPE_TYPE_OFFSET:
		free (record->type_offset);
		break;
	case R_ANAL_HINT_TYPE_ARCH:
		free (record->arch);
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

// used in anal.c, but no API needed
void r_anal_hint_tree_init(RAnal *a) {
	r_interval_tree_init (&a->hints, (RIntervalNodeFree)hint_record_free);
}

// used in anal.c, but no API needed
void r_anal_hint_tree_fini(RAnal *a) {
	r_interval_tree_fini (&a->hints);
}

R_API void r_anal_hint_clear(RAnal *a) {
	r_anal_hint_tree_fini (a);
	r_anal_hint_tree_init (a);
}

static void interval_tree_list(RIntervalNode *node, void *user) {
	RList *r = user;
	r_list_push (r, user);
}

R_API void r_anal_hint_del(RAnal *a, ut64 addr, ut64 size) {
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
}

static void unset_hint(RAnal *anal, RAnalHintType type, ut64 addr) {
	// TODO
}

static void set_hint(RAnal *anal, RAnalHintRecord *record, ut64 addr, ut64 size) {
	ut64 end = size == 0 ? addr : addr + size - 1;
	// TODO: resolve dups
	r_interval_tree_insert (&anal->hints, addr, end, record);
}

#define SET_HINT_RANGE(type, size, setcode) do { \
	RAnalHintRecord *r = hint_record_new (R_ANAL_HINT_TYPE_TYPE_OFFSET); \
	if (!r) { \
		break; \
	} \
	setcode \
	set_hint (a, r, addr, size); \
} while(0)

#define SET_HINT(type, setcode) SET_HINT_RANGE(type, 0, setcode)

R_API void r_anal_hint_set_offset(RAnal *a, ut64 addr, const char *typeoff) {
	SET_HINT (R_ANAL_HINT_TYPE_TYPE_OFFSET, r->type_offset = strdup (typeoff););
	//setHint (a, "Offset:", addr, r_str_trim_ro (typeoff), 0);
}

R_API void r_anal_hint_set_nword(RAnal *a, ut64 addr, int nword) {
	SET_HINT (R_ANAL_HINT_TYPE_NWORD, r->nword = nword;);
	//setHint (a, "nword:", addr, NULL, nword);
}

R_API void r_anal_hint_set_jump(RAnal *a, ut64 addr, ut64 jump) {
	SET_HINT (R_ANAL_HINT_TYPE_JUMP, r->jump = jump;);
	//setHint (a, "jump:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_newbits(RAnal *a, ut64 addr, int bits) {
	SET_HINT (R_ANAL_HINT_TYPE_NEW_BITS, r->newbits = bits;);
	//setHint (a, "Bits:", addr, NULL, bits);
}

// TODO: add helpers for newendian and newbank

R_API void r_anal_hint_set_fail(RAnal *a, ut64 addr, ut64 fail) {
	SET_HINT (R_ANAL_HINT_TYPE_FAIL, r->fail = fail;);
	//setHint (a, "fail:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_high(RAnal *a, ut64 addr) {
	SET_HINT (R_ANAL_HINT_TYPE_HIGH,);
	//setHint (a, "high:", addr, NULL, 1);
}

R_API void r_anal_hint_set_immbase(RAnal *a, ut64 addr, int base) {
	if (base) {
		SET_HINT (R_ANAL_HINT_TYPE_IMMBASE, r->immbase = base;);
		//setHint (a, "immbase:", addr, NULL, (ut64)base);
	} else {
		unset_hint (a, R_ANAL_HINT_TYPE_IMMBASE, addr);
		//unsetHint (a, "immbase:", addr);
	}
}

R_API void r_anal_hint_set_pointer(RAnal *a, ut64 addr, ut64 ptr) {
	SET_HINT (R_ANAL_HINT_TYPE_PTR, r->ptr = ptr;);
	//setHint (a, "ptr:", addr, NULL, ptr);
}

R_API void r_anal_hint_set_ret(RAnal *a, ut64 addr, ut64 val) {
	SET_HINT (R_ANAL_HINT_TYPE_RET, r->retval = val;);
	//setHint (a, "ret:", addr, NULL, val);
}

R_API void r_anal_hint_set_arch(RAnal *a, ut64 addr, const char *arch) {
	SET_HINT (R_ANAL_HINT_TYPE_ARCH, r->arch = strdup (arch););
	//setHint (a, "arch:", addr, r_str_trim_ro (arch), 0);
}

R_API void r_anal_hint_set_syntax(RAnal *a, ut64 addr, const char *syn) {
	SET_HINT (R_ANAL_HINT_TYPE_SYNTAX, r->syntax = strdup (syn););
	//setHint (a, "Syntax:", addr, syn, 0);
}

R_API void r_anal_hint_set_opcode(RAnal *a, ut64 addr, const char *opcode) {
	SET_HINT (R_ANAL_HINT_TYPE_OPCODE, r->opcode = strdup (opcode););
	//setHint (a, "opcode:", addr, r_str_trim_ro (opcode), 0);
}

R_API void r_anal_hint_set_esil(RAnal *a, ut64 addr, const char *esil) {
	SET_HINT (R_ANAL_HINT_TYPE_ESIL, r->esil = strdup (esil););
	//setHint (a, "esil:", addr, r_str_trim_ro (esil), 0);
}

R_API void r_anal_hint_set_type (RAnal *a, ut64 addr, int type) {
	SET_HINT (R_ANAL_HINT_TYPE_OPTYPE, r->type = type;);
	//setHint (a, "type:", addr, NULL, (ut64)type);
}

R_API void r_anal_hint_set_bits(RAnal *a, ut64 addr, ut64 size, int bits) {
	SET_HINT_RANGE (R_ANAL_HINT_TYPE_BITS, size, r->bits = bits;);
	//setHint (a, "bits:", addr, NULL, bits);
	if (a && a->hint_cbs.on_bits) {
		a->hint_cbs.on_bits (a, addr, bits, true);
	}
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

R_API void r_anal_hint_unset_size(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_SIZE, addr);
	//unsetHint(a, "size:", addr);
}

R_API void r_anal_hint_unset_bits(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_BITS, addr);
	//unsetHint(a, "bits:", addr);
	if (a && a->hint_cbs.on_bits) {
		a->hint_cbs.on_bits (a, addr, 0, false);
	}
}

R_API void r_anal_hint_unset_esil(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_ESIL, addr);
	//unsetHint(a, "esil:", addr);
}

R_API void r_anal_hint_unset_opcode(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_OPCODE, addr);
	//unsetHint(a, "opcode:", addr);
}

R_API void r_anal_hint_unset_high(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_HIGH, addr);
	//unsetHint(a, "high:", addr);
}

R_API void r_anal_hint_unset_arch(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_ARCH, addr);
	//unsetHint(a, "arch:", addr);
}

R_API void r_anal_hint_unset_nword(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_NWORD, addr);
	//unsetHint(a, "nword:", addr);
}

R_API void r_anal_hint_unset_syntax(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_SYNTAX, addr);
	//unsetHint(a, "Syntax:", addr);
}

R_API void r_anal_hint_unset_pointer(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_PTR, addr);
	//unsetHint(a, "ptr:", addr);
}

R_API void r_anal_hint_unset_ret(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_RET, addr);
	//unsetHint(a, "ret:", addr);
}

R_API void r_anal_hint_unset_offset(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_TYPE_OFFSET, addr);
	//unsetHint (a, "Offset:", addr);
}

R_API void r_anal_hint_unset_jump(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_JUMP, addr);
	//unsetHint (a, "jump:", addr);
}

R_API void r_anal_hint_unset_fail(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_FAIL, addr);
	//unsetHint (a, "fail:", addr);
}

R_API void r_anal_hint_unset_val (RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_VAL, addr);
	//unsetHint (a, "val:", v);
}

R_API void r_anal_hint_unset_type (RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_OPTYPE, addr);
	//unsetHint (a, "type:", addr);
}

R_API void r_anal_hint_unset_stackframe(RAnal *a, ut64 addr) {
	unset_hint (a, R_ANAL_HINT_TYPE_STACKFRAME, addr);
	//unsetHint (a, "Frame:", addr);
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

static void hint_merge(RAnalHint *hint, RAnalHintRecord *record) {
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
	case R_ANAL_HINT_TYPE_BITS:
		hint->bits = record->bits;
		break;
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
	case R_ANAL_HINT_TYPE_ARCH:
		hint->arch = record->arch ? strdup (record->arch) : NULL;
		break;
	case R_ANAL_HINT_TYPE_HIGH:
		hint->high = true;
		break;
	case R_ANAL_HINT_TYPE_VAL:
		hint->val = record->val;
		break;
	}
}

static void hint_get_cb(RIntervalNode *node, void *user) {
	hint_merge (user, node->data);
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
	r_interval_tree_all_in (&a->hints, addr, true, hint_get_cb, hint);
	return hint;
}

typedef struct {
	int bits;
	const char *arch;
} ArchBitsCtx;

static void arch_bits_cb(RIntervalNode *node, void *user) {
	ArchBitsCtx *ctx = user;
	RAnalHintRecord *record = node->data;
	switch (record->type) {
	case R_ANAL_HINT_TYPE_BITS:
		ctx->bits = record->bits;
		break;
	case R_ANAL_HINT_TYPE_ARCH:
		ctx->arch = record->arch;
		break;
	default:
		break;
	}
}

R_API void r_anal_hint_arch_bits_at(RAnal *a, ut64 addr, R_OUT R_NULLABLE int *bits, R_OUT R_BORROW R_NULLABLE const char **arch) {
	if (!bits && !arch) {
		return;
	}
	ArchBitsCtx ctx = { 0 };
	r_interval_tree_all_in (&a->hints, addr, true, arch_bits_cb, &ctx);
	if (bits) {
		*bits = ctx.bits;
	}
	if (arch) {
		*arch = ctx.arch;
	}
}
