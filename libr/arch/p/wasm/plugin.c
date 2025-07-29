/* radare2 - LGPL - Copyright 2017-2022 - pancake, xvilka, deroad */

#define R_LOG_ORIGIN "anal.wasm"

#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "wasm.h"
#include "wasm.c"

typedef struct wasm_cf_scope {
	ut64 addr, jump, fail;
	WasmOpCodes opcode;
	struct wasm_cf_scope *parent;
	union {
		struct wasm_cf_scope *sibling; // sibling used for `else` only
		ut32 val; // br/br_if only
	};
} CFScope;

typedef struct wasm_cf_info {
	ut64 jump, fail;
	ut32 type;
} CFInfo;

// finds the address of the call function (essentially where to jump to).
static inline ut64 get_func_offset(RArch *a, ut32 id, bool start) {
	if (a && a->binb.get_offset && a->binb.bin) {
		int type = start? 'F': 'e'; // find start or end
		return a->binb.get_offset (a->binb.bin, type, id);
	}
	return UT64_MAX;
}

static inline ut64 func_off_from_idx(RArch *a, ut32 id) {
	if (a && a->binb.get_offset && a->binb.bin) {
		return a->binb.get_offset (a->binb.bin, 'f', id);
	}
	return UT64_MAX;
}

static inline CFScope *parse_new_scope(RList *list, ut64 addr, WasmOp *wop, CFScope *prev) {
	CFScope *sc = R_NEW0 (CFScope);
	if (sc) {
		sc->opcode = wop->op.core;
		sc->addr = addr;
		sc->jump = addr + wop->len;
		sc->fail = UT64_MAX;
		sc->parent = prev;
		if (r_list_push (list, sc)) {
			return sc;
		}
		free (sc);
	}
	return NULL;
}

static inline bool parse_op_cf(RList *scopes, RList *keep, ut64 addr, WasmOp *wop, CFScope **cur) {
	if (wop->type != WASM_TYPE_OP_CORE) {
		return true;
	}
	CFScope *c = *cur;
	CFScope *sc;
	switch (wop->op.core) {
	// move to adjancent scope
	case WASM_OP_ELSE:
		if (!c || c->opcode != WASM_OP_IF) {
			R_LOG_WARN ("Ignoring `else` at 0x%" PFMT64x " without `if`", addr);
			sc = parse_new_scope (keep, addr, wop, NULL);
			if (!sc) {
				return false;
			}
			sc->jump = UT64_MAX; // dud
		} else {
			sc = parse_new_scope (keep, addr, wop, c->parent);
			if (!sc) {
				break;
			}
			// if and else are siblings
			sc->sibling = c;
			c->sibling = sc; // probably not needed
			*cur = sc;
		}
		break;

	// open scope, move deeper scope
	case WASM_OP_LOOP:
	case WASM_OP_BLOCK:
		sc = parse_new_scope (scopes, addr, wop, c);
		if (!sc) {
			return false;
		}
		*cur = sc;
		break;
	case WASM_OP_IF:
		sc = parse_new_scope (keep, addr, wop, c);
		if (!sc) {
			return false;
		}
		*cur = sc;
		break;

	// keeps current scope
	case WASM_OP_BR:
	case WASM_OP_BRIF:
		sc = parse_new_scope (keep, addr, wop, c);
		if (!sc) {
			return false;
		}
		sc->val = wop->val;
		break;

	// close scope, move up
	case WASM_OP_END:
		// close current scope and move up
		if (!c) {
			R_LOG_WARN ("Ignoring `end` at 0x%" PFMT64x " without opening", addr);
			sc = parse_new_scope (keep, addr, wop, NULL);
			if (!sc) {
				return false;
			}
			sc->jump = UT64_MAX; // dud
		} else {
			c->fail = addr;
			if (c->opcode == WASM_OP_ELSE && c->sibling) {
				c->sibling->fail = addr;
			}
			*cur = c->parent;
		}
		break;
	default:
		break;
	}
	return true;
}

static void inline find_br_scope(CFInfo *nfo, CFScope *sc) {
	ut32 i;
	CFScope *outer = sc;
	if (sc->val == UT32_MAX) {
		return;
	}
	// move up sc->val + 1 scopes
	for (i = 0; i <= sc->val; i++) {
		if (!outer) {
			const char *n = sc->opcode == WASM_OP_BRIF? "br_if": "br";
			R_LOG_WARN ("ignoring %s at 0x%" PFMT64x ", references non-existent address", n, sc->addr);
			return;
		}
		outer = outer->parent;
	}
	if (!outer) {
		const char *n = sc->opcode == WASM_OP_BRIF? "br_if": "br";
		R_LOG_WARN ("ignoring %s at 0x%" PFMT64x ", references non-existent address", n, sc->addr);
		return;
	}

	if (sc->opcode == WASM_OP_BRIF) {
		nfo->fail = sc->jump;
		nfo->type = R_ANAL_OP_TYPE_CJMP;
	} else {
		nfo->type = R_ANAL_OP_TYPE_JMP;
	}

	// depending on outer, br goes to different place
	switch (outer->opcode) {
	case WASM_OP_BLOCK:
	case WASM_OP_IF:
	case WASM_OP_ELSE:
		nfo->jump = outer->fail;
		break;
	case WASM_OP_LOOP:
		nfo->jump = outer->jump;
		break;
	default:
		R_LOG_ERROR ("Unexpected type: 0x%x", outer->opcode);
	}
}

static bool cache_dud(HtUP *cache, ut64 addr) {
	CFInfo *nfo = R_NEW (CFInfo);
	if (nfo) {
		nfo->jump = UT64_MAX;
		nfo->fail = UT64_MAX;
		nfo->type = R_ANAL_OP_TYPE_ILL;
		if (ht_up_insert (cache, addr, nfo)) {
			return true;
		}
		free (nfo);
	}
	return false;
}

static inline bool scope_to_cache(HtUP *cache, CFScope *sc) {
	if (sc->jump == UT64_MAX) {
		return cache_dud (cache, sc->addr);
	}
	CFInfo *nfo = R_NEW (CFInfo);
	nfo->jump = UT64_MAX;
	nfo->fail = UT64_MAX;
	if (nfo) {
		switch (sc->opcode) {
		case WASM_OP_IF:
			nfo->type = R_ANAL_OP_TYPE_CJMP;
			nfo->jump = sc->jump;
			nfo->fail = sc->fail;
			if (ht_up_insert (cache, sc->addr, nfo)) {
				return true;
			}
			break;
		case WASM_OP_ELSE:
			nfo->type = R_ANAL_OP_TYPE_NOP;
			nfo->jump = sc->jump;
			nfo->fail = sc->fail;
			if (ht_up_insert (cache, sc->addr, nfo)) {
				return true;
			}
			break;
		case WASM_OP_BR:
		case WASM_OP_BRIF:
			find_br_scope (nfo, sc);
			if (ht_up_insert (cache, sc->addr, nfo)) {
				return true;
			}
			break;
		default:
			break;
		}
		free (nfo);
	}
	return false;
}

// from a list of BR, BRIF, IF, ELSE, scopes find offsets
static inline bool cache_offsets(HtUP *cache, RList *keep) {
	RListIter *iter;
	CFScope *sc;
	r_list_foreach (keep, iter, sc) {
		if (!scope_to_cache (cache, sc)) {
			return false;
		}
	}
	return true;
}

static inline bool parse_control_flow(RArchSession *s, ut64 opaddr) {
	R_RETURN_VAL_IF_FAIL (s && s->arch, false);
	RArch *a = s->arch;
	RBin *bin = R_UNWRAP2 (a, binb.bin);
	if (!bin || !bin->iob.read_at) {
		return false;
	}
	RIOReadAt read_at = bin->iob.read_at;

	HtUP *cache = s->user;
	if (!cache) { // exit early if no cache,
		return false;
	}

	ut64 addr = get_func_offset (a, opaddr, true);
	ut64 end = get_func_offset (a, opaddr, false);
	if (addr == UT64_MAX || end == UT64_MAX) {
		return cache_dud (cache, opaddr);
	}

	ut32 len = end - addr;
	RList *scope = r_list_newf ((RListFree)free);
	RList *keep = r_list_newf ((RListFree)free);

	bool ret = false;
	if (!scope || !keep) {
		goto cleanup;
	}
	WasmOp wop = { { 0 } };
	wop.op.core = WASM_OP_BLOCK;
	// implicit block when new function starts
	CFScope *lastcf = parse_new_scope (scope, addr, &wop, NULL);

	if (lastcf && len) {
		ut8 buffer[16];
		ut8 *ptr = buffer;
		ut32 readsize = R_MIN (sizeof (buffer), len);

		// TODO: bigger and fewer reads to speed up
		while (readsize && read_at (bin->iob.io, addr, buffer, readsize)) {
			int size = wasm_dis (&wop, ptr, readsize, false);
			if (!parse_op_cf (scope, keep, addr, &wop, &lastcf)) {
				break;
			}
			addr += size;
			len -= size;
			if (len < sizeof (buffer)) {
				readsize = len;
			}
		}
		ret = cache_offsets (cache, keep);
	}
cleanup:
	r_list_free (scope);
	r_list_free (keep);
	return ret;
}

static inline ut64 get_end(RArch *a, ut64 addr) {
	if (a && a->binb.get_offset && a->binb.bin) {
		return a->binb.get_offset (a->binb.bin, 'e', addr);
	}
	return UT64_MAX;
}

static inline bool op_set_nfo(HtUP *c, RAnalOp *op) {
	CFInfo *nfo = ht_up_find (c, op->addr, NULL);
	if (nfo) {
		op->type = nfo->type;
		op->jump = nfo->jump;
		op->fail = nfo->fail;
		return true;
	}
	return false;
}

static void set_cf_info(RArchSession *s, RAnalOp *op) {
	// TODO: check if file has changed
	HtUP *cache = (HtUP *)s->user;
	R_RETURN_IF_FAIL (cache);

	if (!op_set_nfo (cache, op)) {
		if (parse_control_flow (s, op->addr)) {
			op_set_nfo (cache, op);
		}
	}
}

static bool wasm_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	int len = 56;
	ut8 *buf = malloc (len);
	if (buf) {
		// TODO: improve wasm_asm
		len = wasm_asm (op->mnemonic, buf, len);
		if (len > 0) {
			free (op->bytes);
			op->bytes = NULL;
			op->bytes = realloc (buf, len);
			if (op->bytes) {
				op->size = len;
				return true;
			}
			op->size = 0;
		}
		free (buf);
	}
	return false;
}

// analyzes the wasm opcode.
static bool wasm_decode(RArchSession *s, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (s && op, false);
	WasmOp wop = {{0}};
	const bool txt = mask & R_ARCH_OP_MASK_DISASM;
	int ret = wasm_dis (&wop, op->bytes, op->size, txt);

	op->mnemonic = wop.txt;
	wop.txt = NULL;

	if (txt && (!op->mnemonic || !strcmp (op->mnemonic, "invalid"))) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}

	op->nopcode = 1;
	op->sign = true; // XXX: Probably not always signed?
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		op->id = wop.op.core;
		break;
	case WASM_TYPE_OP_ATOMIC:
		op->id = (0xfe << 8) | wop.op.atomic;
		break;
	case WASM_TYPE_OP_SIMD:
		op->id = 0xfd;
		break;
	}

	switch (wop.type) {
	case WASM_TYPE_OP_CORE:
		switch (wop.op.core) {
		/* Calls here are using index instead of address */
		case WASM_OP_LOOP:
		case WASM_OP_BLOCK:
			// op->type = R_ANAL_OP_TYPE_NOP; // acts as a label, BR will escape it
			break;
		case WASM_OP_ELSE:
		case WASM_OP_BR:
		case WASM_OP_IF:
		case WASM_OP_BRIF:
			set_cf_info (s, op);
			break;
		case WASM_OP_END:
			op->type = R_ANAL_OP_TYPE_NOP;
			op->eob = true;
			if (op->addr != UT64_MAX && get_end (s->arch, op->addr) == op->addr) {
				op->type = R_ANAL_OP_TYPE_RET;
			}
			break;
		case WASM_OP_RETURN:
			// should be ret, but if there the analisys is stopped.
			op->jump = get_end (s->arch, op->addr);
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case WASM_OP_I32REMS:
		case WASM_OP_I32REMU:
			op->type = R_ANAL_OP_TYPE_MOD;
			break;
		case WASM_OP_TRAP:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case WASM_OP_GETLOCAL:
		case WASM_OP_I32LOAD:
		case WASM_OP_I64LOAD:
		case WASM_OP_F32LOAD:
		case WASM_OP_F64LOAD:
		case WASM_OP_I32LOAD8S:
		case WASM_OP_I32LOAD8U:
		case WASM_OP_I32LOAD16S:
		case WASM_OP_I32LOAD16U:
		case WASM_OP_I64LOAD8S:
		case WASM_OP_I64LOAD8U:
		case WASM_OP_I64LOAD16S:
		case WASM_OP_I64LOAD16U:
		case WASM_OP_I64LOAD32S:
		case WASM_OP_I64LOAD32U:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case WASM_OP_SETLOCAL:
		case WASM_OP_TEELOCAL:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case WASM_OP_I32EQZ:
		case WASM_OP_I32EQ:
		case WASM_OP_I32NE:
		case WASM_OP_I32LTS:
		case WASM_OP_I32LTU:
		case WASM_OP_I32GTS:
		case WASM_OP_I32GTU:
		case WASM_OP_I32LES:
		case WASM_OP_I32LEU:
		case WASM_OP_I32GES:
		case WASM_OP_I32GEU:
		case WASM_OP_I64EQZ:
		case WASM_OP_I64EQ:
		case WASM_OP_I64NE:
		case WASM_OP_I64LTS:
		case WASM_OP_I64LTU:
		case WASM_OP_I64GTS:
		case WASM_OP_I64GTU:
		case WASM_OP_I64LES:
		case WASM_OP_I64LEU:
		case WASM_OP_I64GES:
		case WASM_OP_I64GEU:
		case WASM_OP_F32EQ:
		case WASM_OP_F32NE:
		case WASM_OP_F32LT:
		case WASM_OP_F32GT:
		case WASM_OP_F32LE:
		case WASM_OP_F32GE:
		case WASM_OP_F64EQ:
		case WASM_OP_F64NE:
		case WASM_OP_F64LT:
		case WASM_OP_F64GT:
		case WASM_OP_F64LE:
		case WASM_OP_F64GE:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case WASM_OP_I64OR:
		case WASM_OP_I32OR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case WASM_OP_I64XOR:
		case WASM_OP_I32XOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case WASM_OP_I32CONST:
		case WASM_OP_I64CONST:
		case WASM_OP_F32CONST:
		case WASM_OP_F64CONST:
			op->type = R_ANAL_OP_TYPE_MOV;
			if (op->size > 1) {
				ut8 arg = op->bytes[1];
				r_strbuf_setf (&op->esil, "4,sp,-=,%d,sp,=[4]", arg);
			}
			break;
		case WASM_OP_I64ADD:
		case WASM_OP_I32ADD:
		case WASM_OP_F32ADD:
		case WASM_OP_F64ADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case WASM_OP_I64SUB:
		case WASM_OP_I32SUB:
		case WASM_OP_F32SUB:
		case WASM_OP_F64SUB:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case WASM_OP_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			r_strbuf_setf (&op->esil, "%s", "");
			break;
		case WASM_OP_CALL:
		case WASM_OP_CALLINDIRECT: // XXX: I Don't think this is right
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = func_off_from_idx (s->arch, wop.val);
			op->fail = op->addr + op->size;
			if (op->jump != UT64_MAX) {
				op->ptr = op->jump;
			}
			r_strbuf_setf (&op->esil, "4,sp,-=,0x%"PFMT64x",sp,=[4],0x%"PFMT64x",pc,=", op->fail, op->jump);
			break;
		default:
			break;
		}
		break;
	case WASM_TYPE_OP_ATOMIC:
		switch (wop.op.atomic) {
		case WASM_OP_I32ATOMICLOAD:
		case WASM_OP_I64ATOMICLOAD:
		case WASM_OP_I32ATOMICLOAD8U:
		case WASM_OP_I32ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD8U:
		case WASM_OP_I64ATOMICLOAD16U:
		case WASM_OP_I64ATOMICLOAD32U:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case WASM_OP_I32ATOMICSTORE:
		case WASM_OP_I64ATOMICSTORE:
		case WASM_OP_I32ATOMICSTORE8:
		case WASM_OP_I32ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE8:
		case WASM_OP_I64ATOMICSTORE16:
		case WASM_OP_I64ATOMICSTORE32:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case WASM_OP_I32ATOMICRMWADD:
		case WASM_OP_I64ATOMICRMWADD:
		case WASM_OP_I32ATOMICRMW8UADD:
		case WASM_OP_I32ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW8UADD:
		case WASM_OP_I64ATOMICRMW16UADD:
		case WASM_OP_I64ATOMICRMW32UADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case WASM_OP_I32ATOMICRMW8USUB:
		case WASM_OP_I32ATOMICRMW16USUB:
		case WASM_OP_I32ATOMICRMWSUB:
		case WASM_OP_I64ATOMICRMW8USUB:
		case WASM_OP_I64ATOMICRMW16USUB:
		case WASM_OP_I64ATOMICRMW32USUB:
		case WASM_OP_I64ATOMICRMWSUB:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case WASM_OP_I32ATOMICRMWAND:
		case WASM_OP_I64ATOMICRMWAND:
		case WASM_OP_I32ATOMICRMW8UAND:
		case WASM_OP_I32ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW8UAND:
		case WASM_OP_I64ATOMICRMW16UAND:
		case WASM_OP_I64ATOMICRMW32UAND:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case WASM_OP_I32ATOMICRMWOR:
		case WASM_OP_I64ATOMICRMWOR:
		case WASM_OP_I32ATOMICRMW8UOR:
		case WASM_OP_I32ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW8UOR:
		case WASM_OP_I64ATOMICRMW16UOR:
		case WASM_OP_I64ATOMICRMW32UOR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case WASM_OP_I32ATOMICRMWXOR:
		case WASM_OP_I64ATOMICRMWXOR:
		case WASM_OP_I32ATOMICRMW8UXOR:
		case WASM_OP_I32ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW8UXOR:
		case WASM_OP_I64ATOMICRMW16UXOR:
		case WASM_OP_I64ATOMICRMW32UXOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case WASM_OP_I32ATOMICRMWXCHG:
		case WASM_OP_I64ATOMICRMWXCHG:
		case WASM_OP_I32ATOMICRMW8UXCHG:
		case WASM_OP_I32ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW8UXCHG:
		case WASM_OP_I64ATOMICRMW16UXCHG:
		case WASM_OP_I64ATOMICRMW32UXCHG:
			op->type = R_ANAL_OP_TYPE_XCHG;
			break;
		default:
			break;
		}
	default:
		break;
	}
	op->size = ret;
	return ret > 0;
}

#if 0
static int archinfo(RAnal *a, int q) {
	return 1;
}
#endif

static char *wasm_regs(RArchSession *ai) {
	return strdup (
		"=PC	pc\n"
		"=BP	bp\n"
		"=SP	sp\n"
		"=SN	r0\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"gpr	sp	.32	0	0\n" // stack pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	bp	.32	8	0\n" // base pointer // unused
	);
}

static void _kv_free(HtUPKv *kv) {
	free (kv->value);
}

static bool cache_new(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	s->user = ht_up_new (NULL, _kv_free, NULL);
	return s->user? true: false;
}

static bool cache_clean(RArchSession *s) {
	ht_up_free ((HtUP *)s->user);
	s->user = NULL;
	return true;
}

const RArchPlugin r_arch_plugin_wasm = {
	.meta = {
		.name = "wasm",
		.author = "pancake,xvilka,condret",
		.desc = "WebAssembly bytecode",
		.license = "LGPL-3.0-only",
	},
	.arch = "wasm",
	.bits = R_SYS_BITS_PACK2 (32,64),
	.regs = wasm_regs,
	.decode = wasm_decode,
	.encode = wasm_encode,
	.init = cache_new,
	.fini = cache_clean,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_wasm,
	.version = R2_VERSION
};
#endif
