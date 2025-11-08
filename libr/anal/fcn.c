/* radare - LGPL - Copyright 2010-2025 - nibble, alvaro, pancake */

#define R_LOG_ORIGIN "fcn"

#include <r_anal.h>
#include <r_core.h>
#include <r_vec.h>

#define READ_AHEAD 1
#define SDB_KEY_BB "bb.0x%"PFMT64x ".0x%"PFMT64x
// XXX must be configurable by the user
#define JMPTBLSZ 512
#define JMPTBL_LEA_SEARCH_SZ 64
#define JMPTBL_MAXFCNSIZE 4096
#define R_ANAL_MAX_INCSTACK 8096
#define BB_ALIGN 0x10
#define MAX_SCAN_SIZE 0x7ffffff

/* speedup analysis by removing some function overlapping checks */
#define JAYRO_04 1

#define FIX_JMP_FWD 0
#define D if (a->verbose)

// 64KB max size
// 256KB max function size
#define MAX_FCN_SIZE (1024 * 256)

// Max NOP count to stop analysis
#define MAX_NOP_PREFIX_CNT 1024

#define DB a->sdb_fcns
#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);

R_VEC_TYPE (RVecAnalRef, RAnalRef);

R_API const char *r_anal_functiontype_tostring(int type) {
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

typedef struct {
	ut8 cache[1024];
	ut64 cache_addr;
} ReadAhead;

// TODO: move into io :?
static int read_ahead(ReadAhead *ra, RAnal *anal, ut64 addr, ut8 *buf, int len) {
	const size_t cache_len = sizeof (ra->cache);
	if (len < 1) {
		return -1;
	}
	bool is_cached = false;
#if READ_AHEAD
	if (ra->cache_addr != UT64_MAX && addr >= ra->cache_addr && addr < ra->cache_addr + sizeof (ra->cache)) {
		ut64 addr_end = UT64_ADD_OVFCHK (addr, len)? UT64_MAX: addr + len;
		ut64 cache_addr_end = UT64_ADD_OVFCHK (ra->cache_addr, cache_len)? UT64_MAX: ra->cache_addr + cache_len;
		is_cached = ((addr != UT64_MAX) && (addr >= ra->cache_addr) && (addr_end < cache_addr_end));
	}
#endif
	if (!is_cached) {
		if (len > sizeof (ra->cache)) {
			len = sizeof (ra->cache);
		}
		(void)anal->iob.read_at (anal->iob.io, addr, ra->cache, sizeof (ra->cache));
		ra->cache_addr = addr;
	}
	int delta = addr - ra->cache_addr;
	R_RETURN_VAL_IF_FAIL (delta >= 0, -1);
	size_t length = sizeof (ra->cache) - delta;
	memcpy (buf, ra->cache + delta, R_MIN (len, length));
	return len;
}

R_API int r_anal_function_resize(RAnalFunction *fcn, int newsize) {
	RAnal *anal = fcn->anal;
	RAnalBlock *bb;
	RListIter *iter, *iter2;

	R_RETURN_VAL_IF_FAIL (fcn, false);

	if (newsize < 1) {
		return false;
	}

	// XXX this is something we should probably do for all the archs
	const char *sarch = R_UNWRAP5 (anal, arch, session, config, arch);
	const bool is_arm = sarch && r_str_startswith (sarch, "arm");
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;
	r_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		if (bb->addr >= eof) {
			r_anal_function_remove_block (fcn, bb);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			r_anal_block_set_size (bb, eof - bb->addr);
			r_anal_block_update_hash (bb);
		}
		if (bb->jump != UT64_MAX && bb->jump >= eof) {
			bb->jump = UT64_MAX;
		}
		if (bb->fail != UT64_MAX && bb->fail >= eof) {
			bb->fail = UT64_MAX;
		}
	}
	return true;
}

// Create a new 0-sized basic block inside the function
static RAnalBlock *fcn_append_basic_block(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	RAnalBlock *bb = r_anal_create_block (anal, addr, 0);
	if (bb) {
		r_anal_function_add_block (fcn, bb);
		bb->stackptr = fcn->stack;
		bb->parent_stackptr = fcn->stack;
	}
	return bb;
}

#define gotoBeach(x) ret = x; goto beach;

static bool is_invalid_memory(RAnal *anal, const ut8 *buf, int len) {
	if (len > 8) {
		if (!memcmp (buf, "\x00\x00\x00\x00\x00\x00\x00\x00", R_MIN (len, 8))) {
			const char *arch = R_UNWRAP3 (anal, config, arch);
			if (arch) {
				if (anal->config->bits == 16 && !strcmp (arch, "x86")) {
					return true;
				}
				if (!strcmp (arch, "java") || !strcmp (arch, "riscv")) {
					return true;
				}
			}
		}
	}
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

static bool is_symbol_flag(const char *name) {
	return strstr (name, "imp.")
		|| strstr (name, "dbg.")
		// implicit in sym. || r_str_startswith (name, "rsym.")
		|| strstr (name, "sym.")
		|| r_str_startswith (name, "entry")
		|| !strcmp (name, "main");
}

static bool next_instruction_is_symbol(RAnal *anal, RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (anal && op && anal->flb.get_at, false);
	RFlagItem *fi = anal->flb.get_at (anal->flb.f, op->addr + op->size, false);
	return (fi && fi->name && is_symbol_flag (fi->name));
}

static bool is_delta_pointer_table(ReadAhead *ra, RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, ut64 *casetbl_addr, RAnalOp *jmp_aop) {
	int i;
	ut64 dst;
	st32 jmptbl[64] = {0};
	/* check if current instruction is followed by an ujmp */
	ut8 buf[JMPTBL_LEA_SEARCH_SZ];
	RAnalOp *aop = jmp_aop;
	RAnalOp omov_aop = {0};
	RAnalOp mov_aop = {0};
	RAnalOp add_aop = {0};
	const char *reg_src = NULL;
	const char *o_reg_dst = NULL;
	RAnalValue cur_scr, cur_dst = {0};
	read_ahead (ra, anal, addr, (ut8*)buf, sizeof (buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
		int len = r_anal_op (anal, aop, at, buf + i, left, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_VAL);
		if (len < 1) {
			len = 1;
		}
		if (aop->type == R_ANAL_OP_TYPE_UJMP || aop->type == R_ANAL_OP_TYPE_RJMP) {
			isValid = true;
			r_anal_op_fini (aop);
			break;
		}
		if (aop->type == R_ANAL_OP_TYPE_JMP || aop->type == R_ANAL_OP_TYPE_CJMP) {
			r_anal_op_fini (aop);
			break;
		}
		if (aop->type == R_ANAL_OP_TYPE_MOV) {
			omov_aop = mov_aop;
			mov_aop = *aop;
			o_reg_dst = cur_dst.reg;
			RAnalValue *rval = NULL;
			rval = r_vector_at (&mov_aop.dsts, 0);
			if (rval) {
				cur_dst = *rval;
			}
			rval = r_vector_at (&mov_aop.srcs, 0);
			if (rval) {
				cur_scr = *rval;
				reg_src = cur_scr.regdelta;
			}
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
	// mov reg2, dword [reg1 + tbl_off*4 + tbl_loc_off]
	// add reg2, reg1
	// jmp reg2
	if (mov_aop.type && add_aop.type && mov_aop.addr < add_aop.addr && add_aop.addr < jmp_aop->addr
		&& mov_aop.disp && mov_aop.disp != UT64_MAX) {
		// disp in this case should be tbl_loc_off
		*jmptbl_addr += mov_aop.disp;
#if 1
		if (o_reg_dst && reg_src && omov_aop.disp != UT64_MAX) {
			RRegItem *ri0 = r_reg_get (anal->reg, o_reg_dst, R_REG_TYPE_GPR);
			RRegItem *ri1 = r_reg_get (anal->reg, reg_src, R_REG_TYPE_GPR);
			if (ri0 && ri1 && ri0->offset == ri1->offset) {
				*casetbl_addr += omov_aop.disp;
			}
		}
#else
		if (o_reg_dst && reg_src && !strcmp (o_reg_dst, reg_src) && omov_aop.disp != UT64_MAX) {
			// Special case for indirection
			// lea reg1, [base_addr]
			// movzx reg2, byte [reg1 + tbl_off + casetbl_loc_off]
			// mov reg3, dword [reg1 + reg2*4 + tbl_loc_off]
			// add reg3, reg1
			// jmp reg3
			*casetbl_addr += omov_aop.disp;
		}
#endif
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
	read_ahead (ra, anal, *jmptbl_addr, (ut8 *)&jmptbl, 64);
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

static ut64 try_get_cmpval_from_parents(RAnal *anal, RAnalFunction *fcn, RAnalBlock *my_bb, const char *cmp_reg) {
	if (!cmp_reg) {
		R_LOG_DEBUG ("try_get_cmpval_from_parents: cmp_reg not defined");
		return UT64_MAX;
	}
	R_RETURN_VAL_IF_FAIL (fcn && fcn->bbs, UT64_MAX);
	RListIter *iter;
	RAnalBlock *tmp_bb;
	r_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			if (tmp_bb->cmpreg == cmp_reg) {
				if (tmp_bb->cond) {
					if (tmp_bb->cond->type == R_ANAL_CONDTYPE_HI || tmp_bb->cond->type == R_ANAL_CONDTYPE_GT) {
						return tmp_bb->cmpval + 1;
					}
				}
				return tmp_bb->cmpval;
			}
		}
	}
	return UT64_MAX;
}

static inline bool regs_exist(RAnalValue *src, RAnalValue *dst) {
	R_RETURN_VAL_IF_FAIL (src && dst, false);
	return src->reg && dst->reg;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
static int skip_hp(RAnal *anal, RAnalFunction *fcn, RAnalOp *op, RAnalBlock *bb, ut64 addr, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!anal->flb.exist_at (anal->flb.f, "skip", 4, addr)) {
			char *name = r_str_newf ("skip.%"PFMT64x,  addr);
			anal->flb.set (anal->flb.f, name, addr, oplen);
			free (name);
			fcn->addr += oplen;
			r_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen);
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
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
static void check_purity(HtUP *ht, RAnalFunction *fcn) {
	fcn->is_pure = true;
	ht_up_insert (ht, fcn->addr, NULL);

	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (!refs) {
		return;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		const int rt = R_ANAL_REF_TYPE_MASK (ref->type);
		switch (rt) {
		case R_ANAL_REF_TYPE_CALL:
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_ICOD:
			{
				RAnalFunction *called_fcn = r_anal_get_fcn_in (fcn->anal, ref->addr, 0);
				if (!called_fcn) {
					continue;
				}
				if (!purity_checked (ht, called_fcn)) {
					check_purity (ht, called_fcn);
				}
				if (!called_fcn->is_pure) {
					fcn->is_pure = false;
					RVecAnalRef_free (refs);
					return;
				}
			}
			break;
		case R_ANAL_REF_TYPE_DATA:
			fcn->is_pure = false;
			RVecAnalRef_free (refs);
			return;
		}
	}

	RVecAnalRef_free (refs);
}

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
	char *reg;
} leaddr_pair;

static void free_leaddr_pair(void *pair) {
	leaddr_pair *_pair = pair;
	free (_pair->reg);
	free (_pair);
}

static RAnalBlock *bbget(RAnal *anal, ut64 addr, bool jumpmid) {
	RList *intersecting = r_anal_get_blocks_in (anal, addr);
	RListIter *iter;
	RAnalBlock *bb, *ret = NULL;

	jumpmid &= r_anal_is_aligned (anal, addr);
	r_list_foreach (intersecting, iter, bb) {
		ut64 eaddr = bb->addr + bb->size;
		if (((bb->addr >= eaddr && addr == bb->addr)
				|| r_anal_block_contains (bb, addr))
				&& (!jumpmid || r_anal_block_op_starts_at (bb, addr))) {
			if (anal->opt.delay) {
				ut8 *buf = malloc (bb->size);
				if (anal->iob.read_at (anal->iob.io, bb->addr, buf, bb->size)) {
					const int last_instr_idx = bb->ninstr - 1;
					bool in_delay_slot = false;
					int i;
					for (i = last_instr_idx; i >= 0; i--) {
						const ut64 off = r_anal_bb_offset_inst (bb, i);
						const ut64 at = bb->addr + off;
						if (addr <= at || off >= bb->size) {
							continue;
						}
						RAnalOp op;
						int size = r_anal_op (anal, &op, at, buf + off, bb->size - off, R_ARCH_OP_MASK_BASIC);
						if (size > 0 && op.delay) {
							if (op.delay >= last_instr_idx - i) {
								in_delay_slot = true;
							}
							r_anal_op_fini (&op);
							break;
						}
						r_anal_op_fini (&op);
					}
					if (in_delay_slot) {
						free (buf);
						continue;
					}
				}
				free (buf);
			}
			ret = bb;
			break;
		}
	}
	r_list_free (intersecting);
	return ret;
}

typedef struct {
	RAnalFunction *fcn;
	const int stack_diff;
} BlockTakeoverCtx;

static bool fcn_takeover_block_recursive_followthrough_cb(RAnalBlock *block, void *user) {
	BlockTakeoverCtx *ctx = user;
	RAnalFunction *our_fcn = ctx->fcn;
	RAnal *anal = our_fcn->anal;
	r_anal_block_ref (block);
	while (!r_list_empty (block->fcns)) {
		RAnalFunction *other_fcn = r_list_first (block->fcns);
		if (other_fcn->addr == block->addr) {
			r_anal_block_unref (block);
			return false;
		}
		// Steal vars from this block
		size_t i;
		for (i = 0; i < block->ninstr; i++) {
			const ut64 addr = r_anal_bb_opaddr_i (block, i);
			RPVector *vars_used = r_anal_function_get_vars_used_at (other_fcn, addr);
			if (!vars_used) {
				continue;
			}
			// vars_used will get modified if r_anal_var_remove_access_at gets called
			RPVector *cloned_vars_used = (RPVector *)r_vector_clone ((RVector *)vars_used);
			void **it;
			r_pvector_foreach (cloned_vars_used, it) {
				RAnalVar *other_var = *it;
				const int actual_delta = other_var->kind == R_ANAL_VAR_KIND_SPV
					? other_var->delta + ctx->stack_diff
					: other_var->delta + (other_fcn->bp_off - our_fcn->bp_off);
				RAnalVar *our_var = r_anal_function_get_var (our_fcn, other_var->kind, actual_delta);
				if (!our_var) {
					our_var = r_anal_function_set_var (our_fcn, actual_delta, other_var->kind, other_var->type, 0, other_var->isarg, other_var->name);
				}
				if (our_var) {
					RAnalVarAccess *acc = r_anal_var_get_access_at (other_var, addr);
					r_anal_var_set_access (anal, our_var, acc->reg, addr, acc->type, acc->stackptr);
				}
				r_anal_var_remove_access_at (other_var, addr);
				if (r_vector_empty (&other_var->accesses)) {
					r_anal_function_delete_var (other_fcn, other_var);
				}
			}
			r_pvector_free (cloned_vars_used);
		}

		// TODO: remove block->ninstr from other_fcn considering delay slots
		r_anal_function_remove_block (other_fcn, block);
	}
	block->stackptr -= ctx->stack_diff;
	block->parent_stackptr -= ctx->stack_diff;
	r_anal_function_add_block (our_fcn, block);
	// TODO: add block->ninstr from our_fcn considering delay slots
	r_anal_block_unref (block);
	return true;
}

// Remove block and all of its recursive successors from all its functions and add them only to fcn
static void fcn_takeover_block_recursive(RAnalFunction *fcn, RAnalBlock *start_block) {
	BlockTakeoverCtx ctx = { fcn, start_block->parent_stackptr - fcn->stack};
	r_anal_block_recurse_followthrough (start_block, fcn_takeover_block_recursive_followthrough_cb, &ctx);
}

static const char *retpoline_reg(RAnal *anal, ut64 addr) {
	RFlagItem *flag = anal->flag_get (anal->flb.f, false, addr);
	if (flag) {
		const char *token = "x86_indirect_thunk_";
		const char *thunk = strstr (flag->name, token);
		if (thunk) {
			return thunk + strlen (token);
		}
	}
#if 0
// TODO: implement following code analysis check for stripped binaries:
// 1) op(addr).type == CALL
// 2) call_dest = op(addr).addr
// 3) op(call_dest).type == STORE
// 4) op(call_dest + op(call_dest).size).type == RET
[0x00000a65]> pid 6
	0x00000a65  sym.__x86_indirect_thunk_rax:
	0x00000a65  .------- e807000000  call 0xa71
	0x00000a6a  |              f390  pause
	0x00000a6c  |            0faee8  lfence
	0x00000a6f  |              ebf9  jmp 0xa6a
	0x00000a71  `---->     48890424  mov qword [rsp], rax
	0x00000a75                   c3  ret
#endif
	return NULL;
}

static void analyze_retpoline(RAnal *anal, RAnalOp *op) {
	if (anal->opt.retpoline) {
		const char *rr = retpoline_reg (anal, op->jump);
		if (rr) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->reg = rr;
		}
	}
}

static inline bool op_is_set_bp(const char *op_dst, const char *op_src, const char *bp_reg, const char *sp_reg) {
	if (op_dst && op_src) {
		return !strcmp (bp_reg, op_dst) && !strcmp (sp_reg, op_src);
	}
	return false;
}

static inline bool does_arch_destroys_dst(const char *arch) {
	return arch && (r_str_startswith (arch, "arm") ||
			r_str_startswith (arch, "riscv") ||
			r_str_startswith (arch, "ppc"));
}

static inline bool has_vars(RAnal *anal, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
	return fcn && r_anal_var_count_all (fcn) > 0;
}

static void fcn_rename_readdr(RAnalFunction *fcn, ut64 to) {
	r_strf_var (addrstr, 64, "%08"PFMT64x, fcn->addr);
	char *s = strstr (fcn->name, addrstr);
	if (s) {
		char *pfx = r_str_ndup (fcn->name, s - fcn->name);
		free (fcn->name);
		fcn->name = r_str_newf ("%s%08"PFMT64x, pfx, to);
		free (pfx);
	}
	fcn->addr = to;
}

static int fcn_recurse(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int depth) {
	const char *variadic_reg = NULL;
	ReadAhead ra = {0};
	ra.cache_addr = UT64_MAX; // invalidate the cache
	char *bp_reg = NULL;
	char *sp_reg = NULL;
	char *op_dst = NULL;
	char *op_src = NULL;
	if (depth < -1) {
		// only happens when we want to analyze 1 basic block
		R_LOG_DEBUG ("fcn recurse limit reached at 0x%08"PFMT64x, addr);
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}
	if (R_UNLIKELY ((depth < 0) && (depth != -1))) {
		R_LOG_WARN ("Analysis of 0x%08"PFMT64x" stopped at 0x%08"PFMT64x", use a higher anal.depth to continue", fcn->addr, addr);
		return R_ANAL_RET_ERROR;
	}
	// TODO Store all this stuff in the heap so we save memory in the stack
	RAnalOp *op = NULL;
	RAnalValue *dst = NULL, *src0 = NULL, *src1 = NULL;
	const char *movbasereg = NULL;
	const int addrbytes = anal->iob.io ? anal->iob.io->addrbytes : 1;
	const char *last_reg_mov_lea_name = NULL;
	RAnalBlock *bb = NULL;
	RAnalBlock *bbg = NULL;
	int ret = R_ANAL_RET_END;
	bool overlapped = false;
	int oplen, idx = 0;
	size_t lea_cnt = 0;
	size_t nop_prefix_cnt = 0;
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
	RCore *core = anal->coreb.core;
	RCons *cons = core->cons;
	const char *arch = anal->config? anal->config->arch: R_SYS_ARCH;
	bool arch_destroys_dst = does_arch_destroys_dst (arch);
	const bool flagends = anal->opt.flagends;
	const bool is_arm = r_str_startswith (arch, "arm");
	const bool is_mips = !is_arm && r_str_startswith (arch, "mips");
	const bool is_v850 = is_arm ? false: (arch && (!strncmp (arch, "v850", 4) || !strncmp (anal->coreb.cfgGet (core, "asm.cpu"), "v850", 4)));
	const bool is_x86 = is_arm ? false: arch && !strncmp (arch, "x86", 3);
	const bool is_amd64 = is_x86 ? fcn->callconv && !strcmp (fcn->callconv, "amd64") : false;
	const bool is_dalvik = is_x86 ? false : arch && !strncmp (arch, "dalvik", 6);
	const bool propagate_noreturn = anal->opt.propagate_noreturn;
	ut64 v1 = UT64_MAX;

	if (r_cons_is_breaked (cons)) {
		return R_ANAL_RET_END;
	}
	if (anal->sleep) {
		r_sys_usleep (anal->sleep);
	}

	// check if address is readable //:
	if (anal->iob.io && !anal->iob.is_valid_offset (anal->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !anal->iob.io->va) {
			R_LOG_DEBUG ("Invalid address 0x%"PFMT64x ". Try with io.va=true", addr);
		}
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	RAnalFunction *fcn_at_addr = r_anal_get_function_at (anal, addr);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return R_ANAL_RET_ERROR; // MUST BE NOT FOUND
	}

	RAnalBlock *existing_bb = bbget (anal, addr, anal->opt.jmpmid);
	if (existing_bb) {
		bool existing_in_fcn = r_list_contains (existing_bb->fcns, fcn);
		existing_bb = r_anal_block_split (existing_bb, addr);
		if (!existing_in_fcn && existing_bb) {
			if (existing_bb->addr == fcn->addr) {
				if (anal->opt.slow) {
					// XXX this call causes an infinite loop if not commented
					// our function starts directly there, so we steal what is ours!
					fcn_takeover_block_recursive (fcn, existing_bb);
				} else {
					r_list_delete_data (fcn->bbs, existing_bb);
					R_LOG_INFO ("Basic block collides with function 0x%08"PFMT64x, fcn->addr);
					// r_anal_block_unref (existing_bb);
					// return R_ANAL_RET_END; // MUST BE NOT FOUND
				}
			}
		}
		// r_unref (existing_bb);
		r_anal_block_unref (existing_bb);
		if (anal->opt.recont) {
			return R_ANAL_RET_END;
		}
		R_LOG_DEBUG ("r_anal_function_bb() fails at 0x%"PFMT64x, addr);
		return R_ANAL_RET_ERROR; // MUST BE NOT DUP
	}

	bb = fcn_append_basic_block (anal, fcn, addr);
	if (!bb) {
		// we checked before whether there is a bb at addr, so the create should have succeeded
		R_LOG_DEBUG ("Missing basic block assertion failed");
		return R_ANAL_RET_ERROR;
	}

	if (!anal->leaddrs) {
		anal->leaddrs = r_list_newf (free_leaddr_pair);
		if (R_UNLIKELY (!anal->leaddrs)) {
			R_LOG_ERROR ("Cannot create leaddr list");
			gotoBeach (R_ANAL_RET_ERROR);
		}
	}
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	bool last_is_add_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (anal->limit && addr + idx < anal->limit->from) {
		R_LOG_DEBUG ("anal.limit");
		gotoBeach (R_ANAL_RET_END);
	}

	bool varset = has_vars (anal, addr); // Checks if var is already analyzed at given addr

	ut64 movdisp = UT64_MAX; // used by jmptbl when coded as "mov Reg,[Reg*Scale+Disp]"
	ut64 movscale = 0;
	int maxlen = len * addrbytes;
	if (is_dalvik) {
		bool skipAnalysis = false;
		const char *name = fcn->name;
		if (r_str_startswith (name, "sym.")) {
			if (r_str_startswith (name + 4, "imp.")) {
				skipAnalysis = true;
			} else if (strstr (name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			gotoBeach (R_ANAL_RET_END);
		}
	}
	if ((maxlen - (addrbytes * idx)) > MAX_SCAN_SIZE) {
		if (anal->verbose) {
			R_LOG_WARN ("Skipping large memory region");
		}
		maxlen = 0;
	}
	const char *_bp_reg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
	const char *_sp_reg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
	const bool has_stack_regs = _bp_reg && _sp_reg;
	if (has_stack_regs) {
		free (bp_reg);
		bp_reg = strdup (_bp_reg);
		free (sp_reg);
		sp_reg = strdup (_sp_reg);
	}
	if (is_amd64) {
		variadic_reg = "rax";
	}
	bool has_variadic_reg = !!variadic_reg;
	bool nopskip = anal->opt.nopskip;
	if (nopskip) {
		const bool isvm = r_anal_archinfo (anal, R_ARCH_INFO_ISVM) == R_ARCH_INFO_ISVM;
		if (isvm) {
			nopskip = false;
		}
	}

	op = r_anal_op_new ();
	const ut32 opflags = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_HINT;
	while (addrbytes * idx < maxlen) {
		if (!last_is_reg_mov_lea) {
			last_reg_mov_lea_name = NULL;
		}
		if (anal->limit && anal->limit->to <= addr + idx) {
			break;
		}
repeat:
		if (r_cons_is_breaked (cons)) {
			break;
		}
		ut8 buf[32]; // 32 bytes is enough to hold any instruction.
		ut32 at_delta = addrbytes * idx;
		ut64 at = addr + at_delta;
		ut64 bytes_read = R_MIN (len - at_delta, sizeof (buf));
		ret = read_ahead (&ra, anal, at, buf, bytes_read);
		if (ret < 0) {
			R_LOG_ERROR ("Failed to read");
			break;
		}
		// ret is the max length of bytes available
		// eprintf("%02x %02x\n", buf[0], buf[1]);
		if (is_invalid_memory (anal, buf, bytes_read)) {
			R_LOG_DEBUG ("FFFF opcode at 0x%08"PFMT64x, at);
			gotoBeach (R_ANAL_RET_ERROR)
		}
		r_anal_op_fini (op);
		oplen = r_anal_op (anal, op, at, buf, bytes_read, opflags);

		if (oplen < 1) {
			R_LOG_DEBUG ("Invalid instruction at 0x%"PFMT64x" with %d bits", at, anal->config->bits);
			// gotoBeach (R_ANAL_RET_ERROR);
			// RET_END causes infinite loops somehow
			gotoBeach (R_ANAL_RET_END);
		}
		R_LOG_DEBUG ("op 0x%08"PFMT64x" %d %s", at, op->size, r_anal_optype_tostring (op->type));
		dst = r_vector_at (&op->dsts, 0);
		free (op_dst);
		op_dst = (dst && dst->reg)? strdup (dst->reg): NULL;
		src0 = r_vector_at (&op->srcs, 0);
		free (op_src);
		op_src = (src0 && src0->reg)? strdup (src0->reg): NULL;
		src1 = r_vector_at (&op->srcs, 1);

		if (nopskip && fcn->addr == at) {
			const int codealign = r_anal_archinfo (anal, R_ARCH_INFO_CODE_ALIGN);
			if (codealign > 1) {
				if (at % codealign) {
					goto noskip;
				}
			}
			RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
			if (!fi || strstr (fi->name, "sym.")) {
				if ((addr + delay.un_idx - oplen) == fcn->addr) {
					if (r_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen)) {
						fcn_rename_readdr (fcn, fcn->addr + oplen);
						idx = delay.un_idx;
						r_anal_op_fini (op);
						goto repeat;
					}
				}
			}
			switch (op->type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_NOP:
				nop_prefix_cnt++;
				if (nop_prefix_cnt > MAX_NOP_PREFIX_CNT) {
					gotoBeach (R_ANAL_RET_ERROR);
				}
				if (r_anal_block_relocate (bb, at + op->size, bb->size)) {
					r_anal_op_fini (op);
					addr = at + op->size;
					fcn_rename_readdr (fcn, addr);
					// force function rename if needed
					goto repeat;
				}
			}
		}
noskip:
		if (op->hint.new_bits) {
			r_anal_hint_set_bits (anal, op->jump, op->hint.new_bits);
		}
		if (idx > 0 && !overlapped) {
			bbg = bbget (anal, at, anal->opt.jmpmid);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (anal->opt.jmpmid && r_anal_is_aligned (anal, at)) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RAnalBlock *split = r_anal_block_split (bbg, at);
					r_anal_block_unref (split);
				}
				overlapped = true;
				R_LOG_DEBUG ("Overlapped at 0x%08"PFMT64x, at);
			}
		}
		if (flagends && fcn->addr != at) {
			RFlagItem *flag = anal->flag_get (anal->flb.f, false, at);
			if (flag) {
				if (r_str_startswith (flag->name, "sym")) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
		}
		if (!overlapped) {
			const ut64 newbbsize = bb->size + oplen;
			if (newbbsize > MAX_FCN_SIZE) {
				gotoBeach (R_ANAL_RET_ERROR);
			}
			r_anal_block_set_size (bb, newbbsize);
			if (!r_anal_bb_set_offset (bb, bb->ninstr++, at - bb->addr)) {
				gotoBeach (R_ANAL_RET_ERROR);
			}
			fcn->ninstr++;
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
						ret = r_anal_function_bb (anal, fcn, handle_addr, depth - 1);
						R_LOG_INFO ("(%s) 0x%08"PFMT64x, handle, handle_addr);
						if (bb->size == 0) {
							r_anal_function_remove_block (fcn, bb);
						}
						r_anal_block_unref (bb);
						bb = fcn_append_basic_block (anal, fcn, addr);
						if (!bb) {
							gotoBeach (R_ANAL_RET_ERROR);
						}
					}
				}
			}
		}
		idx += oplen;
		delay.un_idx = idx;
		if (anal->opt.delay && op->delay > 0 && !delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			R_LOG_DEBUG ("Enter branch delay at 0x%08"PFMT64x ". bb->sz=%"PFMT64u, at - oplen, bb->size);
			delay.idx = idx - oplen;
			delay.cnt = op->delay;
			delay.pending = 1; // we need this in case the actual idx is zero...
			delay.adjust = !overlapped; // adjustment is required later to avoid double count
			r_anal_op_fini (op);
			continue;
		}

		if (delay.cnt > 0) {
			// if we had passed a branch delay instruction, keep
			// track of how many still to process.
			delay.cnt--;
			if (!delay.cnt) {
				R_LOG_DEBUG ("Last branch delayed opcode at 0x%08"PFMT64x ". bb->sz=%"PFMT64u, addr + idx - oplen, bb->size);
				delay.after = idx;
				idx = delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (op->delay > 0 && delay.pending) {
			R_LOG_DEBUG ("Revisit branch delay jump at 0x%08"PFMT64x ". bb->sz=%"PFMT64u, addr + idx - oplen, bb->size);
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				r_anal_block_set_size (bb, (ut64)addrbytes * (ut64)delay.after);
				fcn->ninstr--;
				R_LOG_DEBUG ("Correct for branch delay @ %08"PFMT64x " bb.addr=%08"PFMT64x " corrected.bb=%"PFMT64u" f.uncorr=%"PFMT64u,
						addr + idx - oplen, bb->addr, bb->size, r_anal_function_linear_size (fcn));
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			idx = delay.after;
			delay.pending = delay.after = delay.idx = delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		switch (op->stackop) {
		case R_ANAL_STACK_INC:
			if (R_ABS (op->stackptr) < R_ANAL_MAX_INCSTACK) {
				fcn->stack += op->stackptr;
				if (fcn->stack > fcn->maxstack) {
					fcn->maxstack = fcn->stack;
				}
			}
			bb->stackptr += op->stackptr;
			break;
		case R_ANAL_STACK_RESET:
			bb->stackptr = 0;
			break;
		default:
			break;
		}
		if (op->ptr && op->ptr != UT64_MAX && op->ptr != UT32_MAX) {
			// swapped parameters wtf
			// its read or wr
			int dir = 0;
			if (op->direction & R_ANAL_OP_DIR_READ) {
				dir |= R_ANAL_REF_TYPE_READ;
			}
			if (op->direction & R_ANAL_OP_DIR_REF) {
				dir |= R_ANAL_REF_TYPE_READ;
			}
			if (op->direction & R_ANAL_OP_DIR_WRITE) {
				dir |= R_ANAL_REF_TYPE_WRITE;
			}
			if (op->direction & R_ANAL_OP_DIR_EXEC) {
				dir |= R_ANAL_REF_TYPE_EXEC;
			}
			r_anal_xrefs_set (anal, op->addr, op->ptr, R_ANAL_REF_TYPE_DATA | dir);
		}
		if (anal->opt.vars && !varset) {
			// XXX uses op.src/dst and fails because regprofile invalidates the regitems
			// lets just call this BEFORE retpoline() to avoid such issue
			r_anal_extract_vars (anal, fcn, op);
		}
		// this call may cause regprofile changes which cause ranalop.regitem references to be invalid
		analyze_retpoline (anal, op);
		switch (op->type & R_ANAL_OP_TYPE_MASK) {
		case R_ANAL_OP_TYPE_CMOV:
		case R_ANAL_OP_TYPE_MOV:
			last_is_reg_mov_lea = false;
			if (is_arm) { // mov lr, pc
				const char *esil = r_strbuf_get (&op->esil);
				if (!strcmp (esil, "pc,lr,=")) {
					last_is_mov_lr_pc = true;
				}
			}
			if (has_stack_regs && op_is_set_bp (op_dst, op_src, bp_reg, sp_reg)) {
				fcn->bp_off = fcn->stack;
			}
			// Is this a mov of immediate value into a register?
			if (dst && dst->reg && op->val > 0 && op->val != UT64_MAX) {
				last_reg_mov_lea_name = dst->reg;
				last_reg_mov_lea_val = op->val;
				last_is_reg_mov_lea = true;
			}
			// skip mov reg, reg
			if (anal->opt.jmptbl && op->scale && op->ireg) {
				movdisp = op->disp;
				movscale = op->scale;
				movbasereg = src0? src0->reg: NULL;
			}
			if (anal->opt.hpskip && regs_exist (src0, dst) && !strcmp (src0->reg, dst->reg)) {
				const int skip_ret = skip_hp (anal, fcn, op, bb, addr, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					r_anal_op_fini (op);
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_LEA:
			last_is_reg_mov_lea = false;
			// if first byte in op->ptr is 0xff, then set leaddr assuming its a jumptable
#if 0
			{
				ut8 buf[4];
				anal->iob.read_at (anal->iob.io, op->ptr, buf, sizeof (buf));
				if ((buf[2] == 0xff || buf[2] == 0xfe) && buf[3] == 0xff) {
					leaddr_pair *pair = R_NEW0 (leaddr_pair);
					if (!pair) {
						R_LOG_ERROR ("Cannot create leaddr_pair");
						gotoBeach (R_ANAL_RET_ERROR);
					}
					pair->op_addr = op->addr;
					pair->leaddr = op->ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
					r_list_append (anal->leaddrs, pair);
				}
				if (has_stack_regs && op_is_set_bp (op, bp_reg, sp_reg)) {
					fcn->bp_off = fcn->stack - op->src[0]->delta;
				}
				if (op->dst && op->dst->reg && op->dst->reg->name && op->ptr > 0 && op->ptr != UT64_MAX) {
					free (last_reg_mov_lea_name);
					if ((last_reg_mov_lea_name = strdup (op->dst->reg->name))) {
						last_reg_mov_lea_val = op->ptr;
						last_is_reg_mov_lea = true;
					}
				}
			}
#else
			if (op->ptr != UT64_MAX) {
				leaddr_pair *pair = R_NEW0 (leaddr_pair);
				if (!pair) {
					R_LOG_ERROR ("Cannot create leaddr_pair");
					gotoBeach (R_ANAL_RET_ERROR);
				}
				pair->op_addr = op->addr;
				pair->leaddr = op->ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
				pair->reg = op->reg
					? strdup (op->reg)
					: dst && dst->reg
					? strdup (dst->reg)
					: NULL;
				lea_cnt++;
				r_list_append (anal->leaddrs, pair);
			}
			if (has_stack_regs && op_is_set_bp (op_dst, op_src, bp_reg, sp_reg)) {
				fcn->bp_off = fcn->stack - src0->delta;
			}
			if (dst && dst->reg && op->ptr > 0 && op->ptr != UT64_MAX) {
				last_reg_mov_lea_name = dst->reg;
				last_reg_mov_lea_val = op->ptr;
				last_is_reg_mov_lea = true;
			}
			if (op->type == R_ANAL_OP_TYPE_ADD && dst && dst->reg && last_reg_mov_lea_name && !strcmp (dst->reg, last_reg_mov_lea_name) && op->val != UT64_MAX) {
				last_reg_mov_lea_val += op->val;
			}
#endif
			// skip lea reg,[reg]
			if (anal->opt.hpskip && regs_exist (src0, dst) && !strcmp (src0->reg, dst->reg)) {
				const int skip_ret = skip_hp (anal, fcn, op, bb, at, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					r_anal_op_fini (op);
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			if (anal->opt.jmptbl) {
				RAnalOp jmp_aop = {0};
				ut64 jmptbl_addr = op->ptr;
				ut64 casetbl_addr = op->ptr;
				if (is_delta_pointer_table (&ra, anal, fcn, op->addr, op->ptr, &jmptbl_addr, &casetbl_addr, &jmp_aop)) {
					ut64 table_size, default_case = 0;
					st64 case_shift = 0;
					// we require both checks here since try_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// try_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with try_get_jmptbl_info
					ut64 addr = jmp_aop.addr;
					bool ready = false;
					if (try_get_jmptbl_info (anal, fcn, addr, bb, &table_size, &default_case, &case_shift)) {
						ready = true;
					} else if (try_get_delta_jmptbl_info (anal, fcn, addr, op->addr, &table_size, &default_case, &case_shift)) {
						ready = true;
					}
					// TODO: -1-
					if (ready) {
						ret = casetbl_addr == op->ptr
							? r_anal_jmptbl_walk (anal, fcn, bb, depth, addr, case_shift, jmptbl_addr, op->ptr, 4, table_size, default_case, 4)
							: try_walkthrough_casetbl (anal, fcn, bb, depth, addr, case_shift, jmptbl_addr, casetbl_addr, jmptbl_addr, 4, table_size, default_case, 4);
						if (ret) {
							anal->lea_jmptbl_ip = addr;
						}
					}
				}
				r_anal_op_fini (&jmp_aop);
			}
			break;
		case R_ANAL_OP_TYPE_LOAD: ;
			// R2R db/anal/arm db/esil/apple
			//v1 = UT64_MAX; // reset v1 jmptable pointer value for mips only
			// on stm8 this must be disabled.. but maybe we need a global option to disable icod refs
			bool want_icods = anal->opt.icods;
			{
				const char *arch = R_UNWRAP3 (anal, config, arch);
				if (r_str_startswith (arch, "stm8")) {
					want_icods = false;
				}
			}
			if (want_icods && anal->iob.is_valid_offset (anal->iob.io, op->ptr, 0)) {
				// TODO: what about the qword loads!??!?
				ut8 dd[4] = {0};
				(void)anal->iob.read_at (anal->iob.io, op->ptr, (ut8 *) dd, sizeof (dd));
				// if page have exec perms
				ut64 da = (ut64)r_read_ble32 (dd, R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config));
				if (da != UT32_MAX && da != UT64_MAX && anal->iob.is_valid_offset (anal->iob.io, da, 0)) {
					/// TODO: this must be CODE | READ , not CODE|DATA, but raises 10 fails
					if (is_mips && anal->opt.jmptbl) {
						const char *esil = r_strbuf_get (&op->esil);
						if (strstr (esil, "v1,=")) {
							// eprintf("iftarget is v1 (%s)\n", esil);
							// eprintf ("LOAD FROM %llx -> %llx\n", op->ptr, da);
							v1 = da;
						}
					}
					// r_anal_xrefs_set (anal, op->addr, da, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_DATA);
					// Register an indirect code pointer reference
					r_anal_xrefs_set (anal, op->addr, da, R_ANAL_REF_TYPE_ICOD | R_ANAL_REF_TYPE_EXEC);
				} else {
					R_LOG_DEBUG ("Invalid refs 0x%08"PFMT64x" .. 0x%08"PFMT64x" .. 0x%08"PFMT64x" not adding", op->addr, op->ptr, da);
					/// XXX this breaks the db/esil/apple tests
				//	r_meta_set (anal, R_META_TYPE_DATA, op->ptr, 4, "");
				}
				// maybe optional or in the else
				// r_anal_xrefs_set (anal, op->addr, op->ptr, R_ANAL_REF_TYPE_DATA);
				if (anal->opt.loads) {
					// set this address as data if destination is not code
					r_meta_set (anal, R_META_TYPE_DATA, op->ptr, 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case R_ANAL_OP_TYPE_ADD:
			if (is_mips) {
				if (anal->opt.jmptbl && v1 != UT64_MAX) {
					// TODO: ensure we add in v1 // const char *esil = r_strbuf_get (&op->esil);
					v1 += (st32)op->val;
					// align v1
					while (v1 & 3) {
						v1++;
					}
					R_LOG_DEBUG ("[0x%"PFMT64x"]============= 0x%"PFMT64x, op->addr, v1);
				}
			} else if (is_arm) {
				const int bits = anal->config->bits;
				if (bits == 64) {
					if (last_is_reg_mov_lea) {
						// incremement the leaddr
						leaddr_pair *la;
						last_is_reg_mov_lea = false;
						RListIter *iter;
						r_list_foreach_prev (anal->leaddrs, iter, la) {
							la->leaddr += op->val;
							break;
						}
					}
				} else if (bits == 32) {
					if (len >= 4 && !memcmp (buf, "\x00\xe0\x8f\xe2", 4)) {
						// add lr, pc, 0 //
						last_is_add_lr_pc = true; // TODO: support different values, not just 0
					}
				}
			}
			if (anal->opt.ijmp) {
				if ((op->size + 4 <= bytes_read) && !memcmp (buf + op->size, "\x00\x00\x00\x00", 4)) {
					r_anal_block_set_size (bb, bb->size - oplen);
					op->type = R_ANAL_OP_TYPE_RET;
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
			if (op->jump == UT64_MAX) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				RFlagItem *fi = anal->flb.get_at (anal->flb.f, op->jump, false);
				if (fi) {
					if (strstr (fi->name, "imp.")) {
						gotoBeach (R_ANAL_RET_END);
					} else if (strstr (fi->name, "sym.") || r_str_startswith (fi->name, "fcn.")) {
						gotoBeach (R_ANAL_RET_END);
					}
				}
			}
			if (r_cons_is_breaked (cons)) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (anal->opt.jmpref) {
				(void) r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_EXEC);
			}
			if (!anal->opt.jmpabove && (op->jump < fcn->addr)) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (r_anal_noreturn_at (anal, op->jump)) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				bool must_eob = true;
				RIOMap *map = anal->iob.map_get_at (anal->iob.io, addr);
				if (map) {
					must_eob = ! r_io_map_contain (map, op->jump);
				}
				if (must_eob) {
					op->jump = UT64_MAX;
					gotoBeach (R_ANAL_RET_END);
				}
			}
#if FIX_JMP_FWD
			bb->jump = op->jump;
			bb->fail = UT64_MAX;
			FITFCNSZ ();
			gotoBeach (R_ANAL_RET_END);
#else
			if (!overlapped) {
				bb->jump = op->jump;
				bb->fail = UT64_MAX;
			}
			if (!anal->opt.tailcall) {
				goto beach;
			}
			// TAILCALL CHECKS BELOW
			{ // check if destination is a prelude, so we assume that's a tailcall
				ut8 buf[32];
				(void)anal->iob.read_at (anal->iob.io, op->jump, (ut8 *) buf, sizeof (buf));
				if (r_anal_is_prelude (anal, op->jump, buf, sizeof (buf))) {
					R_LOG_DEBUG ("tail call jump found at 0x%08"PFMT64x, op->addr);
					// XXX using type-jump wont analyze the destination as a function
					// calling fcn_recurse wont make it analyze it either
#if 0
					(void) r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_CALL | R_ANAL_REF_TYPE_EXEC);
#else
					(void) r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_JUMP | R_ANAL_REF_TYPE_EXEC);
					// using type-jump wont analyze the destination as a function
					// fcn_recurse (anal, fcn, op->jump, anal->opt.bb_max_size, depth - 1);
					/// XXX RAnalFunction *fcn = r_anal_function_new (anal, op->jump);
					RAnalFunction *nfcn = r_anal_create_function (anal, NULL, op->jump, 0, NULL);
					r_anal_function (anal, nfcn? nfcn: fcn, op->jump, R_ANAL_REF_TYPE_CALL);
#endif
					gotoBeach (R_ANAL_RET_END);
				}
			}
			ret = r_anal_function_bb (anal, fcn, op->jump, depth);
			int tc = anal->opt.tailcall_delta;
			if (tc) {
				int diff = op->jump - op->addr;
				if (tc > 0 && R_ABS (diff) > tc) {
					(void) r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_CALL | R_ANAL_REF_TYPE_EXEC);
					fcn_recurse (anal, fcn, op->jump, anal->opt.bb_max_size, depth - 1);
					gotoBeach (R_ANAL_RET_END);
				}
			}
			goto beach;
#endif
			break;
		case R_ANAL_OP_TYPE_SUB:
			if (op->val != UT64_MAX && op->val > 0) {
				// if register is not stack
				anal->cmpval = op->val;
			}
			break;
		case R_ANAL_OP_TYPE_CMP:
			{
				ut64 val = (is_x86 || is_v850)? op->val : op->ptr;
				if (val) {
					anal->cmpval = val;
					bb->cmpval = anal->cmpval;
					bb->cmpreg = op->reg;
					r_anal_cond_free (bb->cond);
					bb->cond = r_anal_cond_new_from_op (op);
					if (bb->cond) {
						src0 = src1 = NULL;
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_MCJMP:
		case R_ANAL_OP_TYPE_RCJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			if (anal->opt.cjmpref) {
				const bool is_success = r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_CODE);
				if (!is_success) {
					R_LOG_DEBUG ("failed to add xref @ %"PFMT64u" -> %"PFMT64u, op->addr, op->jump);
				}
			}
			if (!overlapped) {
				bb->jump = op->jump;
				bb->fail = op->fail;
			}
			if (bb->cond) {
				bb->cond->type = op->cond;
			}
			if (anal->opt.jmptbl && !is_mips) {
				if (op->ptr != UT64_MAX) {
					ut64 table_size, default_case;
					table_size = anal->cmpval + 1;
					default_case = op->fail; // is this really default case?
					if (anal->cmpval != UT64_MAX && default_case != UT64_MAX && (op->reg || op->ireg)) {
						// TODO -1
						if (op->ireg) {
							ret = r_anal_jmptbl_walk (anal, fcn, bb, depth, op->addr, 0, op->ptr, op->ptr, anal->config->bits >> 3, table_size, default_case, ret);
						} else { // op->reg
							ret = walkthrough_arm_jmptbl_style (anal, fcn, bb, depth, op->addr, op->ptr, anal->config->bits >> 3, table_size, default_case, ret);
						}
						// check if op->jump and op->fail contain jump table location
						// clear jump address, because it's jump table location
						if (op->jump == op->ptr) {
							op->jump = UT64_MAX;
						} else if (op->fail == op->ptr) {
							op->fail = UT64_MAX;
						}
						anal->cmpval = UT64_MAX;
					}
				}
			}
			int saved_stack = fcn->stack;
			// TODO: depth -1 in here
			r_anal_function_bb (anal, fcn, op->jump, depth);
			fcn->stack = saved_stack;
			ret = r_anal_function_bb (anal, fcn, op->fail, depth);
			fcn->stack = saved_stack;

			// XXX breaks mips analysis too !op->delay
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
			(void) r_anal_xrefs_set (anal, op->addr, op->ptr, R_ANAL_REF_TYPE_CALL);

			if (propagate_noreturn && r_anal_noreturn_at (anal, op->ptr)) {
				RAnalFunction *f = r_anal_get_function_at (anal, op->ptr);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_CALL:
			/* call dst */
			(void) r_anal_xrefs_set (anal, op->addr, op->jump, R_ANAL_REF_TYPE_CALL | R_ANAL_REF_TYPE_EXEC);

			if (propagate_noreturn && r_anal_noreturn_at (anal, op->jump)) {
				RAnalFunction *f = r_anal_get_function_at (anal, op->jump);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
			if (is_arm && anal->config->bits == 32) {
				if (last_is_mov_lr_pc) {
					break;
				}
				if (last_is_add_lr_pc) {
					op->type = R_ANAL_OP_TYPE_CALL;
					op->fail = op->addr + 4;
					break;
				}
			} else if (is_mips && anal->opt.jmptbl) {
				// lw v1, -0x7fc4(gp) ; gp = 0x684c00 - 0x7fc4 // read 4 bytes at gp-0x7fc4
				// sll v0, s0, 2   // select the case from the pointer table * 4
				// addiu v1, v1, 0x74b4 ; [gp-0x7fc4] + 0x74b4 ;; is jmptbl_ptr_addr
				// addu v0, v0, v1 // increment the pointer
				ut64 jmptbl_ptr_addr = v1; // 0x005a74b4;
				ut64 default_case = UT64_MAX; // op->addr + 8;
				int tablesize = 0;
				ut64 tblptr = v1;
				while (1) {
					ut8 dd[4];
					// read le32 until the number is not negative
					(void)anal->iob.read_at (anal->iob.io, tblptr, (ut8 *) dd, sizeof (dd));
					// if page have exec perms
					st32 n = (st32)r_read_ble32 (dd, R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config));
					if (n >= -1) {
						break;
					}
					tblptr += 4;
					tablesize ++;
				}
				tablesize *= 4;
				ut64 tblloc = jmptbl_ptr_addr;
				int sz = 4;
				ret = r_anal_jmptbl_walk (anal, fcn, bb, depth, op->addr, 0,
						tblloc, jmptbl_ptr_addr, sz, tablesize, default_case, ret);
			} else if (is_v850 && anal->opt.jmptbl) {
				int ptsz = (anal->cmpval && anal->cmpval != UT64_MAX)? anal->cmpval + 1: 4;
				if ((int)anal->cmpval > 0) {
					ret = r_anal_jmptbl_walk (anal, fcn, bb, depth, op->addr,
							0, op->addr + 2, op->addr + 2, 2, ptsz, 0, ret);
				}
				gotoBeach (R_ANAL_RET_END);
				break;
			}
			/* fall through */
		case R_ANAL_OP_TYPE_MJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (anal->opt.ijmp && next_instruction_is_symbol (anal, op)) {
				gotoBeach (R_ANAL_RET_END);
			}
			// switch statement
			if (anal->opt.jmptbl && anal->lea_jmptbl_ip != op->addr) {
				ut8 buf[32]; // 32 bytes is enough to hold any instruction.
					// op->ireg since rip relative addressing produces way too many false positives otherwise
					// op->ireg is 0 for rip relative, "rax", etc otherwise
				if (op->ptr != UT64_MAX && op->ireg) { // direct jump
					ut64 table_size, default_case;
					st64 case_shift = 0;
					if (try_get_jmptbl_info (anal, fcn, op->addr, bb, &table_size, &default_case, &case_shift)) {
						bool case_table = false;
						RAnalOp *prev_op = r_anal_op_new ();
						anal->iob.read_at (anal->iob.io, op->addr - op->size, buf, sizeof (buf));
						if (r_anal_op (anal, prev_op, op->addr - op->size, buf, sizeof (buf), R_ARCH_OP_MASK_VAL) > 0) {
							RAnalValue *prev_dst = r_vector_at (&prev_op->dsts, 0);
							bool prev_op_has_dst_name = prev_dst && prev_dst->reg;
							bool op_has_src_name = src0 && src0->reg;
							bool same_reg = (op->ireg && prev_op_has_dst_name && !strcmp (op->ireg, prev_dst->reg))
								|| (op_has_src_name && prev_op_has_dst_name && !strcmp (src0->reg, prev_dst->reg));
							if (prev_op->type == R_ANAL_OP_TYPE_MOV && prev_op->disp && prev_op->disp != UT64_MAX && same_reg) {
								//	movzx reg, byte [reg + case_table]
								//	jmp dword [reg*4 + jump_table]
								if (try_walkthrough_casetbl (anal, fcn, bb, depth - 1, op->addr, case_shift, op->ptr, prev_op->disp, op->ptr, anal->config->bits >> 3, table_size, default_case, ret)) {
									ret = case_table = true;
								}
							}
						}
						r_anal_op_free (prev_op);
						if (!case_table) {
							ret = r_anal_jmptbl_walk (anal, fcn, bb, depth, op->addr, case_shift, op->ptr, op->ptr, anal->config->bits >> 3, table_size, default_case, ret);
						}
					}
				} else if (op->ptr != UT64_MAX && op->reg) { // direct jump
					ut64 table_size, default_case;
					st64 case_shift = 0;
					if (try_get_jmptbl_info (anal, fcn, op->addr, bb, &table_size, &default_case, &case_shift)) {
						ret = r_anal_jmptbl_walk (anal, fcn, bb, depth - 1, op->addr, case_shift, op->ptr, op->ptr, anal->config->bits >> 3, table_size, default_case, ret);
					}
				} else if (movdisp != UT64_MAX) {
					st64 case_shift = 0;
					ut64 table_size, default_case;
					ut64 jmptbl_base = 0; //UT64_MAX;
					ut64 lea_op_off = UT64_MAX;
					RListIter *iter;
					leaddr_pair *pair;
					if (movbasereg) {
						// find nearest candidate leaddr before op.addr
						r_list_foreach_prev (anal->leaddrs, iter, pair) {
							if (pair->op_addr >= op->addr) {
								continue;
							}
							if ((lea_op_off == UT64_MAX || lea_op_off > op->addr - pair->op_addr) && pair->reg && !strcmp (movbasereg, pair->reg)) {
								lea_op_off = op->addr - pair->op_addr;
								jmptbl_base = pair->leaddr;
							}
						}
					}
					if (!try_get_jmptbl_info (anal, fcn, op->addr, bb, &table_size, &default_case, &case_shift)) {
						table_size = anal->cmpval + 1;
						default_case = -1;
					}
					ret = r_anal_jmptbl_walk (anal, fcn, bb, depth - 1, op->addr, case_shift, jmptbl_base + movdisp, jmptbl_base, movscale, table_size, default_case, ret);
					anal->cmpval = UT64_MAX;
#if 0
				} else if (movdisp != UT64_MAX) {
					ut64 table_size, default_case;
					st64 case_shift;
					if (try_get_jmptbl_info (anal, fcn, op->addr, bb, &table_size, &default_case, &case_shift)) {
						op->ptr = movdisp;
						ret = r_anal_jmptbl_walk (anal, fcn, bb, depth - 1, op->addr, case_shift, op->ptr, op->ptr, anal->config->bits >> 3, table_size, default_case, ret);
					}
					movdisp = UT64_MAX;
#endif
				} else if (is_arm) {
					if (op->ptrsize == 0 && anal->config->bits == 64) {
						if (op->reg && op->ireg) {
							// braa x16, x17 (when bra takes 2 args we skip jump tables dont do that
							goto analopfinish;
						}
						int nreg = (op->reg && *op->reg == 'x')? atoi (op->reg + 1): 0xff;
						if (nreg > 16) {
							// x17 is used for the imports, ignoring that cases
							goto analopfinish;
						}
						if (lea_cnt < 2) {
							while (lea_cnt > 0) {
								r_list_delete (anal->leaddrs, r_list_tail (anal->leaddrs));
								lea_cnt--;
							}
							goto analopfinish;
						}
#if 0
					CODE
						// swift compiler can use ANY register for BR or ADR
						adrp x9, sym.func.100004000
						add x9, x9, 0x114
						adr x10, 0x100004048  // this is why we use op->addr-12
						ldrsw x11, [x9, x8, lsl 2]
						add x10, x10, x11
						br x10 // x10+x11 taking the delta from x9
					ALGO
						x10 = [..4000+0x114]
#endif
						leaddr_pair *la;
						RListIter *iter;
						ut64 table_addr = UT64_MAX;
						int count = 0;
						r_list_foreach_prev (anal->leaddrs, iter, la) {
							table_addr = la->leaddr;
							if (count == 1) {
								break;
							}
							count++;
						}
						// table_addr = 0x100004114;
						ret = r_anal_jmptbl_walk (anal,
								fcn, bb, depth - 1,
								op->addr - 12, 0,
								table_addr,
								op->addr + 4, 4,
								0, // table size is autodetected
								UT64_MAX, ret);
						// skip inlined jumptable
						// idx += table_size;
					} else if (op->ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents (anal, fcn, bb, op->ireg);
						ut64 table_size = 0;
						if (pred_cmpval != UT64_MAX) {
							table_size += pred_cmpval;
						} else {
							table_size += anal->cmpval;
						}
						ret = r_anal_jmptbl_walk (anal, fcn, bb, depth - 1, op->addr, 0, op->addr + op->size,
								op->addr + 4, 1, table_size, UT64_MAX, ret);
						// skip inlined jumptable
						idx += table_size;
					} else if (op->ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op->ireg);
						int tablesize = 1;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += anal->cmpval;
						}
						ret = r_anal_jmptbl_walk (anal, fcn, bb, depth - 1, op->addr, 0, op->addr + op->size,
								op->addr + 4, 2, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize * 2);
					}
				}
			}
			if (anal->lea_jmptbl_ip == op->addr) {
				anal->lea_jmptbl_ip = UT64_MAX;
			}
			if (anal->opt.ijmp) {
				r_anal_function_bb (anal, fcn, op->jump, depth - 1);
				ret = r_anal_function_bb (anal, fcn, op->fail, depth - 1);
				if (overlapped) {
					goto analopfinish;
				}
				if (r_anal_noreturn_at (anal, op->jump) || op->eob) {
					goto analopfinish;
				}
			} else {
analopfinish:
				if (op->type == R_ANAL_OP_TYPE_RJMP) {
					gotoBeach (R_ANAL_RET_NOP);
				} else {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op->val;
			if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
				(void) r_anal_xrefs_set (anal, op->addr, last_push_addr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_WRITE);
			}
			break;
		case R_ANAL_OP_TYPE_UPUSH:
			if ((op->type & R_ANAL_OP_TYPE_REG) && last_is_reg_mov_lea && src0 && src0->reg
					&& src0->reg && !strcmp (src0->reg, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
					(void) r_anal_xrefs_set (anal, op->addr, last_push_addr, R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_WRITE);
				}
			}
			break;
		case R_ANAL_OP_TYPE_RET:
			if (op->family == R_ANAL_OP_FAMILY_PRIV) {
				fcn->type = R_ANAL_FCN_TYPE_INT;
			}
			if (last_is_push && anal->opt.pushret) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = last_push_addr;
				bb->jump = op->jump;
				ret = r_anal_function_bb (anal, fcn, op->jump, depth - 1);
				goto beach;
			}
			if (!op->cond) {
				if (anal->verbose) {
					R_LOG_DEBUG ("RET 0x%08"PFMT64x ". overlap=%s %"PFMT64u" %"PFMT64u,
							addr + delay.un_idx - oplen, r_str_bool (overlapped),
							bb->size, r_anal_function_linear_size (fcn));
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		}
		if (has_stack_regs && arch_destroys_dst) {
			if (op_is_set_bp (op_dst, op_src, bp_reg, sp_reg) && src1) {
				switch (op->type & R_ANAL_OP_TYPE_MASK) {
				case R_ANAL_OP_TYPE_ADD:
					fcn->bp_off = fcn->stack - src1->imm;
					break;
				case R_ANAL_OP_TYPE_SUB:
					fcn->bp_off = fcn->stack + src1->imm;
					break;
				}
			}
		}
#if 0
		if (anal->opt.vars && !varset) {
			// XXX uses op.src/dst and fails because regprofile invalidates the regitems
			// we must ranalop in here to avoid uaf
			r_anal_extract_vars (anal, fcn, op);
		}
#endif
		if (op->type != R_ANAL_OP_TYPE_MOV && op->type != R_ANAL_OP_TYPE_CMOV && op->type != R_ANAL_OP_TYPE_LEA) {
			last_is_reg_mov_lea = false;
		}
		if (op->type != R_ANAL_OP_TYPE_PUSH && op->type != R_ANAL_OP_TYPE_RPUSH) {
			last_is_push = false;
		}
		if (is_arm && op->type != R_ANAL_OP_TYPE_MOV) {
			last_is_mov_lr_pc = false;
		}
		if (has_variadic_reg && !fcn->is_variadic) {
			variadic_reg = "rax";
#if 1
			// XXX arm_cs plugin
			bool dst_is_variadic = dst && dst->reg && variadic_reg;
			if (dst_is_variadic) {
				dst_is_variadic = false;
				RRegItem *ri0 = r_reg_get (anal->reg, dst->reg, R_REG_TYPE_GPR);
				RRegItem *ri1 = r_reg_get (anal->reg, variadic_reg, R_REG_TYPE_GPR);
				if (ri0 && ri1 && ri0->offset == ri1->offset) {
					dst_is_variadic = true;
				}
			}
#else
			bool dst_is_variadic = dst && dst->reg && variadic_reg && !strcmp (dst->reg, variadic_reg);
#endif
			bool op_is_cmp = (op->type == R_ANAL_OP_TYPE_CMP) || op->type == R_ANAL_OP_TYPE_ACMP;
			if (dst_is_variadic && !op_is_cmp) {
				has_variadic_reg = false;
			} else if (op_is_cmp) {
				if (src0 && src0->reg && (dst->reg == src0->reg) && dst_is_variadic) {
					fcn->is_variadic = true;
				}
			}
		}
	}
beach:
	free (op_src);
	free (op_dst);
	free (bp_reg);
	free (sp_reg);
	while (lea_cnt > 0) {
		r_list_delete (anal->leaddrs, r_list_tail (anal->leaddrs));
		lea_cnt--;
	}
	r_anal_op_free (op);
	if (bb && bb->size == 0) {
		r_anal_function_remove_block (fcn, bb);
	}
	r_anal_block_update_hash (bb);
	r_anal_block_unref (bb);
	return ret;
}

R_API int r_anal_function_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, int depth) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, -1);
	return fcn_recurse (anal, fcn, addr, anal->opt.bb_max_size, depth - 1);
}

R_API bool r_anal_check_fcn(RAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	R_RETURN_VAL_IF_FAIL (anal && buf, false);
	RAnalOp op = {
		0
	};
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (r_anal_is_prelude (anal, addr, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, addr + i, buf + i, bufsz - i, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT)) < 1) {
			r_anal_op_fini (&op);
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
				r_anal_op_fini (&op);
				return false;
			}
			brcnt++;
			break;
		case R_ANAL_OP_TYPE_UNK:
			r_anal_op_fini (&op);
			return false;
		default:
			break;
		}
	}
	r_anal_op_fini (&op);
	return (pushcnt + movcnt + brcnt > 5);
}

R_API void r_anal_trim_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (anal && fcn);

	const char *arch = R_UNWRAP4 (anal, arch, session, name);
	const bool is_x86 = arch && !strcmp (arch, "x86"); // HACK

	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (!refs) {
		return;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		int rt = R_ANAL_REF_TYPE_MASK (ref->type);
		// TODO: honor REF_TYPE_ICOD too?
		if (rt == R_ANAL_REF_TYPE_CODE && r_anal_function_contains (fcn, ref->addr)
			&& (!is_x86 || !r_anal_function_contains (fcn, ref->at))) {
			r_anal_xref_del (anal, ref->at, ref->addr);
		}
	}

	RVecAnalRef_free (refs);
}

R_API void r_anal_del_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (anal && fcn);

	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (!refs) {
		return;
	}

	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		RAnalRefType rt = R_ANAL_REF_TYPE_MASK (ref->type);
		// TODO: honor REF_TYPE_ICOD too?
		if (rt == R_ANAL_REF_TYPE_CODE) {
			r_anal_xref_del (anal, ref->at, ref->addr);
		}
	}
	RVecAnalRef_free (refs);
}

/* Does NOT invalidate read-ahead cache. */
R_API int r_anal_function(RAnal *anal, RAnalFunction *fcn, ut64 addr, int reftype) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, 0);
	RPVector *metas = r_meta_get_all_in (anal, addr, R_META_TYPE_ANY);
	if (metas) {
		void **it;
		r_pvector_foreach (metas, it) {
			RAnalMetaItem *meta = ((RIntervalNode *)*it)->data;
			switch (meta->type) {
			case R_META_TYPE_DATA:
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
				r_pvector_free (metas);
				return 0;
			default:
				break;
			}
		}
		r_pvector_free (metas);
	}
	if (anal->opt.norevisit) {
		if (!anal->visited) {
			anal->visited = set_u_new ();
		}
		if (set_u_contains (anal->visited, addr)) {
			R_LOG_ERROR ("visit at 0x%08"PFMT64x" %c", addr, reftype);
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
	fcn->type = (R_ANAL_REF_TYPE_MASK (reftype) == R_ANAL_REF_TYPE_CODE) ? R_ANAL_FCN_TYPE_LOC : R_ANAL_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	if (fcn->callconv && !strcmp (fcn->callconv, "ms")) {
		// Probably should put this on the cc sdb
		const int shadow_store = 0x28; // First 4 args + retaddr
		fcn->stack = fcn->maxstack = fcn->reg_save_area = shadow_store;
	}
	// XXX -1 here results in lots of errors
	int ret = r_anal_function_bb (anal, fcn, addr, anal->opt.depth);
	if (ret < 0) {
		R_LOG_DEBUG ("Failed to analyze basic block at 0x%"PFMT64x, addr);
	}
	return ret;
}

R_API int r_anal_function_del(RAnal *a, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_function_at (a, addr);
	if (fcn) {
		r_anal_function_delete (a, fcn);
		// r_anal_function_free (fcn);
		return true;
	}
	return false;
}

R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type) {
	RList *list = r_anal_get_functions_in (anal, addr);
	RAnalFunction *ret = NULL;
	if (list && !r_list_empty (list)) {
		if (type == R_ANAL_FCN_TYPE_ROOT) {
			RAnalFunction *fcn;
			RListIter *iter;
			r_list_foreach (list, iter, fcn) {
				if (fcn->addr == addr) {
					ret = fcn;
					break;
				}
			}
		} else {
			ret = r_list_first (list);
		}
	}
	r_list_free (list);
	return ret;
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
			if (r_anal_function_contains (fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

R_API RAnalFunction *r_anal_get_function_byname(RAnal *a, const char *name) {
	bool found = false;
	RAnalFunction *f = ht_pp_find (a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RAnalFunctionBB.add() */
// R2580 - R_API bool r_anal_function_add_new_block(RAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, R_BORROW RAnalDiff *diff) {
R_API bool r_anal_function_add_bb(RAnal *a, RAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, R_BORROW RAnalDiff *diff) {
	if (size == 0) { // empty basic blocks allowed?
		R_LOG_WARN ("empty basic block at 0x%08"PFMT64x" is not allowed. pending discussion", addr);
		R_WARN_IF_REACHED ();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		R_LOG_WARN ("can't allocate such big bb of %"PFMT64d" bytes at 0x%08"PFMT64x, (st64)size, addr);
		R_WARN_IF_REACHED ();
		return false;
	}

	RAnalBlock *block = r_anal_get_block_at (a, addr);
	if (block) {
		r_anal_delete_block (block);
		block = NULL;
	}

	// XXX R2_592 - try to remove this check, no need to be x86 specific
	const char *sarch = R_UNWRAP5 (a, arch, session, config, arch);
	const bool is_x86 = sarch && r_str_startswith (sarch, "x86");
	if (is_x86) {
		fcn_recurse (a, fcn, addr, size, -1);
		block = r_anal_get_block_at (a, addr);
		if (block) {
			r_anal_block_set_size (block, size);
		}
	} else {
		block = r_anal_create_block (a, addr, size);
	}

	if (!block) {
		R_LOG_DEBUG ("r_anal_function_add_bb failed in fcn 0x%08"PFMT64x" at 0x%08"PFMT64x, fcn->addr, addr);
		return false;
	}

	r_anal_function_add_block (fcn, block);

	block->jump = jump;
	block->fail = fail;
	if (diff) {
		if (!block->diff) {
			block->diff = r_anal_diff_new ();
		}
		if (block->diff) {
			block->diff->type = diff->type;
			block->diff->addr = diff->addr;
			if (diff->name) {
				R_FREE (block->diff->name);
				block->diff->name = strdup (diff->name);
			}
		}
	}
	return true;
}

R_API int r_anal_function_loops(RAnalFunction *fcn) {
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

R_API int r_anal_function_complexity(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
#if 0
	* CC = E - N + 2P
	* E = the number of edges of the graph.
	* N = the number of nodes of the graph.
	* P = the number of connected components (exit nodes).
#endif
	RAnal *anal = fcn->anal;
	int E = 0, N = 0, P = 0;
	RListIter *iter;
	RAnalBlock *bb;

	r_list_foreach (fcn->bbs, iter, bb) {
		N++; // nodes
		if ((!anal || anal->verbose) && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			R_LOG_WARN ("invalid bb jump/fail pair at 0x%08"PFMT64x" (fcn 0x%08"PFMT64x, bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += r_list_length (bb->switch_op->cases);
		}
	}

	const int result = E - N + (2 * P);
	if (result < 1 && (!anal || anal->verbose)) {
		R_LOG_WARN ("CC = E(%d) - N(%d) + (2 * P(%d)) < 1 at 0x%08"PFMT64x, E, N, P, fcn->addr);
	}
	// R_RETURN_VAL_IF_FAIL (result > 0, 0);
	return result;
}

R_API bool r_anal_function_del_signature(RAnal *a, const char *name) {
	Sdb *db = a->sdb_types;
	const char *s = sdb_const_get (db, name, 0);
	if (!s || strcmp (s, "func")) {
		return false;
	}
	char *sdb_ret = r_str_newf ("func.%s.ret", name);
	char *sdb_args = r_str_newf ("func.%s.args", name);
	int argc = sdb_num_get (db, sdb_args, 0);

	sdb_unset (db, sdb_ret, 0);
	sdb_unset (db, sdb_args, 0);
	int i;
	for (i = 0; i < argc; i++) {
		char *s = r_str_newf ("func.%s.arg.%d", name, i);
		sdb_unset (db, s, 0);
		free (s);
	}
	sdb_unset (db, name, 0);
	free (sdb_ret);
	free (sdb_args);
	return true;
}

// MOVE To function.c
R_API char *r_anal_function_get_signature(RAnalFunction *function) {
	RAnal *a = function->anal;
	const char *realname = NULL, *import_substring = NULL;

	RFlagItem *flag = a->flag_get (a->flb.f, false, function->addr);
	// Can't access R_FLAGS_FS_IMPORTS, since it is defined in r_core.h
	if (flag && flag->space && !strcmp (flag->space->name, "imports")) {
		// Get substring after last dot
		import_substring = r_str_rchr (function->name, NULL, '.');
		if (import_substring) {
			realname = import_substring + 1;
		}
	} else {
		realname = function->name;
	}

	char *ret = NULL, *args = strdup ("");
	char *sdb_ret = r_str_newf ("func.%s.ret", realname);
	char *sdb_args = r_str_newf ("func.%s.args", realname);
	// RList *args_list = r_list_newf ((RListFree) free);
	unsigned int i, j;
	const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);

	int argc = argc_str? atoi (argc_str): 0;

	for (i = 0; i < argc; i++) {
		char *sdb_arg_i = r_str_newf ("func.%s.arg.%d", realname, i);
		char *arg_i = sdb_get (a->sdb_types, sdb_arg_i, 0);
		if (!arg_i) {
			free (sdb_arg_i);
			break;
		}
		// parse commas
		int arg_i_len = strlen (arg_i);
		for (j = 0; j < arg_i_len; j++) {
			if (arg_i[j] == ',') {
				if (j> 0) {
					if (arg_i[j - 1] == '*') {
						// remove whitespace
						memmove (arg_i + j, arg_i + j + 1, strlen (arg_i) - j);
					} else {
						arg_i[j] = ' ';
					}
				} else {
					// untyped arg. fex: `printf(...)`
					memmove (arg_i, arg_i + 1, strlen (arg_i));
				}
			}
		}
		// for variadic arguments, don't include the name
		if (r_str_startswith (arg_i, "...")) {
			char *comma = strchr (arg_i, ' ');
			if (comma) {
				*comma = 0;
			}
		}
		char *new_args = (i + 1 == argc)
			? r_str_newf ("%s%s", args, arg_i)
			: r_str_newf ("%s%s, ", args, arg_i);
		free (args);
		args = new_args;
		free (arg_i);
		free (sdb_arg_i);
	}

	char *sane = r_name_filter_dup (realname);
	if (sane) {
		r_str_replace_ch (sane, ':', '_', true);
		realname = sane;
	}
	ret = r_str_newf ("%s %s (%s);", r_str_get_fail (ret_type, "void"), realname, args);
	free (sane);

	free (sdb_args);
	free (sdb_ret);
	free (args);
	return ret;
}

/* set function signature from string */
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *sig) {
	R_RETURN_VAL_IF_FAIL (a || f || sig, false);
	char *error_msg = NULL;
	const char *out = r_anal_cparse (a, sig, &error_msg);
	if (out) {
		r_anal_save_parsed_type (a, out);
	}
	if (error_msg) {
		R_LOG_ERROR ("%s", error_msg);
		free (error_msg);
	}

	return true;
}

R_API RAnalFunction *r_anal_function_next(RAnal *anal, ut64 addr) {
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

R_API int r_anal_function_count(RAnal *anal, ut64 from, ut64 to) {
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
R_API RAnalBlock *r_anal_function_bbget_in(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	RListIter *iter;
	RAnalBlock *bb;
	const bool aligned = r_anal_is_aligned (anal, addr);
	r_list_foreach (fcn->bbs, iter, bb) {
		if (r_anal_block_contains (bb, addr)) {
			if ((!anal->opt.jmpmid || !aligned || r_anal_block_op_starts_at (bb, addr))) {
			// if (r_anal_block_op_starts_at (bb, addr)) {
				return bb;
			}
			// return bb;
		}
	}
	return NULL;
}

R_API RAnalBlock *r_anal_function_bbget_at(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (fcn && addr != UT64_MAX, NULL);
	RAnalBlock *b = r_anal_get_block_at (anal, addr);
	if (b) {
		return b;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
R_API ut32 r_anal_function_cost(RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RAnal *anal = fcn->anal;
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
			(void) r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ARCH_OP_MASK_BASIC);
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

R_API int r_anal_function_count_edges(const RAnalFunction *fcn, int * R_NULLABLE ebbs) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
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


R_API bool r_anal_function_purity(RAnalFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new (NULL, NULL, NULL);
		if (ht) {
			check_purity (ht, fcn);
			ht_up_free (ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RAnal *anal, RAnalOp* op) {
	RAnalValue *dst = r_vector_at (&op->dsts, 0);
	RAnalValue *src = r_vector_at (&op->srcs, 0);
	const char *opdreg = dst? dst->reg: NULL;
	const char *opsreg = src? src->reg: NULL;
	const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
	if (bpreg) {
		bool dst_is_bp = opdreg && !dst->memref && !strcmp (opdreg, bpreg);
		bool src_is_bp = opsreg && !src->memref && !strcmp (opsreg, bpreg);
		if (op->type == R_ANAL_OP_TYPE_XCHG) {
			return src_is_bp || dst_is_bp;
		}
		return dst_is_bp;
	}
	return false;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
R_API void r_anal_function_check_bp_use(RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (fcn);
	RAnal *anal = fcn->anal;
	RListIter *iter;
	RAnalBlock *bb;
	char *pos;
	// XXX omg this is one of the most awful things ive seen lately
	char str_to_find[40] = {0};
	const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
	if (bpreg) {
		snprintf (str_to_find, sizeof (str_to_find),
			"\"type\":\"reg\",\"value\":\"%s", bpreg);
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		RAnalOp op;
		RAnalValue *src = NULL;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_OPEX);
			if (op.size < 1) {
				op.size = 1;
			}
			src = r_vector_at (&op.srcs, 0);
			switch (op.type) {
			case R_ANAL_OP_TYPE_MOV:
			case R_ANAL_OP_TYPE_LEA:
				if (can_affect_bp (anal, &op)) {
					const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
					if (spreg && src && src->reg && strcmp (src->reg, spreg)) {
						fcn->bp_frame = false;
						r_anal_op_fini (&op);
						free (buf);
						return;
					}
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
				// op.dst is not filled for these operations, so for now,
				// check for bp as dst looks like this; in the future
				// it may be just replaced with call to can_affect_bp
				if (*str_to_find) {
					pos = op.opex.ptr ? strstr (op.opex.ptr, str_to_find) : NULL;
					if (pos && pos - op.opex.ptr < 60) {
						fcn->bp_frame = false;
						r_anal_op_fini (&op);
						free (buf);
						return;
					}
				} else {
					R_LOG_WARN ("No string to find");
				}
				break;
			case R_ANAL_OP_TYPE_XCHG:
				if (*str_to_find) {
					if (op.opex.ptr && strstr (op.opex.ptr, str_to_find)) {
						fcn->bp_frame = false;
						r_anal_op_fini (&op);
						free (buf);
						return;
					}
				} else {
					R_LOG_WARN ("No string to find");
				}
				break;
			case R_ANAL_OP_TYPE_POP:
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			r_anal_op_fini (&op);
		}
		free (buf);
	}
}

typedef struct {
	RAnalFunction *fcn;
	HtUP *visited;
} BlockRecurseCtx;

static bool mark_as_visited(RAnalBlock *bb, void *user) {
	BlockRecurseCtx *ctx = user;
	ht_up_insert (ctx->visited, bb->addr, NULL);
	return true;
}

static bool analize_addr_cb(ut64 addr, void *user) {
	BlockRecurseCtx *ctx = user;
	RAnal *anal = ctx->fcn->anal;
	RAnalBlock *existing_bb = r_anal_get_block_at (anal, addr);
	if (!existing_bb || !r_list_contains (ctx->fcn->bbs, existing_bb)) {
		int old_len = r_list_length (ctx->fcn->bbs);
		r_anal_function_bb (ctx->fcn->anal, ctx->fcn, addr, anal->opt.depth);
		if (old_len != r_list_length (ctx->fcn->bbs)) {
			r_anal_block_recurse (r_anal_get_block_at (anal, addr), mark_as_visited, user);
		}
	}
	ht_up_insert (ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RAnalBlock *bb, void *user) {
	r_anal_block_successor_addrs_foreach (bb, analize_addr_cb, user);
	return true;
}

static void free_ht_up(HtUPKv *kv) {
	ht_up_free ((HtUP *)kv->value);
}

static void update_var_analysis(RAnalFunction *fcn, int align, ut64 from, ut64 to) {
	RAnal *anal = fcn->anal;
	ut64 cur_addr;
	int opsz;
	from = align ? from - (from % align) : from;
	to = align ? R_ROUND (to, align) : to;
	if (UT64_SUB_OVFCHK (to, from)) {
		return;
	}
	ut64 len = to - from;
	ut8 *buf = malloc (len);
	if (!buf) {
		return;
	}
	if (anal->iob.read_at (anal->iob.io, from, buf, len) < len) {
		return;
	}
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		RAnalOp op;
		// int ret = r_anal_op (anal->coreb.core, &op, cur_addr, buf, len, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_VAL);
		int ret = r_anal_op (anal, &op, cur_addr, buf, len, R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			r_anal_op_fini (&op);
			break;
		}
		opsz = op.size;
		r_anal_extract_vars (anal, fcn, &op);
		r_anal_op_fini (&op);
	}
	free (buf);
}

// Clear function variable acesses inside in a block
static void clear_bb_vars(RAnalFunction *fcn, RAnalBlock *bb, ut64 from, ut64 to) {
	int i;
	if (r_pvector_empty (&fcn->vars)) {
		return;
	}
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 addr = r_anal_bb_opaddr_i (bb, i);
		if (addr < from) {
			continue;
		}
		if (addr >= to || addr == UT64_MAX) {
			break;
		}
		RPVector *vars = r_anal_function_get_vars_used_at (fcn, addr);
		if (vars) {
			RPVector *vars_clone = (RPVector *)r_vector_clone ((RVector *)vars);
			void **v;
			r_pvector_foreach (vars_clone, v) {
				r_anal_var_remove_access_at ((RAnalVar *)*v, addr);
			}
			r_pvector_clear (vars_clone);
		}
	}
}

static void update_analysis(RAnal *anal, RList *fcns, HtUP *reachable) {
	// huge slowdown
	RListIter *it, *it2, *tmp;
	RAnalFunction *fcn;
	bool old_jmpmid = anal->opt.jmpmid;
	anal->opt.jmpmid = true;
	r_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RAnalBlock *bb = r_anal_get_block_at (anal, fcn->addr);
		if (!bb) {
			r_anal_function_bb (anal, fcn, fcn->addr, anal->opt.depth);
			bb = r_anal_get_block_at (anal, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new0 ();
		ht_up_insert (ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		r_anal_block_recurse (bb, analize_descendents, &ctx);

		// Remove non-reachable blocks
		r_list_foreach_safe (fcn->bbs, it2, tmp, bb) {
			if (ht_up_find_kv (ht, bb->addr, NULL)) {
				continue;
			}
			HtUP *o_visited = ht_up_find (reachable, fcn->addr, NULL);
			if (!ht_up_find_kv (o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			r_anal_function_remove_block (fcn, bb);
		}

		RList *bbs = r_list_clone (fcn->bbs, NULL);
		r_anal_block_automerge (bbs);
		r_anal_function_delete_unused_vars (fcn);
		r_list_free (bbs);
	}
	anal->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RList *fcns, RAnalFunction *fcn, RAnalBlock *bb, HtUP *reachable) {
	clear_bb_vars (fcn, bb, bb->addr, bb->addr + bb->size);
	if (!r_list_contains (fcns, fcn)) {
		r_list_append (fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new0 ();
		BlockRecurseCtx ctx = { fcn, ht };
		r_anal_block_recurse (r_anal_get_block_at (fcn->anal, fcn->addr), mark_as_visited, &ctx);
		ht_up_insert (reachable, fcn->addr, ht);
	}
	fcn->ninstr -= bb->ninstr;
	r_anal_function_remove_block (fcn, bb);
}

R_API void r_anal_update_analysis_range(RAnal *anal, ut64 addr, int size) {
	R_RETURN_IF_FAIL (anal);
	RListIter *it, *it2, *tmp;
	RAnalBlock *bb;
	RAnalFunction *fcn;
	RList *blocks = r_anal_get_blocks_intersect (anal, addr, size);
	if (r_list_empty (blocks)) {
		r_list_free (blocks);
		return;
	}
	RList *fcns = r_list_new ();
	HtUP *reachable = ht_up_new (NULL, free_ht_up, NULL);
	const int align = r_anal_archinfo (anal, R_ARCH_INFO_CODE_ALIGN);
	const ut64 end_write = addr + size;

	r_list_foreach (blocks, it, bb) {
		if (!r_anal_block_was_modified (bb)) {
			continue;
		}
		r_list_foreach_safe (bb->fcns, it2, tmp, fcn) {
			if (align > 1) {
				if ((end_write < r_anal_bb_opaddr_i (bb, bb->ninstr - 1))
					&& (!bb->switch_op || end_write < bb->switch_op->addr)) {
					// Special case when instructions are aligned and we don't
					// need to worry about a write messing with the jump instructions
					clear_bb_vars (fcn, bb, addr > bb->addr ? addr : bb->addr, end_write);
					update_var_analysis (fcn, align, addr > bb->addr ? addr : bb->addr, end_write);
					r_anal_function_delete_unused_vars (fcn);
					continue;
				}
			}
			calc_reachable_and_remove_block (fcns, fcn, bb, reachable);
		}
	}
	r_list_free (blocks); // This will call r_anal_block_unref to actually remove blocks from RAnal
	update_analysis (anal, fcns, reachable);
	ht_up_free (reachable);
	r_list_free (fcns);
}

R_API void r_anal_function_update_analysis(RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (fcn);
	RListIter *it, *it2, *tmp, *tmp2;
	RAnalBlock *bb;
	RAnalFunction *f;
	RList *fcns = r_list_new ();
	HtUP *reachable = ht_up_new (NULL, free_ht_up, NULL);
	r_list_foreach_safe (fcn->bbs, it, tmp, bb) {
		if (r_anal_block_was_modified (bb)) {
			r_list_foreach_safe (bb->fcns, it2, tmp2, f) {
				calc_reachable_and_remove_block (fcns, f, bb, reachable);
			}
		}
	}
	update_analysis (fcn->anal, fcns, reachable);
	ht_up_free (reachable);
	r_list_free (fcns);
}
