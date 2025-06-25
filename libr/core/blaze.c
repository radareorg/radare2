/* radare - LGPL - Copyright 2017-2023 - pancake, defragger */

#include <r_core.h>

#define USE_SDB 0

typedef enum bb_type {
	TRAP,
	NORMAL,
	JUMP,
	FAIL,
	CALL,
	END,
} bb_type_t;

typedef struct bb {
	ut64 start;
	ut64 end;
	ut64 jump;
	ut64 fail;
	int score;
	int called;
	int reached;
	bb_type_t type;
} bb_t;

typedef struct fcn {
	ut64 addr;
	ut64 size;
	RList *bbs;
	st64 score;
	ut64 ends;
} fcn_t;

static inline bool __is_data_block_cb(RAnalBlock *block, void *user) {
	bool *block_exists = user;
	*block_exists = true;
	return false;
}

static int __isdata(RCore *core, ut64 addr) {
	if (!r_io_is_valid_offset (core->io, addr, false)) {
		// R_LOG_WARN ("Invalid memory address at 0x%08"PFMT64x, addr);
		return 4;
	}

	bool block_exists = false;
	// This will just set block_exists = true if there is any basic block at this addr
	r_anal_blocks_foreach_in (core->anal, addr, __is_data_block_cb, &block_exists);
	if (block_exists) {
		return 1;
	}

	RPVector *list = r_meta_get_all_in (core->anal, addr, R_META_TYPE_ANY);
	void **it;
	int result = 0;
	r_pvector_foreach (list, it) {
		RIntervalNode *node = *it;
		RAnalMetaItem *meta = node->data;
		switch (meta->type) {
		case R_META_TYPE_DATA:
		case R_META_TYPE_STRING:
		case R_META_TYPE_FORMAT:
			result = node->end - addr + 1;
			goto exit;
		default:
			break;
		}
	}
exit:
	r_pvector_free (list);
	return result;
}

static bool fcnAddBB(fcn_t *fcn, bb_t* block) {
	if (!fcn) {
		R_LOG_ERROR ("No function given to add a basic block");
		return false;
	}
	fcn->score += block->score;
	fcn->size += block->end - block->start;
	if (block->type == END) {
		fcn->ends++;
	}
	if (!fcn->bbs) {
		R_LOG_ERROR ("Block list not initialized");
		return false;
	}
	r_list_append (fcn->bbs, block);
	return true;
}

static fcn_t* fcnNew(bb_t *block) {
	fcn_t* fcn = R_NEW0 (fcn_t);
	fcn->addr = block->start;
	fcn->bbs = r_list_new ();
	if (!fcnAddBB (fcn, block)) {
		R_LOG_ERROR ("Failed to add block to function");
	}
	return fcn;
}

static void fcnFree(fcn_t *fcn) {
	r_list_free (fcn->bbs);
	free (fcn);
}

static int bbCMP(void *_a, void *_b) {
	bb_t *a = (bb_t*)_a;
	bb_t *b = (bb_t*)_b;
	return b->start - a->start;
}

static void initBB(bb_t *bb, ut64 start, ut64 end, ut64 jump, ut64 fail, bb_type_t type, int score, int reached, int called) {
	if (bb) {
		bb->start = start;
		bb->end = end;
		bb->jump = jump;
		bb->fail = fail;
		bb->type = type;
		bb->score = score;
		bb->reached = reached;
		bb->called = called;
	}
}

static bool addBB(RList *block_list, ut64 start, ut64 end, ut64 jump, ut64 fail, bb_type_t type, int score) {
	bb_t *bb = R_NEW0 (bb_t);
	initBB (bb, start, end, jump, fail, type, score, 0, 0);
	if (jump < UT64_MAX) {
		bb_t *jump_bb = R_NEW0 (bb_t);
		if (type == CALL) {
			initBB (jump_bb, jump, UT64_MAX, UT64_MAX, UT64_MAX, CALL, 0, 1, 1);
		} else {
			initBB (jump_bb, jump, UT64_MAX, UT64_MAX, UT64_MAX, JUMP, 0, 1, 0);
		}
		r_list_append (block_list, jump_bb);
	}
	if (fail < UT64_MAX) {
		bb_t *fail_bb = R_NEW0 (bb_t);
		initBB (fail_bb, fail, UT64_MAX, UT64_MAX, UT64_MAX, FAIL, 0, 1, 0);
		r_list_append (block_list, fail_bb);
	}
	r_list_append (block_list, bb);
	return true;
}

#if 0
static void dump_block(bb_t *block) {
	eprintf ("s: 0x%"PFMT64x" e: 0x%"PFMT64x" j: 0x%"PFMT64x" f: 0x%"PFMT64x" t: %d\n"
			, block->start, block->end, block->jump, block->fail, block->type);
}

static void dump_blocks(RList* list) {
	RListIter *iter;
	bb_t *block = NULL;
	r_list_foreach (list, iter, block) {
		dump_block (block);
	}
}
#endif

static bool checkFunction(fcn_t *fcn) {
	if (fcn && fcn->ends > 0 && fcn->size > 0) {
		return true;
	}
	return false;
}

static R_MUSTUSE char *function_name(RCore *core, const char *name, ut64 addr) {
	if (name) {
		return strdup (name);
	}
	const char *pfx = r_config_get (core->config, "anal.fcnprefix");
	if (R_STR_ISNOTEMPTY (pfx)) {
		return r_str_newf ("%s.%" PFMT64x, pfx, addr);
	}
	return r_str_newf ("fcn_%" PFMT64x, addr);
}

static void printFunctionCommands(RCore *core, fcn_t* fcn, const char *name) {
	R_RETURN_IF_FAIL (core && fcn);
	RListIter *fcn_iter;
	bb_t *cur = NULL;
	char *_name = function_name (core, name, fcn->addr);
	r_cons_printf ("af+ 0x%08" PFMT64x " %s\n", fcn->addr, _name);
	free (_name);

	r_list_foreach (fcn->bbs, fcn_iter, cur) {
		r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %"PFMT64u" 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
			fcn->addr, cur->start, cur->end - cur->start, cur->jump, cur->fail);
	}
}

static void createFunction(RCore *core, fcn_t* fcn, const char *name) {
	R_RETURN_IF_FAIL (core && fcn);

	RListIter *fcn_iter;
	bb_t *cur = NULL;
	const char *pfx = r_config_get (core->config, "anal.fcnprefix");
	if (!pfx) {
		pfx = "fcn";
	}

	RAnalFunction *f = r_anal_function_new (core->anal);
	if (!f) {
		R_LOG_ERROR ("Failed to create new function");
		return;
	}

	f->name = name? strdup (name): r_str_newf ("%s.%" PFMT64x, pfx, fcn->addr);
	f->addr = fcn->addr;
	f->bits = core->anal->config->bits;
	f->callconv = r_str_constpool_get (&core->anal->constpool, r_anal_cc_default (core->anal));
	f->type = R_ANAL_FCN_TYPE_FCN;

	r_list_foreach (fcn->bbs, fcn_iter, cur) {
		if (__isdata (core, cur->start)) {
			continue;
		}
		r_anal_function_add_bb (core->anal, f, cur->start, (cur->end - cur->start), cur->jump, cur->fail, NULL);
	}
	if (!r_anal_add_function (core->anal, f)) {
		// R_LOG_ERROR ("Failed to insert function");
		r_anal_function_free (f);
		return;
	}
}

#define Fhandled(x) r_strf ("handled.%"PFMT64x, x)
R_API bool core_anal_bbs(RCore *core, const char* input) {
	R_RETURN_VAL_IF_FAIL (core && input, false);
	if (!r_io_is_valid_offset (core->io, core->addr, false)) {
		R_LOG_ERROR ("No valid offset given to analyze");
		return false;
	}
#if USE_SDB
	r_strf_buffer (64);
	Sdb *sdb = NULL;
#else
	HtUP *ht = NULL;
	SetU *ht2 = NULL;
#endif
	const ut64 start = core->addr;
	ut64 size = input[0] ? r_num_math (core->num, input + 1) : core->blocksize;
	ut64 b_start = start;
	RListIter *iter;
	int block_score = 0;
	bb_t *block = NULL;
	int invalid_instruction_barrier = -20000;
	const bool nopskip = r_config_get_b (core->config, "anal.nopskip");

	RList *block_list = r_list_new ();
	if (!block_list) {
		return false;
	}

	R_LOG_DEBUG ("Analyzing [0x%08"PFMT64x"-0x%08"PFMT64x"]", start, start + size);
	R_LOG_DEBUG ("Creating basic blocks");
	ut64 cur = 0, base = 0;
	while (cur >= base && cur < size) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		// magic number to fix huge section of invalid code fuzz files
		if (block_score < invalid_instruction_barrier) {
			break;
		}
		const ut64 dst = start + cur;
		if (dst < start) {
			// fix underflow issue
			break;
		}
		base = cur;
		int dsize = __isdata (core, dst);
		if (dsize > 0) {
			cur += dsize;
			continue;
		}
		RAnalOp *const op = r_core_anal_op (core, dst, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);

		if (!op || !op->mnemonic) {
			block_score -= 10;
			cur++;
			continue;
		}

		if (op->mnemonic[0] == '?') {
			R_LOG_ERROR ("? Bad op at: 0x%08"PFMT64x, dst);
			R_LOG_ERROR ("Cannot analyze opcode at 0x%"PFMT64x, dst);
			block_score -= 10;
			cur++;
			continue;
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_NOP:
			if (nopskip && b_start == dst) {
				b_start = dst + op->size;
			}
			break;
		case R_ANAL_OP_TYPE_CALL:
			if (r_anal_noreturn_at (core->anal, op->jump)) {
				addBB (block_list, b_start, dst + op->size, UT64_MAX, UT64_MAX, END, block_score);
				b_start = dst + op->size;
				block_score = 0;
			} else {
				addBB (block_list, op->jump, UT64_MAX, UT64_MAX, UT64_MAX, CALL, block_score);
			}
			break;
		case R_ANAL_OP_TYPE_JMP:
			addBB (block_list, b_start, dst + op->size, op->jump, UT64_MAX, END, block_score);
			b_start = dst + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_TRAP:
			// we don't want to add trap stuff
			if (b_start < dst) {
				addBB (block_list, b_start, dst, UT64_MAX, UT64_MAX, NORMAL, block_score);
			}
			b_start = dst + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_RET:
			addBB (block_list, b_start, dst + op->size, UT64_MAX, UT64_MAX, END, block_score);
			b_start = dst + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			addBB (block_list, b_start, dst + op->size, op->jump, dst + op->size, NORMAL, block_score);
			b_start = dst + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_UNK:
		case R_ANAL_OP_TYPE_ILL:
			block_score -= 10;
			break;
		default:
			break;
		}
		cur += op->size;
		r_anal_op_free (op);
	}

	R_LOG_DEBUG ("Found %d basic blocks", block_list->length);

	RList *result = r_list_newf (free);
	if (!result) {
		r_list_free (block_list);
		return false;
	}

#if USE_SDB
	sdb = sdb_new0 ();
	if (!sdb) {
		r_list_free (block_list);
		r_list_free (result);
		return false;
	}
#else
	ht = ht_up_new0 ();
	ht2 = set_u_new ();
#endif

	r_list_sort (block_list, (RListComparator)bbCMP);

	R_LOG_DEBUG ("Sorting all blocks done");
	R_LOG_DEBUG ("Creating the complete graph");

	while (block_list->length > 0) {
		block = r_list_pop (block_list);
		if (!block) {
			R_LOG_ERROR ("Failed to get next block from list");
			continue;
		}
		if (r_cons_is_breaked (core->cons)) {
			break;
		}

		if (block_list->length > 0) {
			bb_t *next_block = (bb_t*) r_list_iter_get_data (block_list->tail);
			if (!next_block) {
				R_LOG_ERROR ("No next block to compare with!");
			}

			// current block is just a split block
			if (block->start == next_block->start && block->end == UT64_MAX) {
				if (block->type != CALL && next_block->type != CALL) {
					next_block->reached = block->reached + 1;
				}
				free (block);
				continue;
			}

			// block and next_block share the same start so we copy the
			// contenct of the block into the next_block and skip the current one
			if (block->start == next_block->start && next_block->end == UT64_MAX) {
				if (next_block->type != CALL)  {
					block->reached += 1;
				}
				*next_block = *block;
				free (block);
				continue;
			}

			if (block->end < UT64_MAX && next_block->start < block->end && next_block->start > block->start) {
				if (next_block->jump == UT64_MAX) {
					next_block->jump = block->jump;
				}

				if (next_block->fail == UT64_MAX) {
					next_block->fail = block->fail;
				}

				next_block->end = block->end;
				block->end = next_block->start;
				block->jump = next_block->start;
				block->fail = UT64_MAX;
				next_block->type = block->type;
				if (next_block->type != CALL)  {
					next_block->reached += 1;
				}
			}
		}
#if USE_SDB
		sdb_ptr_set (sdb, r_strf ("bb.0x%08"PFMT64x, block->start), block, 0);
#else
		ht_up_insert (ht, block->start, block);
#endif
		r_list_append (result, block);
	}

	// finally search for functions
	// we simply assume that non reached blocks or called blocks
	// are functions
	R_LOG_DEBUG ("Trying to create functions");

	r_list_foreach (result, iter, block) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (block && (block->reached == 0 || block->called >= 1)) {
			fcn_t* current_function = fcnNew (block);
			RStack *stack = r_stack_new (100);
			bb_t *jump = NULL;
			bb_t *fail = NULL;
			bb_t *cur = NULL;

			if (!r_stack_push (stack, (void*)block)) {
				R_LOG_ERROR ("Failed to push initial block");
			}

			while (!r_stack_is_empty (stack)) {
				cur = (bb_t*) r_stack_pop (stack);
				if (!cur) {
					continue;
				}
#if USE_SDB
				sdb_num_set (sdb, Fhandled (cur->start), 1, 0);
#else
				set_u_add (ht2, cur->start);
#endif
				if (cur->score < 0) {
					fcnFree (current_function);
					current_function = NULL;
					break;
				}
				// we ignore negative blocks
				if ((st64)(cur->end - cur->start) < 0) {
					break;
				}

				fcnAddBB (current_function, cur);

#if USE_SDB
				if (cur->jump < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->jump), NULL)) {
					jump = sdb_ptr_get (sdb, r_strf ("bb.0x%08"PFMT64x, cur->jump), NULL);
#else
				if (cur->jump < UT64_MAX && !set_u_contains (ht2, cur->jump)) {
					jump = ht_up_find (ht, cur->jump, NULL);
#endif
					if (!jump) {
						R_LOG_ERROR ("Failed to get jump block at 0x%"PFMT64x, cur->jump);
						continue;
					}
					if (!r_stack_push (stack, (void*)jump)) {
						R_LOG_ERROR ("Failed to push jump block to stack");
					}
				}
#if USE_SDB
				if (cur->fail < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->fail), NULL)) {
					fail = sdb_ptr_get (sdb, r_strf ("bb.0x%08" PFMT64x, cur->fail), NULL);
#else
				if (cur->fail < UT64_MAX && !set_u_contains (ht2, cur->fail)) {
					fail = ht_up_find (ht, cur->fail, NULL);
#endif
					if (!fail) {
						R_LOG_ERROR ("Failed to get fail block at 0x%"PFMT64x, cur->fail);
						continue;
					}
					if (!r_stack_push (stack, (void*)fail)) {
						R_LOG_ERROR ("Failed to push jump block to stack");
					}
				}
			}

			// function creation complete
			if (current_function) {
				if (checkFunction (current_function)) {
					if (input[0] == '*') {
						printFunctionCommands (core, current_function, NULL);
					} else {
						createFunction (core, current_function, NULL);
					}
				}
				fcnFree (current_function);
			}

			r_stack_free (stack);
		}
	}

#if USE_SDB
	sdb_free (sdb);
#else
	ht_up_free (ht);
	set_u_free (ht2);
#endif
	r_list_free (result);
	r_list_free (block_list);
	return true;
}

R_API bool core_anal_bbs_range(RCore *core, const char* input) {
	if (!r_io_is_valid_offset (core->io, core->addr, false)) {
		R_LOG_ERROR ("No valid offset given to analyze");
		return false;
	}
#if USE_SDB
	r_strf_buffer (64);
	Sdb *sdb = NULL;
#else
	HtUP *ht = NULL;
	SetU *ht2 = NULL;
#endif
	ut64 cur = 0;
	ut64 start = core->addr;
	ut64 size = input[0] ? r_num_math (core->num, input + 1) : core->blocksize;
	ut64 b_start = start;
	RAnalOp *op;
	RListIter *iter;
	int block_score = 0;
	bb_t *block = NULL;
	int invalid_instruction_barrier = -20000;
	ut64 lista[1024] = {0};
	int idx = 0;
	int x;

	RList *block_list = r_list_new ();
	if (!block_list) {
		R_LOG_ERROR ("Failed to create block_list");
	}
	R_LOG_DEBUG ("Analyzing [0x%08"PFMT64x"-0x%08"PFMT64x"]", start, start + size);
	R_LOG_DEBUG ("Creating basic blocks");
	lista[idx++] = b_start;
	for (x = 0; x < 1024; x++) {
		if (lista[x] != 0) {
			cur = 0;
			b_start = lista[x];
			lista[x] = 0;
			while (cur < size) {
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				// magic number to fix huge section of invalid code fuzz files
				if (block_score < invalid_instruction_barrier) {
					break;
				}

				bool bFound = false;
				// check if offset don't have into block_list, to end branch analisys
				r_list_foreach (block_list, iter, block) {
					if ((block->type == END || block->type == NORMAL) && b_start + cur == block->start ) {
						bFound = true;
						break;
					}
				}

				if (!bFound) {
					op = r_core_anal_op (core, b_start + cur, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_DISASM);

					if (!op || !op->mnemonic) {
						block_score -= 10;
						cur++;
						continue;
					}

					if (op->mnemonic[0] == '?') {
						R_LOG_ERROR ("? Bad op at: 0x%08"PFMT64x, cur + b_start);
						R_LOG_ERROR ("Cannot analyze opcode at %"PFMT64x, b_start + cur);
						block_score -= 10;
						cur++;
						continue;
					}
					//eprintf ("0x%08"PFMT64x" %s\n", b_start + cur, op->mnemonic);
					switch (op->type) {
					case R_ANAL_OP_TYPE_RET:
						addBB (block_list, b_start, b_start + cur + op->size, UT64_MAX, UT64_MAX, END, block_score);
						cur = size;
						break;
					case R_ANAL_OP_TYPE_UJMP:
					case R_ANAL_OP_TYPE_IRJMP:
						addBB (block_list, b_start, b_start + cur + op->size, op->jump, UT64_MAX, END, block_score);
						cur = size;
						break;
					case R_ANAL_OP_TYPE_JMP:
						addBB (block_list, b_start, b_start + cur + op->size, op->jump, UT64_MAX, END, block_score);
						b_start = op->jump;
						cur = 0;
						block_score = 0;
						break;
					case R_ANAL_OP_TYPE_CJMP:
						//eprintf ("bb_b  0x%08"PFMT64x" - 0x%08"PFMT64x"\n", b_start, b_start + cur + op->size);
						addBB (block_list, b_start, b_start + cur + op->size, op->jump, b_start + cur + op->size, NORMAL, block_score);
						b_start = b_start + cur + op->size;
						cur = 0;
						if (idx < 1024) {
							lista[idx++] = op->jump;
						}
						block_score = 0;
						break;
					case R_ANAL_OP_TYPE_TRAP:
					case R_ANAL_OP_TYPE_UNK:
					case R_ANAL_OP_TYPE_ILL:
						block_score -= 10;
						cur += op->size;
						break;
					default:
						cur += op->size;
						break;
					}
					r_anal_op_free (op);
					op = NULL;
				} else {
					// we have this offset into previous analyzed block, exit from this path flow.
					break;
				}
			}
		}
	}
	R_LOG_DEBUG ("Found %d basic blocks", block_list->length);

	RList *result = r_list_newf (free);
	if (!result) {
		r_list_free (block_list);
		return false;
	}

#if USE_SDB
	sdb = sdb_new0 ();
	if (!sdb) {
		r_list_free (block_list);
		r_list_free (result);
		return false;
	}
#else
	ht = ht_up_new0 ();
	ht2 = set_u_new ();
#endif

	r_list_sort (block_list, (RListComparator)bbCMP);

	R_LOG_DEBUG ("Sorting all blocks done");
	R_LOG_DEBUG ("Creating the complete graph");

	while (block_list->length > 0) {
		block = r_list_pop (block_list);
		if (!block) {
			R_LOG_ERROR ("Failed to get next block from list");
			continue;
		}
		if (r_cons_is_breaked (core->cons)) {
			break;
		}

		if (block_list->length > 0) {
			bb_t *next_block = (bb_t*)r_list_iter_get_data (block_list->tail);
			if (!next_block) {
				R_LOG_ERROR ("No next block to compare with!");
			}

			// current block is just a split block
			if (block->start == next_block->start && block->end == UT64_MAX) {
				if (block->type != CALL && next_block->type != CALL) {
					next_block->reached = block->reached + 1;
				}
				free (block);
				continue;
			}

			// block and next_block share the same start so we copy the
			// contenct of the block into the next_block and skip the current one
			if (block->start == next_block->start && next_block->end == UT64_MAX) {
				if (next_block->type != CALL) {
					block->reached += 1;
				}
				*next_block = *block;
				free (block);
				continue;
			}

			if (block->end < UT64_MAX && next_block->start < block->end && next_block->start > block->start) {
				if (next_block->jump == UT64_MAX) {
					next_block->jump = block->jump;
				}

				if (next_block->fail == UT64_MAX) {
					next_block->fail = block->fail;
				}

				next_block->end = block->end;
				block->end = next_block->start;
				block->jump = next_block->start;
				block->fail = UT64_MAX;
				next_block->type = block->type;
				if (next_block->type != CALL) {
					next_block->reached++;
				}
			}
		}

#if USE_SDB
		sdb_ptr_set (sdb, r_strf ("bb.0x%08"PFMT64x, block->start), block, 0);
#else
		ht_up_insert (ht, block->start, block);
#endif
		r_list_append (result, block);
	}

	// finally add bb to function
	// we simply assume that non reached blocks
	// don't are part of the created function
	R_LOG_DEBUG ("Trying to create functions");

	r_list_foreach (result, iter, block) {
		if (r_cons_is_breaked (core->cons)) {
			break;
		}
		if (block && (block->reached == 0)) {
			fcn_t* current_function = fcnNew (block);
			RStack *stack = r_stack_new (100);
			bb_t *jump = NULL;
			bb_t *fail = NULL;
			bb_t *cur = NULL;

			if (!r_stack_push (stack, (void*)block)) {
				R_LOG_ERROR ("Failed to push initial block");
			}

			while (!r_stack_is_empty (stack)) {
				cur = (bb_t*)r_stack_pop (stack);
				if (!cur) {
					continue;
				}
#if USE_SDB
				sdb_num_set (sdb, Fhandled (cur->start), 1, 0);
#else
				set_u_add (ht2, cur->start);
#endif
				if (cur->score < 0) {
					fcnFree (current_function);
					current_function = NULL;
					break;
				}
				// we ignore negative blocks
				if ((st64)(cur->end - cur->start) < 0) {
					break;
				}

				fcnAddBB (current_function, cur);

#if USE_SDB
				if (cur->jump < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->jump), NULL)) {
					jump = _ptr_get (sdb, r_strf ("bb.0x%08"PFMT64x, cur->jump), NULL);
#else
				if (cur->jump < UT64_MAX && !set_u_contains (ht2, cur->jump)) {
					jump = ht_up_find (ht, cur->jump, NULL);
#endif
					if (!jump) {
						R_LOG_ERROR ("Failed to get jump block at 0x%"PFMT64x, cur->jump);
						continue;
					}
					if (!r_stack_push (stack, (void*)jump)) {
						R_LOG_ERROR ("Failed to push jump block to stack");
					}
				}

#if USE_SDB
				if (cur->fail < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->fail), NULL)) {
					fail = sdb_ptr_get (sdb, r_strf ("bb.0x%08" PFMT64x, cur->fail), NULL);
#else
				if (cur->fail < UT64_MAX && !set_u_contains (ht2, cur->fail)) {
					fail = ht_up_find (ht, cur->fail, NULL);
#endif
					if (!fail) {
						R_LOG_ERROR ("Failed to get fail block at 0x%"PFMT64x, cur->fail);
						continue;
					}
					if (!r_stack_push (stack, (void*)fail)) {
						R_LOG_ERROR ("Failed to push jump block to stack");
					}
				}
			}

			// function creation complete
			if (current_function) {
				// check for supply function address match with current block
				if (current_function->addr == start) {
					// set supply function size
					current_function->size = size;
					if (checkFunction (current_function)) {
						if (input[0] == '*') {
							printFunctionCommands (core, current_function, NULL);
						} else {
							createFunction (core, current_function, NULL);
						}
						fcnFree (current_function);
						r_stack_free (stack);
						break;
					}
				}
				fcnFree (current_function);
			}
			r_stack_free (stack);
		}
	}

#if USE_SDB
	sdb_free (sdb);
#else
	ht_up_free (ht);
	set_u_free (ht2);
#endif
	r_list_free (result);
	r_list_free (block_list);
	return true;
}
