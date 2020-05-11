/* radare - LGPL - Copyright 2017 - pancake, defragger */

#include <r_core.h>

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

static bool __is_data_block_cb(RAnalBlock *block, void *user) {
	bool *block_exists = user;
	*block_exists = true;
	return false;
}

static int __isdata(RCore *core, ut64 addr) {
	if (!r_io_is_valid_offset (core->io, addr, false)) {
		// eprintf ("Warning: Invalid memory address at 0x%08"PFMT64x"\n", addr);
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

static bool fcnAddBB (fcn_t *fcn, bb_t* block) {
	if (!fcn) {
		eprintf ("No function given to add a basic block\n");
		return false;
	}
	fcn->score += block->score;
	fcn->size += block->end - block->start;
	if (block->type == END) {
		fcn->ends++;
	}
	if (!fcn->bbs) {
		eprintf ("Block list not initialized\n");
		return false;
	}
	r_list_append (fcn->bbs, block);
	return true;
}

static fcn_t* fcnNew (bb_t *block) {
	fcn_t* fcn = R_NEW0 (fcn_t);
	if (!fcn) {
		eprintf ("Failed to allocate memory for function\n");
		return NULL;
	}
	fcn->addr = block->start;
	fcn->bbs = r_list_new ();
	if (!fcnAddBB (fcn, block)) {
		eprintf ("Failed to add block to function\n");
	}
	return fcn;
}

static void fcnFree (fcn_t *fcn) {
	r_list_free (fcn->bbs);
	free (fcn);
}

static int bbCMP (void *_a, void *_b) {
	bb_t *a = (bb_t*)_a;
	bb_t *b = (bb_t*)_b;
	return b->start - a->start;
}

static void initBB (bb_t *bb, ut64 start, ut64 end, ut64 jump, ut64 fail, bb_type_t type, int score, int reached, int called) {
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
	bb_t *bb = (bb_t*) R_NEW0 (bb_t);
	if (!bb) {
		eprintf ("Failed to calloc mem for new basic block!\n");
		return false;
	}
	initBB (bb, start, end, jump, fail, type, score, 0, 0);
	if (jump < UT64_MAX) {
		bb_t *jump_bb = (bb_t*) R_NEW0 (bb_t);
		if (!jump_bb) {
			eprintf ("Failed to allocate memory for jump block\n");
			free (bb);
			return false;
		}
		if (type == CALL) {
			initBB (jump_bb, jump, UT64_MAX, UT64_MAX, UT64_MAX, CALL, 0, 1, 1);
		} else {
			initBB (jump_bb, jump, UT64_MAX, UT64_MAX, UT64_MAX, JUMP, 0, 1, 0);
		}
		r_list_append (block_list, jump_bb);
	}
	if (fail < UT64_MAX) {
		bb_t *fail_bb = (bb_t*) R_NEW0 (bb_t);
		if (!fail_bb) {
			eprintf ("Failed to allocate memory for fail block\n");
			free (bb);
			return false;
		}
		initBB (fail_bb, fail, UT64_MAX, UT64_MAX, UT64_MAX, FAIL, 0, 1, 0);
		r_list_append (block_list, fail_bb);
	}
	r_list_append (block_list, bb);
	return true;
}

void dump_block(bb_t *block) {
	eprintf ("s: 0x%"PFMT64x" e: 0x%"PFMT64x" j: 0x%"PFMT64x" f: 0x%"PFMT64x" t: %d\n"
			, block->start, block->end, block->jump, block->fail, block->type);
}

void dump_blocks (RList* list) {
	RListIter *iter;
	bb_t *block = NULL;
	r_list_foreach (list, iter, block) {
		dump_block(block);
	}
}

static bool checkFunction(fcn_t *fcn) {
	if (fcn && fcn->ends > 0 && fcn->size > 0) {
		return true;
	}

	return false;
}

static void printFunctionCommands(RCore *core, fcn_t* fcn, const char *name) {
	if (!fcn) {
		eprintf ("No function given to print\n");
		return;
	}

	RListIter *fcn_iter;
	bb_t *cur = NULL;
	const char *pfx = r_config_get (core->config, "anal.fcnprefix");
	if (!pfx) {
		pfx = "fcn";
	}

	char *_name = name? (char *) name: r_str_newf ("%s.%" PFMT64x, pfx, fcn->addr);
	r_cons_printf ("af+ 0x%08" PFMT64x " %s\n", fcn->addr, _name);
	if (!name) {
		free (_name);
	}

	r_list_foreach (fcn->bbs, fcn_iter, cur) {
		r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %llu 0x%08"PFMT64x" 0x%08"PFMT64x"\n"
			, fcn->addr, cur->start, cur->end - cur->start, cur->jump, cur->fail);
	}
}

static void createFunction(RCore *core, fcn_t* fcn, const char *name) {
	if (!fcn) {
		eprintf ("No function given to create\n");
		return;
	}

	RListIter *fcn_iter;
	bb_t *cur = NULL;
	const char *pfx = r_config_get (core->config, "anal.fcnprefix");
	if (!pfx) {
		pfx = "fcn";
	}

	RAnalFunction *f = r_anal_function_new (core->anal);
	if (!f) {
		eprintf ("Failed to create new function\n");
		return;
	}

	f->name = name? strdup (name): r_str_newf ("%s.%" PFMT64x, pfx, fcn->addr);
	f->addr = fcn->addr;
	f->bits = core->anal->bits;
	f->cc = r_str_constpool_get (&core->anal->constpool, r_anal_cc_default (core->anal));
	f->type = R_ANAL_FCN_TYPE_FCN;

	r_list_foreach (fcn->bbs, fcn_iter, cur) {
		if (__isdata (core, cur->start)) {
			continue;
		}
		r_anal_fcn_add_bb (core->anal, f, cur->start, (cur->end - cur->start), cur->jump, cur->fail, NULL);
	}
	if (!r_anal_add_function (core->anal, f)) {
		// eprintf ("Failed to insert function\n");
		r_anal_function_free (f);
		return;
	}
}

#define Fhandled(x) sdb_fmt("handled.%"PFMT64x"", x)
R_API bool core_anal_bbs(RCore *core, const char* input) {
	if (!r_io_is_valid_offset (core->io, core->offset, false)) {
		eprintf ("No valid offset given to analyze\n");
		return false;
	}

	Sdb *sdb = NULL;
	const ut64 start = core->offset;
	ut64 size = input[0] ? r_num_math (core->num, input + 1) : core->blocksize;
	ut64 b_start = start;
	RListIter *iter;
	int block_score = 0;
	RList *block_list;
	bb_t *block = NULL;
	int invalid_instruction_barrier = -20000;
	bool debug = r_config_get_i (core->config, "cfg.debug");
	bool nopskip = r_config_get_i (core->config, "anal.nopskip");

	block_list = r_list_new ();
	if (!block_list) {
		eprintf ("Failed to create block_list\n");
	}

	if (debug) {
		eprintf ("Analyzing [0x%08"PFMT64x"-0x%08"PFMT64x"]\n", start, start + size);
		eprintf ("Creating basic blocks\b");
	}
	ut64 cur = 0, base = 0;
	while (cur >= base && cur < size) {
		if (r_cons_is_breaked ()) {
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
		RAnalOp *const op = r_core_anal_op (core, dst, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_DISASM);

		if (!op || !op->mnemonic) {
			block_score -= 10;
			cur++;
			continue;
		}

		if (op->mnemonic[0] == '?') {
			eprintf ("? Bad op at: 0x%08"PFMT64x"\n", dst);
			eprintf ("Cannot analyze opcode at 0x%"PFMT64x"\n", dst);
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

	if (debug) {
		eprintf ("Found %d basic blocks\n", block_list->length);
	}

	RList *result = r_list_newf (free);
	if (!result) {
		r_list_free (block_list);
		eprintf ("Failed to create resulting list\n");
		return false;
	}

	sdb = sdb_new0 ();
	if (!sdb) {
		eprintf ("Failed to initialize sdb db\n");
		r_list_free (block_list);
		r_list_free (result);
		return false;
	}

	r_list_sort (block_list, (RListComparator)bbCMP);

	if (debug) {
		eprintf ("Sorting all blocks done\n");
		eprintf ("Creating the complete graph\n");
	}

	while (block_list->length > 0) {
		block = r_list_pop (block_list);
		if (!block) {
			eprintf ("Failed to get next block from list\n");
			continue;
		}
		if (r_cons_is_breaked ()) {
			break;
		}

		if (block_list->length > 0) {
			bb_t *next_block = (bb_t*) r_list_iter_get_data (block_list->tail);
			if (!next_block) {
				eprintf ("No next block to compare with!\n");
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

		sdb_ptr_set (sdb, sdb_fmt ("bb.0x%08"PFMT64x, block->start), block, 0);
		r_list_append (result, block);
	}

	// finally search for functions
	// we simply assume that non reached blocks or called blocks
	// are functions
	if (debug) {
		eprintf ("Trying to create functions\n");
	}

	r_list_foreach (result, iter, block) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (block && (block->reached == 0 || block->called >= 1)) {
			fcn_t* current_function = fcnNew (block);
			RStack *stack = r_stack_new (100);
			bb_t *jump = NULL;
			bb_t *fail = NULL;
			bb_t *cur = NULL;

			if (!r_stack_push (stack, (void*)block)) {
				eprintf ("Failed to push initial block\n");
			}

			while (!r_stack_is_empty (stack)) {
				cur = (bb_t*) r_stack_pop (stack);
				if (!cur) {
					continue;
				}
				sdb_num_set (sdb, Fhandled(cur->start), 1, 0);
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

				if (cur->jump < UT64_MAX && !sdb_num_get (sdb, Fhandled(cur->jump), NULL)) {
					jump = sdb_ptr_get (sdb, sdb_fmt ("bb.0x%08"PFMT64x, cur->jump), NULL);
					if (!jump) {
						eprintf ("Failed to get jump block at 0x%"PFMT64x"\n", cur->jump);
						continue;
					}
					if (!r_stack_push (stack, (void*)jump)) {
						eprintf ("Failed to push jump block to stack\n");
					}
				}

				if (cur->fail < UT64_MAX && !sdb_num_get (sdb, Fhandled(cur->fail), NULL)) {
					fail = sdb_ptr_get (sdb, sdb_fmt ("bb.0x%08" PFMT64x, cur->fail), NULL);
					if (!fail) {
						eprintf ("Failed to get fail block at 0x%"PFMT64x"\n", cur->fail);
						continue;
					}
					if (!r_stack_push (stack, (void*)fail)) {
						eprintf ("Failed to push jump block to stack\n");
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

	sdb_free (sdb);
	r_list_free (result);
	r_list_free (block_list);
	return true;
}

R_API bool core_anal_bbs_range (RCore *core, const char* input) {
	if (!r_io_is_valid_offset (core->io, core->offset, false)) {
		eprintf ("No valid offset given to analyze\n");
		return false;
	}

	Sdb *sdb = NULL;
	ut64 cur = 0;
	ut64 start = core->offset;
	ut64 size = input[0] ? r_num_math (core->num, input + 1) : core->blocksize;
	ut64 b_start = start;
	RAnalOp *op;
	RListIter *iter;
	int block_score = 0;
	RList *block_list;
	bb_t *block = NULL;
	int invalid_instruction_barrier = -20000;
	bool debug = r_config_get_i (core->config, "cfg.debug");
	ut64 lista[1024] = { 0 };
	int idx = 0;
	int x;

	block_list = r_list_new ();
	if (!block_list) {
		eprintf ("Failed to create block_list\n");
	}
	if (debug) {
		eprintf ("Analyzing [0x%08"PFMT64x"-0x%08"PFMT64x"]\n", start, start + size);
		eprintf ("Creating basic blocks\b");
	}
	lista[idx++] = b_start;
	for (x = 0; x < 1024; x++) {
		if (lista[x] != 0) {
			cur =0;
			b_start = lista[x];
			lista[x] = 0;
			while (cur < size) {
				if (r_cons_is_breaked ()) {
					break;
				}
				// magic number to fix huge section of invalid code fuzz files
				if (block_score < invalid_instruction_barrier) {
					break;
				}

				bool bFound = false;
				// check if offset don't have into block_list, to end branch analisys
				r_list_foreach (block_list, iter, block) {
					if ( (block->type == END || block->type == NORMAL) && b_start + cur == block->start ) {
						bFound = true;
						break;
					}
				}

				if (!bFound) {
					op = r_core_anal_op (core, b_start + cur, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_DISASM);

					if (!op || !op->mnemonic) {
						block_score -= 10;
						cur++;
						continue;
					}

					if (op->mnemonic[0] == '?') {
						eprintf ("? Bad op at: 0x%08"PFMT64x"\n", cur + b_start);
						eprintf ("Cannot analyze opcode at %"PFMT64x"\n", b_start + cur);
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
				}
				else {
					// we have this offset into previous analyzed block, exit from this path flow.
					break;
				}
			}
		}
	}
	if (debug) {
		eprintf ("Found %d basic blocks\n", block_list->length);
	}

	RList *result = r_list_newf (free);
	if (!result) {
		r_list_free (block_list);
		eprintf ("Failed to create resulting list\n");
		return false;
	}

	sdb = sdb_new0 ();
	if (!sdb) {
		eprintf ("Failed to initialize sdb db\n");
		r_list_free (block_list);
		r_list_free (result);
		return false;
	}

	r_list_sort (block_list, (RListComparator)bbCMP);

	if (debug) {
		eprintf ("Sorting all blocks done\n");
		eprintf ("Creating the complete graph\n");
	}

	while (block_list->length > 0) {
		block = r_list_pop (block_list);
		if (!block) {
			eprintf ("Failed to get next block from list\n");
			continue;
		}
		if (r_cons_is_breaked ()) {
			break;
		}

		if (block_list->length > 0) {
			bb_t *next_block = (bb_t*)r_list_iter_get_data (block_list->tail);
			if (!next_block) {
				eprintf ("No next block to compare with!\n");
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
					next_block->reached += 1;
				}
			}
		}

		sdb_ptr_set (sdb, sdb_fmt ("bb.0x%08"PFMT64x, block->start), block, 0);
		r_list_append (result, block);
	}

	// finally add bb to function
	// we simply assume that non reached blocks
	// don't are part of the created function
	if (debug) {
		eprintf ("Trying to create functions\n");
	}

	r_list_foreach (result, iter, block) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (block && (block->reached == 0)) {
			fcn_t* current_function = fcnNew (block);
			RStack *stack = r_stack_new (100);
			bb_t *jump = NULL;
			bb_t *fail = NULL;
			bb_t *cur = NULL;

			if (!r_stack_push (stack, (void*)block)) {
				eprintf ("Failed to push initial block\n");
			}

			while (!r_stack_is_empty (stack)) {
				cur = (bb_t*)r_stack_pop (stack);
				if (!cur) {
					continue;
				}
				sdb_num_set (sdb, Fhandled (cur->start), 1, 0);
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

				if (cur->jump < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->jump), NULL)) {
					jump = sdb_ptr_get (sdb, sdb_fmt ("bb.0x%08"PFMT64x, cur->jump), NULL);
					if (!jump) {
						eprintf ("Failed to get jump block at 0x%"PFMT64x"\n", cur->jump);
						continue;
					}
					if (!r_stack_push (stack, (void*)jump)) {
						eprintf ("Failed to push jump block to stack\n");
					}
				}

				if (cur->fail < UT64_MAX && !sdb_num_get (sdb, Fhandled (cur->fail), NULL)) {
					fail = sdb_ptr_get (sdb, sdb_fmt ("bb.0x%08" PFMT64x, cur->fail), NULL);
					if (!fail) {
						eprintf ("Failed to get fail block at 0x%"PFMT64x"\n", cur->fail);
						continue;
					}
					if (!r_stack_push (stack, (void*)fail)) {
						eprintf ("Failed to push jump block to stack\n");
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
						}
						else {
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

	sdb_free (sdb);
	r_list_free (result);
	r_list_free (block_list);
	return true;
}
