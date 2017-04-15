/* radare - LGPL - Copyright 2017 - pancake */

/* blaze is the codename for the new analysis engine for radare2 */
/* by --pancake thanks to @defragger and @nguyen for ideas */

#include <r_core.h>

typedef struct {
	ut64 addr;
	ut64 len;
	ut8 *buf;
	ut64 bb_addr;
	RList *bbs;
	RList *nextbbs;
	RList *fcnents;
	Sdb *bbdb; /* bbaddr=bbsize */
	Sdb *fcdb; /* fcnaddr */
	ut64 last;
	bool wasPad;
	RCore *core;
} AbbState;

typedef struct {
	ut64 addr;
	int bits;
	int type;
	char *name;
} AbbAddr;

static int bbExist(AbbState *abb, ut64 addr) {
	RAnalBlock *bb;
	RListIter *iter;
	if (abb->bbdb) {
		return (int) sdb_num_get (abb->bbdb, sdb_fmt (0, "0x%08" PFMT64x, addr), NULL);
	}
	r_list_foreach (abb->bbs, iter, bb) {
		if (bb->addr == addr) {
			return bb->size;
		}
	}
	return 0;
}

#if 0
static int fcnExist(AbbState *abb, ut64 addr) {
	AbbAddr *a;
	RListIter *iter;
#if 0
	if (abb->bbdb) {
		return (int) sdb_num_get (abb->bbdb, sdb_fmt (0, "fcn.0x%08" PFMT64x, addr), NULL);
	}
#endif
	r_list_foreach (abb->fcnents, iter, a) {
		if (a->addr == addr) {
			return true;
		}
	}
	return false;
}
#endif

static AbbState *abbstate_new(ut64 len) {
	ut8 *buf = malloc (len);
	if (!buf) {
		return NULL;
	}
	AbbState *abb = R_NEW0 (AbbState);
	if (!abb) {
		free (buf);
		return NULL;
	}
	abb->buf = buf;
	abb->len = len;
	abb->bbs = r_list_new ();
	if (!abb->bbs) {
		free (buf);
		return NULL;
	}
	abb->nextbbs = r_list_newf (free);
	abb->fcnents = r_list_newf (free);
	abb->bbdb = sdb_new0 ();
	// TODO: add more boring nullchks
	return abb;
}

static void abbstate_free(AbbState *as) {
	r_list_free (as->bbs);
	r_list_free (as->nextbbs);
	sdb_free (as->bbdb);
	sdb_free (as->fcdb);
	free (as->buf);
	free (as);
}

static bool appendNextBB(AbbState *abb, ut64 addr, int bits, int type) {
	RListIter *iter;
	// RAnalBlock *bb;
	AbbAddr *n;
	if (!addr || addr == UT64_MAX || bbExist (abb, addr)) {
		return false;
	}
	// XXX slow path use SDB HERE
	r_list_foreach (abb->nextbbs, iter, n) {
		if (addr == n->addr) {
			return false;
		}
	}
	n = R_NEW0 (AbbAddr);
	n->addr = addr;
	n->bits = bits;
	n->type = type;
	r_list_append (abb->nextbbs, n);
	return true;
}

static RAnalBlock *parseOpcode(AbbState *abb, RAnalOp *aop) {
	RFlagItem *fi = r_flag_get_i (abb->core->flags, aop->addr + aop->size);
	bool eob = fi? true: false; //strncmp (fi->name, "sym.", 4): false;
	if (eob) {
		aop->fail = UT64_MAX;
	}
//	eprintf ("0x%llx\n", aop->addr);
	switch (aop->type) {
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_NOP:
		abb->wasPad = true;
		/* do nothing */
		return NULL;
	case R_ANAL_OP_TYPE_SWI:
		return NULL;
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_MJMP:
		eob = true;
		break;
	case R_ANAL_OP_TYPE_CALL:
//eprintf ("CALL 0x%"PFMT64x"\n", aop->addr);
		if (aop->jump != UT64_MAX) {
#if 0
			RFlagItem *fi = r_flag_get_i (abb->core->flags, aop->jump);
			if (fi) {
				if (r_anal_noreturn_at_name (abb->core->anal, fi->name)) {
					//if (r_anal_noreturn_at_addr (abb->core->anal, aop->jump))
					eob = true;
				}
			}
#endif
			appendNextBB (abb, aop->jump, 0, 'c');
		}
#if 0
		if (aop->fail != UT64_MAX && !eob) {
			appendNextBB (abb, aop->fail, 0, 0);
		}
		aop->jump = aop->fail; //UT64_MAX;
		aop->fail = UT64_MAX;
#endif
		break;
	case R_ANAL_OP_TYPE_CJMP:
		if (aop->jump != UT64_MAX) {
			appendNextBB (abb, aop->jump, 0, 0);
		}
		if (aop->fail != UT64_MAX && !eob) {
			appendNextBB (abb, aop->fail, 0, 0);
		}
		eob = true;
		break;
	case R_ANAL_OP_TYPE_JMP:
		eob = true;
		if (aop->jump != UT64_MAX) {
			appendNextBB (abb, aop->jump, 0, 0);
		}
		break;
	}
	if (abb->wasPad) {
		abb->wasPad = false;
		eob = true;
	}
	if (eob) {
		if (aop->addr < abb->bb_addr) {
			abb->bb_addr = aop->addr;
		}
		RAnalBlock *bb = R_NEW0 (RAnalBlock);
		bb->jump = aop->jump;
		bb->fail = aop->fail;
		bb->addr = abb->bb_addr;
		bb->size = aop->addr - abb->bb_addr + aop->size;
		if (bb->size < 1) {
			eprintf ("Invalid block size at 0x%08"PFMT64x "\n", bb->addr);
			// XXX
			bb->size = aop->size;
		}
		abb->bb_addr = bb->addr + bb->size;
		return bb;
	}
	return NULL;
}

// find functions

#define F(x, ...) sdb_fmt (0, x, ...)

static RAnalBlock *getBlock(AbbState *abb, ut64 addr) {
	return sdb_ptr_get (abb->bbdb, sdb_fmt (0, "ptr.0x%08" PFMT64x, addr), NULL);
}

static void printBasicBlocks(AbbState *abb, ut64 fcnaddr, ut64 addr) {
	RAnalBlock *bb = getBlock (abb, addr);
	if (!bb) {
		eprintf ("Missing basic block for 0x%08" PFMT64x "\n", addr);
		return;
	}
	if (sdb_bool_get (abb->bbdb, sdb_fmt (0, "bb.0x%08" PFMT64x ".0x%08" PFMT64x, fcnaddr, addr), NULL)) {
		return;
	}
	sdb_bool_set (abb->bbdb, sdb_fmt (0, "used.0x%08" PFMT64x, addr), true, 0);
	sdb_bool_set (abb->bbdb, sdb_fmt (0, "bb.0x%08" PFMT64x ".0x%08" PFMT64x, fcnaddr, addr), true, 0);
	r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %d", fcnaddr, bb->addr, bb->size);
	if (bb->jump != UT64_MAX) {
		r_cons_printf (" 0x%08" PFMT64x, bb->jump);
		if (bb->fail != UT64_MAX) {
			r_cons_printf (" 0x%08" PFMT64x, bb->fail);
		}
	}
	r_cons_newline ();
	if (bb->jump != UT64_MAX) {
		printBasicBlocks (abb, fcnaddr, bb->jump);
	}
	if (bb->fail != UT64_MAX) {
		printBasicBlocks (abb, fcnaddr, bb->fail);
	}
}

static void printFunction(RCore *core, ut64 addr, const char *name) {
	const char *pfx = r_config_get (core->config, "anal.fcnprefix");
	if (!pfx) {
		pfx = "fcn";
	}
	char *_name = name? (char *) name: r_str_newf ("%s.%" PFMT64x, pfx, addr);
	r_cons_printf ("af+ 0x%08" PFMT64x " %s\n", addr, _name);
	if (!name) {
		free (_name);
	}
}

static void findFunctions(RCore *core, AbbState *abb) {
	/*
	we consider functions to be the basic blocks referenced by CALLs
	*/
	RListIter *iter;
	AbbAddr *a;
	eprintf ("Found %d functions\n", r_list_length (abb->fcnents));
	r_list_foreach (abb->fcnents, iter, a) {
		printFunction (core, a->addr, NULL); //a->name);
		printBasicBlocks (abb, a->addr, a->addr);
	}
	RAnalBlock *bb;
	r_list_foreach (abb->bbs, iter, bb) {
// if there's a flag, consider it a function
		RFlagItem *fi = r_flag_get_i (core->flags, bb->addr);
		if (fi) {
			printFunction (core, bb->addr, fi->name);
		} else {
			// eprintf ("# orphan bb 0x%08"PFMT64x"\n", bb->addr);
			printFunction (core, bb->addr, NULL);
		}
		printBasicBlocks (abb, bb->addr, bb->addr);
		//	printFunction (a->addr, a->name);
		// printBasicBlocks (abb, ->addr, a->addr);
	}
#if 0
	RAnalBlock *bb;
	/* false positives ahead */
	/* mark all non-function bbs as functions */
	r_cons_printf ("# orphan basic blocks considered function entry points\n");
	r_list_foreach (abb->bbs, iter, bb) {
		if (sdb_bool_get (abb->bbdb, sdb_fmt (0, "used.0x%08"PFMT64x, bb->addr), 0)) {
			continue;
		}
		printFunction (bb->addr, NULL);
		printBasicBlocks (abb, bb->addr, bb->addr);
	}
#endif
}

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

static bool fcnAddBB (fcn_t *fcn, bb_t* block) {
	if (!fcn) {
		eprintf ("No function given to add a basic block\n");
		return false;
	}
	fcn->score += block->score;
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

static bool addBB (RList *block_list, ut64 start, ut64 end, ut64 jump, ut64 fail, bb_type_t type, int score) {
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

#define Fhandled(x) sdb_fmt(0, "handled.%"PFMT64x"", x)
R_API bool core_anal_bbs(RCore *core, ut64 len) {
	if (!r_io_is_valid_offset (core->io, core->offset, false)) {
		eprintf ("No valid offset given to analyze\n");
		return false;
	}

	Sdb *sdb = NULL;
	ut64 cur = 0;
	ut64 start = core->offset;
	ut64 size = len;
	ut64 b_start = start;
	RAnalOp *op;
	RListIter *iter;
	RListIter *fcn_iter;
	int block_score = 0;
	RList *block_list;
	bb_t *block = NULL;
	int invalid_instruction_barrier = -20000;


	block_list = r_list_new ();
	if (!block_list) {
		eprintf ("Failed to create block_list\n");
	}

	while (cur < size) {
		// magic number to fix huge section of invalid code fuzz files
		if (block_score < invalid_instruction_barrier) {
			break;
		}
		op = r_core_anal_op (core, start + cur);

		if (!op || !op->mnemonic) {
			block_score -= 10;
			cur++;
			continue;
		}

		if (op->mnemonic[0] == '?') {
			eprintf ("Cannot analyze opcode at %"PFMT64x"\n", start + cur);
			block_score -= 10;
			cur++;
			continue;
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_NOP:
			break;
		case R_ANAL_OP_TYPE_CALL:
			addBB (block_list, op->jump, UT64_MAX, UT64_MAX, UT64_MAX, CALL, block_score);
			break;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_JMP:
			addBB (block_list, b_start, start + cur + op->size, op->jump, UT64_MAX, END, block_score);
			b_start = start + cur + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_TRAP:
			// we dont want to add trap stuff
			if (b_start < start + cur) {
				addBB (block_list, b_start, start + cur, UT64_MAX, UT64_MAX, NORMAL, block_score);
			}
			b_start = start + cur + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_RET:
			addBB (block_list, b_start, start + cur + op->size, UT64_MAX, UT64_MAX, END, block_score);
			b_start = start + cur + op->size;
			block_score = 0;
			break;
		case R_ANAL_OP_TYPE_CJMP:
			addBB (block_list, b_start, start + cur + op->size, op->jump, start + cur + op->size, NORMAL, block_score);
			b_start = start + cur + op->size;
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
		op = NULL;
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

	while (block_list->length > 0) {
		block = r_list_pop (block_list);
		if (!block) {
			eprintf ("Failed to get next block from list\n");
			continue;
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

		sdb_ptr_set (sdb, sdb_fmt (0, "bb.0x%08"PFMT64x, block->start), block, 0);
		r_list_append (result, block);
	}

	// finally search for functions
	// we simply assume that non reached blocks or called blocks
	// are functions
	r_list_foreach (result, iter, block) {
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
					break;
				}
				// we ignore negative blocks
				if ((st64)(cur->end - cur->start) < 0) {
					break;
				}

				fcnAddBB (current_function, cur);

				if (cur->jump < UT64_MAX && !sdb_num_get (sdb, Fhandled(cur->jump), NULL)) {
					jump = sdb_ptr_get (sdb, sdb_fmt (0, "bb.0x%08"PFMT64x, cur->jump), NULL);
					if (!jump) {
						eprintf ("Failed to get jump block at 0x%"PFMT64x"\n", cur->jump);
						continue;
					}
					if (!r_stack_push (stack, (void*)jump)) {
						eprintf ("Failed to push jump block to stack\n");
					}
				}

				if (cur->fail < UT64_MAX && !sdb_num_get (sdb, Fhandled(cur->fail), NULL)) {
					fail = sdb_ptr_get (sdb, sdb_fmt (0, "bb.0x%08" PFMT64x, cur->fail), NULL);
					if (!fail) {
						eprintf ("Failed to get fail block at 0x%"PFMT64x"\n", cur->fail);
						continue;
					}
					if (!r_stack_push (stack, (void*)fail)) {
						eprintf ("Failed to push jump block to stack\n");
					}
				}
			}

			if (current_function->ends > 0) {
				printFunction (core, current_function->addr, NULL);
				r_list_foreach (current_function->bbs, fcn_iter, cur) {
					r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %llu 0x%08"PFMT64x" 0x%08"PFMT64x"\n"
						, block->start, cur->start, cur->end - cur->start, cur->jump, cur->fail);
				}
			}
			r_stack_free (stack);
			fcnFree (current_function);
		}
	}

	sdb_free (sdb);
	eprintf ("After merge %d blocks\n", result->length);
	r_list_free (result);
	r_list_free (block_list);
	return true;
}

R_API bool core_anal_bbs2(RCore *core, ut64 len) {
	AbbState *abb = abbstate_new (len);
	if (!abb) {
		return false;
	}
	int i;
	RAnalBlock *bb;
	RAnalOp aop;
	//RListIter *iter;
	ut64 at = core->offset;
	abb->addr = at;
	(void) r_io_read_at (core->io, abb->addr, abb->buf, len);
	int ti = -1;
	int oi = 0;
	abb->last = at;
	abb->core = core;
	abb->bb_addr = abb->addr;
	r_cons_break_push (NULL, NULL);
	eprintf ("Analyzing basic blocks from 0x%08" PFMT64x " to 0x%08" PFMT64x "\n", abb->addr, abb->addr + len);

	for (i = 0; i < len; i++) {
		if (r_cons_is_breaked ()) {
			break;
		}
		oi = i;
		ut64 obb_addr = abb->bb_addr;
mountain:
		if (r_anal_op (core->anal, &aop, abb->addr + i, abb->buf + i, R_MIN (R_MAX (0, len - i), 16)) < 1) {
			continue;
		}
		int next = bbExist (abb, at + i);
		if (next > 0) {
			i += next - 1;
			continue;
		}
		bb = parseOpcode (abb, &aop);
		if (bb) {
			/* register basic block */
			RFlagItem *fi = r_flag_get_i (core->flags, bb->addr);
			if (fi || i == 0) {
				AbbAddr *n = R_NEW0 (AbbAddr);
				n->name = fi? fi->name: NULL;
				n->addr = bb->addr;
				n->bits = 0; //bb->bits;
				// move this logic into a separate function
				if (fi) {
					if (fi->name && !strncmp (fi->name, "str.", 4)) {
						/* do nothing here */
					} else {
						n->type = 'c'; // call function :D
					}
				}
				r_list_append (abb->fcnents, n);
			}
			/* register basic block */
			sdb_num_set (abb->bbdb, sdb_fmt (0, "0x%08" PFMT64x, bb->addr), bb->size, 0);
			sdb_ptr_set (abb->bbdb, sdb_fmt (0, "ptr.0x%08" PFMT64x, bb->addr), bb, 0);
			if (bb->addr) {
				r_list_append (abb->bbs, bb);
				/* walk child blocks */
				if (!r_list_empty (abb->nextbbs)) {
					do {
						AbbAddr *nat = r_list_pop (abb->nextbbs);
						if (nat->type == 'c') {
							// eprintf ("CALL %llx\n", nat->addr);
							r_list_append (abb->fcnents, nat);
						}
						if (!bbExist (abb, nat->addr)) {
							if (nat->addr > at && nat->addr < at + len) {
								if (ti == -1) {
									ti = i;
								}
								i = nat->addr - at;
								abb->bb_addr = nat->addr;
								if (nat->type == 'c') {
									//			r_list_append (abb->fcnents, nat);
								} else {
									free (nat);
								}
								goto mountain;
							} else {
								eprintf ("Out of bounds basic block for 0x%08" PFMT64x "\n", nat->addr);
							}
						}
						free (nat);
					} while (!r_list_empty (abb->nextbbs));
					ti = -1;
				}
				i = oi;
				abb->bb_addr = obb_addr;
			}
		}
		i += aop.size - 1;
		r_anal_op_fini (&aop);
	}
	r_cons_break_pop ();

	eprintf ("Found %d basic blocks\n", r_list_length (abb->bbs));
	findFunctions (core, abb);

#if 0
	// show results
	r_list_foreach (abb->bbs, iter, bb) {
		RFlagItem *f = r_flag_get_at (core->flags, bb->addr, true);
		char *name;
		if (f) {
			if (f->offset != bb->addr) {
				name = r_str_newf ("%s+0x%x", f->name, bb->addr - f->offset);
			} else {
				name = strdup (f->name);
			}
		} else {
			name = r_str_newf ("bb.%"PFMT64x, bb->addr);
		}
		r_cons_printf ("agn 0x%08"PFMT64x " \"%s\"\n", bb->addr, name);
		free (name);
	}
	r_list_foreach (abb->bbs, iter, bb) {
		if (bb->jump != UT64_MAX) {
			r_cons_printf ("age 0x%08"PFMT64x " 0x%08"PFMT64x "\n", bb->addr, bb->jump);
		}
		if (bb->fail != UT64_MAX) {
			r_cons_printf ("age 0x%08"PFMT64x " 0x%08"PFMT64x "\n", bb->addr, bb->fail);
		}
	}
#endif
	abbstate_free (abb);
	return true;
}
