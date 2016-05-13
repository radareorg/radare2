/* radare - LGPL - Copyright 2010-2015 - pancake, nibble */
/* bb.c - basic block analysis */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#define DFLT_NINSTR 3

R_API RAnalBlock *r_anal_bb_new() {
	RAnalBlock *bb = R_NEW0 (RAnalBlock);
	if (!bb) return NULL;
	bb->addr = UT64_MAX;
	bb->jump = UT64_MAX;
	bb->fail = UT64_MAX;
	bb->switch_op = NULL;
	bb->type = R_ANAL_BB_TYPE_NULL;
#if R_ANAL_BB_HAS_OPS
	bb->ops = r_anal_op_list_new ();
#endif
	bb->cond = NULL;
	bb->fingerprint = NULL;
	bb->diff = r_anal_diff_new ();
	bb->label = NULL;
	bb->op_pos = R_NEWS0 (ut16, DFLT_NINSTR);
	bb->n_op_pos = DFLT_NINSTR;
	return bb;
}

R_API void r_anal_bb_free(RAnalBlock *bb) {
	if (!bb) return;
	r_anal_cond_free (bb->cond);
	free (bb->fingerprint);
	if (bb->diff) {
		r_anal_diff_free (bb->diff);
		bb->diff = NULL;
	}
	free (bb->op_bytes);
	if (bb->switch_op) {
		r_anal_switch_op_free (bb->switch_op);
	}
#if R_ANAL_BB_HAS_OPS
	r_list_free (bb->ops);
	bb->ops = NULL;
#endif
	bb->fingerprint = NULL;
	bb->cond = NULL;
	free (bb->label);
	free (bb->op_pos);
	free (bb);
}

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_new ();
	if (!list) return NULL;
	list->free = (void*)r_anal_bb_free;
	return list;
}

R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb, ut64 addr, ut8 *buf, ut64 len, int head) {
	RAnalOp *op = NULL;
	int oplen, idx = 0;

	if (bb->addr == -1) {
		bb->addr = addr;
	}
	len -= 16; // XXX: hack to avoid segfault by x86im
	while (idx < len) {
		// TODO: too slow object construction
		if (!(op = r_anal_op_new ())) {
			eprintf ("Error: new (op)\n");
			return R_ANAL_RET_ERROR;
		}
		if ((oplen = r_anal_op (anal, op, addr + idx, buf + idx, len - idx)) == 0) {
			r_anal_op_free (op);
			op = NULL;
			if (idx == 0) {
				VERBOSE_ANAL eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", addr+idx);
				return R_ANAL_RET_END;
			}
			break;
		}
		if (oplen < 1) {
			return R_ANAL_RET_END;
		}

		r_anal_bb_set_offset (bb, bb->ninstr, addr + idx - bb->addr);
		idx += oplen;
		bb->size += oplen;
		bb->ninstr++;
#if R_ANAL_BB_HAS_OPS
		r_list_append (bb->ops, op);
#endif
		if (head) {
			bb->type = R_ANAL_BB_TYPE_HEAD;
		}

		switch (op->type) {
		case R_ANAL_OP_TYPE_CMP:
			r_anal_cond_free (bb->cond);
			bb->cond = r_anal_cond_new_from_op (op);
			break;
		case R_ANAL_OP_TYPE_CJMP:
			if (bb->cond) {
				// TODO: get values from anal backend
				bb->cond->type = R_ANAL_COND_EQ;
			} else VERBOSE_ANAL eprintf ("Unknown conditional for block 0x%"PFMT64x"\n", bb->addr);
			bb->conditional = 1;
			bb->fail = op->fail;
			bb->jump = op->jump;
			bb->type |= R_ANAL_BB_TYPE_BODY;
			goto beach;
		case R_ANAL_OP_TYPE_JMP:
			bb->jump = op->jump;
			bb->type |= R_ANAL_BB_TYPE_BODY;
			goto beach;
		case R_ANAL_OP_TYPE_UJMP:
			bb->type |= R_ANAL_BB_TYPE_FOOT;
			goto beach;
		case R_ANAL_OP_TYPE_RET:
			bb->type |= R_ANAL_BB_TYPE_LAST;
			goto beach;
		case R_ANAL_OP_TYPE_LEA:
		{
			RAnalValue *src = op->src[0];
			if (src && src->reg && anal->reg) {
				const char *pc = anal->reg->name[R_REG_NAME_PC];
				RAnalValue *dst = op->dst;
				if (dst && dst->reg && !strcmp (src->reg->name, pc)) {
					int memref = anal->bits/8;
					ut8 b[8];
					ut64 ptr = idx+addr+src->delta;
					anal->iob.read_at (anal->iob.io, ptr, b, memref);
					r_anal_ref_add (anal, ptr, addr+idx-op->size, 'd');
				}
			}
		}
		}
		r_anal_op_free (op);
	}
	return bb->size;
beach:
	r_anal_op_free (op);
	return R_ANAL_RET_END;
}

R_API inline int r_anal_bb_is_in_offset (RAnalBlock *bb, ut64 off) {
	return (off >= bb->addr && off < bb->addr + bb->size);
}

R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off) {
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *bb;
	r_list_foreach (anal->fcns, iter, fcn)
		r_list_foreach (fcn->bbs, iter2, bb)
			if (r_anal_bb_is_in_offset (bb, off))
				return bb;
	return NULL;
}

/* return the offset of the i-th instruction in the basicblock bb.
 * If the index of the instruction is not valid, it returns UT16_MAX  */
R_API ut16 r_anal_bb_offset_inst(RAnalBlock *bb, int i) {
	if (i < 0 || i >= bb->ninstr) return UT16_MAX;
	return i > 0 ? bb->op_pos[i - 1] : 0;
}

/* set the offset of the i-th instruction in the basicblock bb */
R_API void r_anal_bb_set_offset(RAnalBlock *bb, int i, ut16 v) {
	// the offset of the instruction 0 is not stored because always 0
	if (i > 0) {
		if (i >= bb->n_op_pos) {
			bb->n_op_pos = i * 2;
			bb->op_pos = realloc (bb->op_pos, bb->n_op_pos * sizeof (*bb->op_pos));
		}
		bb->op_pos[i - 1] = v;
	}
}

/* return the address of the instruction that occupy a given offset.
 * If the offset is not part of the given basicblock, UT64_MAX is returned. */
R_API ut64 r_anal_bb_opaddr_at(RAnalBlock *bb, ut64 off) {
	ut16 delta, delta_off, last_delta;
	int i;

	if (!r_anal_bb_is_in_offset (bb, off)) return UT64_MAX;

	last_delta = 0;
	delta_off = off - bb->addr;
	for (i = 0; i < bb->ninstr; i++) {
		delta = r_anal_bb_offset_inst (bb, i);
		if (delta > delta_off) {
			return bb->addr + last_delta;
		}
		last_delta = delta;
	}
	return UT64_MAX;
}
