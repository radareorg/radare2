/* radare - LGPL - Copyright 2010-2011 */
/* - nibble<.ds@gmail.com> + pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalBlock *r_anal_bb_new() {
	RAnalBlock *bb = R_NEW (RAnalBlock);
	if (!bb) return NULL;
	memset (bb, 0, sizeof (RAnalBlock));
	bb->addr = -1;
	bb->jump = -1;
	bb->fail = -1;
	bb->type = R_ANAL_BB_TYPE_NULL;
#if R_ANAL_BB_HAS_OPS
	bb->ops = r_anal_op_list_new ();
#endif
	bb->cond = NULL;
	bb->fingerprint = NULL;
	bb->diff = r_anal_diff_new ();
	return bb;
}

R_API void r_anal_bb_free(RAnalBlock *bb) {
	if (!bb) return;
	r_anal_cond_free (bb->cond);
	free (bb->fingerprint);
	if (bb->diff)
		r_anal_diff_free (bb->diff);
#if R_ANAL_BB_HAS_OPS
	if (bb->ops)
		r_list_free (bb->ops);
	bb->ops = NULL;
	bb->diff = NULL;
#endif
	bb->fingerprint = NULL;
	bb->cond = NULL;
	free (bb);
}

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_new ();
	list->free = (void*)r_anal_bb_free;
	return list;
}

R_API int r_anal_bb(RAnal *anal, RAnalBlock *bb, ut64 addr, ut8 *buf, ut64 len, int head) {
	RAnalOp *op = NULL;
	int oplen, idx = 0;

	if (bb->addr == -1)
		bb->addr = addr;
	len -= 16; // XXX: hack to avoid segfault by x86im
	while (idx < len) {
		r_anal_op_free (op);
		if (!(op = r_anal_op_new ())) {
			eprintf ("Error: new (op)\n");
			return R_ANAL_RET_ERROR;
		}
		if ((oplen = r_anal_op (anal, op, addr+idx, buf+idx, len-idx)) == 0) {
			r_anal_op_free (op);
			op = NULL;
			if (idx == 0) {
				VERBOSE_ANAL eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", addr+idx);
				return R_ANAL_RET_END;
			}
			break;
		}
		idx += oplen;
		bb->size += oplen;
		bb->ninstr++;
#if R_ANAL_BB_HAS_OPS
		r_list_append (bb->ops, op);
#endif
		if (head)
			bb->type = R_ANAL_BB_TYPE_HEAD;
		switch (op->type) {
		case R_ANAL_OP_TYPE_CMP:
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
		}
	}
	return bb->size;
beach:
	r_anal_op_free (op);
	return R_ANAL_RET_END;
}

R_API RAnalBlock *r_anal_bb_from_offset(RAnal *anal, ut64 off) {
	RListIter *iter, *iter2;
	RAnalFcn *fcn;
	RAnalBlock *bb;
	r_list_foreach (anal->fcns, iter, fcn)
		r_list_foreach (fcn->bbs, iter2, bb)
			if (off >= bb->addr && off < bb->addr + bb->size)
				return bb;
	return NULL;
}
