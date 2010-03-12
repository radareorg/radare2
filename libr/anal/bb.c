/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalysisBB *r_anal_bb_new() {
	return r_anal_bb_init (MALLOC_STRUCT (RAnalysisBB));
}

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_bb_free;
	return list;
}

R_API void r_anal_bb_free(void *bb) {
	if (bb && ((RAnalysisBB*)bb)->aops)
		r_list_destroy (((RAnalysisBB*)bb)->aops);
	free (bb);
}

R_API RAnalysisBB *r_anal_bb_init(RAnalysisBB *bb) {
	if (bb) {
		memset (bb, 0, sizeof (RAnalysisBB));
		bb->addr = -1;
		bb->jump = -1;
		bb->fail = -1;
		bb->aops = r_anal_aop_list_new();
	}
	return bb;
}

R_API int r_anal_bb(RAnalysis *anal, RAnalysisBB *bb, ut64 addr, ut8 *buf, ut64 len) {
	RAnalysisAop *aop;
	int oplen, idx = 0;

	if (bb->addr == -1)
		bb->addr = addr;
	while (idx < len) {
		if (!(aop = r_anal_aop_new())) {
			eprintf ("Error: new (aop)\n");
			return R_ANAL_RET_ERROR;
		}
		if ((oplen = r_anal_aop (anal, aop, addr+idx, buf+idx, len-idx)) == 0) {
			r_anal_aop_free (aop);
			if (idx == 0)
				return R_ANAL_RET_ERROR;
			else break;
		}
		idx += oplen;
		bb->size += oplen;
		r_list_append (bb->aops, aop);
		switch (aop->type) {
		case R_ANAL_OP_TYPE_CJMP:
			bb->fail = aop->fail;
		case R_ANAL_OP_TYPE_JMP:
			bb->jump = aop->jump;
		case R_ANAL_OP_TYPE_RET:
			return R_ANAL_RET_END;
		}
	}
	return bb->size;
}

R_API int r_anal_bb_split(RAnalysis *anal, RAnalysisBB *bb, RList *bbs, ut64 addr) {
	RAnalysisBB *bbi;
	RAnalysisAop *aopi;
	RListIter *iter;

	r_list_foreach (bbs, iter, bbi)
		if (addr == bbi->addr)
			return R_ANAL_RET_DUP;
		else if (addr > bbi->addr && addr < bbi->addr + bbi->size) {
			r_list_append (bbs, bb);
			bb->addr = addr;
			bb->size = bbi->addr + bbi->size - addr;
			bb->jump = bbi->jump;
			bb->fail = bbi->fail;
			bbi->size = addr - bbi->addr;
			bbi->jump = addr;
			bbi->fail = -1;
			iter = r_list_iterator (bbi->aops);
			while (r_list_iter_next (iter)) {
				aopi = r_list_iter_get (iter);
				if (aopi->addr >= addr) {
					r_list_split (bbi->aops, aopi);
					r_list_append (bb->aops, aopi);
				}
			}
			return R_ANAL_RET_END;
		}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_bb_overlap(RAnalysis *anal, RAnalysisBB *bb, RList *bbs) {
	RAnalysisBB *bbi;
	RAnalysisAop *aopi;
	RListIter *iter;

	r_list_foreach (bbs, iter, bbi)
		if (bbi->addr > bb->addr && bbi->addr < bb->addr+bb->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			r_list_foreach (bb->aops, iter, aopi)
				if (aopi->addr >= bbi->addr)
					r_list_unlink (bb->aops, aopi);
			r_list_append (bbs, bb);
			return R_ANAL_RET_END;
		}
	return R_ANAL_RET_NEW;
}
