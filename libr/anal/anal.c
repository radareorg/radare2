/* radare - LGPL - Copyright 2009-2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include "../config.h"

/* plugin pointers */
extern RAnalysisHandle r_anal_plugin_x86;
extern RAnalysisHandle r_anal_plugin_x86_bea;
extern RAnalysisHandle r_anal_plugin_ppc;

static struct r_anal_handle_t *anal_static_plugins[] = 
	{ R_ANAL_STATIC_PLUGINS };

R_API RAnalysis *r_anal_new() {
	return r_anal_init (MALLOC_STRUCT (RAnalysis));
}

R_API RAnalysisBB *r_anal_bb_new() {
	return r_anal_bb_init (MALLOC_STRUCT (RAnalysisBB));
}

R_API RAnalysisAop *r_anal_aop_new() {
	return r_anal_aop_init (MALLOC_STRUCT (RAnalysisAop));
}

R_API RAnalysisFcn *r_anal_fcn_new() {
	return r_anal_fcn_init (MALLOC_STRUCT (RAnalysisFcn));
}

R_API RAnalysisRef *r_anal_ref_new() {
	return r_anal_ref_init (MALLOC_STRUCT (RAnalysisRef));
}

R_API RAnalysisVar *r_anal_var_new() {
	return r_anal_var_init (MALLOC_STRUCT (RAnalysisVar));
}

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_bb_free;
	return list;
}

R_API RList *r_anal_aop_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_std_free;
	return list;
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_fcn_free;
	return list;
}

R_API RList *r_anal_ref_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_std_free;
	return list;
}

R_API RList *r_anal_var_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_var_free;
	return list;
}

R_API RAnalysis *r_anal_free(RAnalysis *a) {
	/* TODO: Free a->anals here */
	r_list_destroy (a->bbs);
	free (a);
	return NULL;
}

R_API void r_anal_std_free(void *ptr) {
	free (ptr);
}

R_API void r_anal_bb_free(void *bb) {
	if (bb && ((RAnalysisBB*)bb)->aops)
		r_list_destroy (((RAnalysisBB*)bb)->aops);
	free (bb);
}

R_API void r_anal_fcn_free(void *fcn) {
	if (fcn) {
		if (((RAnalysisFcn*)fcn)->name)
			free (((RAnalysisFcn*)fcn)->name);
		if (((RAnalysisFcn*)fcn)->vars)
			r_list_destroy (((RAnalysisFcn*)fcn)->vars);
	}
	free (fcn);
}

R_API void r_anal_var_free(void *var) {
	if (var && ((RAnalysisVar*)var)->name)
		free (((RAnalysisVar*)var)->name);
	free (var);
}

R_API RAnalysis *r_anal_init(RAnalysis *anal) {
	int i;

	if (anal) {
		memset (anal, 0, sizeof (RAnalysis));
		anal->bbs = r_anal_bb_list_new ();
		anal->fcns = r_anal_fcn_list_new ();
		r_anal_set_bits (anal, 32);
		r_anal_set_big_endian (anal, R_FALSE);
		INIT_LIST_HEAD (&anal->anals);
		for (i=0; anal_static_plugins[i]; i++)
			r_anal_add (anal, anal_static_plugins[i]);
	}
	return anal;
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

R_API RAnalysisAop *r_anal_aop_init(RAnalysisAop *aop) {
	if (aop) {
		memset (aop, 0, sizeof (RAnalysisAop));
		aop->addr = -1;
		aop->jump = -1;
		aop->fail = -1;
	}
	return aop;
}

R_API RAnalysisFcn *r_anal_fcn_init(RAnalysisFcn *fcn) {
	if (fcn) {
		memset (fcn, 0, sizeof (RAnalysisFcn));
		fcn->addr = -1;
		fcn->vars = r_anal_var_list_new ();
		fcn->refs = r_anal_ref_list_new ();
		fcn->xrefs = r_anal_ref_list_new ();
	}
	return fcn;
}

R_API RAnalysisRef *r_anal_ref_init(RAnalysisRef *ref) {
	if (ref)
		*ref = -1;
	return ref;
}

R_API RAnalysisVar *r_anal_var_init(RAnalysisVar *var) {
	if (var) {
		memset (var, 0, sizeof (RAnalysisVar));
		var->addr = -1;
	}
	return var;
}

R_API void r_anal_set_user_ptr(RAnalysis *anal, void *user) {
	anal->user = user;
}

R_API int r_anal_add(RAnalysis *anal, struct r_anal_handle_t *foo) {
	if (foo->init)
		foo->init(anal->user);
	list_add_tail(&(foo->list), &(anal->anals));
	return R_TRUE;
}

// TODO: Must be deprecated
R_API int r_anal_list(RAnalysis *anal) {
	struct list_head *pos;
	list_for_each_prev(pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		printf (" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_anal_use(RAnalysis *anal, const char *name) {
	struct list_head *pos;
	list_for_each_prev (pos, &anal->anals) {
		struct r_anal_handle_t *h = list_entry(pos, struct r_anal_handle_t, list);
		if (!strcmp (h->name, name)) {
			anal->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_anal_set_bits(RAnalysis *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 32:
	case 64:
		anal->bits = bits;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_anal_set_big_endian(RAnalysis *anal, int bigend) {
	anal->big_endian = bigend;
	return R_TRUE;
}

R_API int r_anal_aop(RAnalysis *anal, RAnalysisAop *aop, ut64 addr, const ut8 *data, int len) {
	if (anal && aop && anal->cur && anal->cur->aop)
		return anal->cur->aop(anal, aop, addr, data, len);
	return 0;
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
			r_anal_std_free (aop);
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
	struct r_anal_bb_t *bbi;
	struct r_anal_aop_t *aopi;
	RListIter *iter;

	iter = r_list_iterator (bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
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
	}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_bb_overlap(RAnalysis *anal, RAnalysisBB *bb, RList *bbs) {
	struct r_anal_bb_t *bbi;
	struct r_anal_aop_t *aopi;
	RListIter *iter;

	iter = r_list_iterator (bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (bbi->addr > bb->addr && bbi->addr < bb->addr+bb->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			iter = r_list_iterator (bb->aops);
			while (r_list_iter_next (iter)) {
				aopi = r_list_iter_get (iter);
				if (aopi->addr >= bbi->addr) {
					r_list_unlink (bb->aops, aopi);
				}
			}
			r_list_append (bbs, bb);
			return R_ANAL_RET_END;
		}
	}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_fcn(RAnalysis *anal, RAnalysisFcn *fcn, ut64 addr, ut8 *buf, ut64 len) {
	RAnalysisRef *ref;
	RAnalysisAop aop;
	int oplen, idx = 0;

	if (fcn->addr == -1)
		fcn->addr = addr;
	while (idx < len) {
		if ((oplen = r_anal_aop (anal, &aop, addr+idx, buf+idx, len-idx)) == 0) {
			if (idx == 0)
				return R_ANAL_RET_ERROR;
			else break;
		}
		idx += oplen;
		fcn->size += oplen;
		switch (aop.type) {
		case R_ANAL_OP_TYPE_CALL:
			if (!(ref = r_anal_ref_new())) {
				eprintf ("Error: new (ref)\n");
				return R_ANAL_RET_ERROR;
			}
			*ref = aop.jump;
			r_list_append (fcn->refs, ref);
			break;
		case R_ANAL_OP_TYPE_RET:
			return R_ANAL_RET_END;
		}
	}
	return fcn->size;
}
