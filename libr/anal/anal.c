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

R_API RList *r_anal_bb_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_bb_free;
	return list;
}

R_API RList *r_anal_aop_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_aop_free;
	return list;
}

R_API RAnalysis *r_anal_free(RAnalysis *a) {
	/* TODO: Free a->anals here */
	r_list_destroy (a->bbs);
	free (a);
	return NULL;
}

R_API void r_anal_bb_free(void *bb) {
	if (bb) {
		r_list_destroy (((RAnalysisBB*)bb)->aops);
		free (bb);
	}
}

R_API void r_anal_aop_free(void *aop) {
	free (aop);
}

R_API RAnalysis *r_anal_init(RAnalysis *anal) {
	int i;

	if (anal) {
		memset (anal, 0, sizeof (RAnalysis));
		anal->bbs = r_anal_bb_list_new();
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
		aop->jump = -1;
		aop->fail = -1;
	}
	return aop;
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
			return -1;
		}
		if ((oplen = r_anal_aop (anal, aop, addr+idx, buf+idx, len-idx)) == 0) {
			r_anal_aop_free (aop);
			break;
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
			return 0;
		}
	}
	return bb->size;
}
