/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalOp *r_anal_aop_new() {
	RAnalOp *aop;

	aop = R_NEW (RAnalOp);
	if (aop) {
		memset (aop, 0, sizeof (RAnalOp));
		aop->addr = -1;
		aop->jump = -1;
		aop->fail = -1;
	}
	return aop;
}

R_API RList *r_anal_aop_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_aop_free;
	return list;
}

R_API void r_anal_aop_free(void *aop) {
	free (aop);
}

R_API int r_anal_aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *data, int len) {
	if (anal && aop && anal->cur && anal->cur->aop)
		return anal->cur->aop (anal, aop, addr, data, len);
	return 0;
}
