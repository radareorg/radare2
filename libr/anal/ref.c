/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalRef *r_anal_ref_new() { // TODO: deprecate?
	RAnalRef *ref = R_NEW (RAnalRef);
	if (ref) {
		ref->addr = -1;
		ref->type = R_ANAL_REF_TYPE_CODE; // HUH?
	}
	return ref;
}

// uh?
R_API RList *r_anal_ref_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_ref_free;
	return list;
}

R_API void r_anal_ref_free(void *ref) {
	free (ref);
}
