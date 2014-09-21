/* radare - LGPL - Copyright 2014 - condret */

#include <r_anal.h>
#include <r_list.h>
#include <r_types.h>


R_API RAnalCycleFrame *r_anal_cycle_frame_new () {
	RAnalCycleFrame *cf = R_NEW0 (RAnalCycleFrame);
	cf->hooks = r_list_new ();
	return cf;
}

R_API void r_anal_cycle_frame_free (RAnalCycleFrame *cf) {
	if (!cf) return;
	r_list_free (cf->hooks);
	free (cf);
}
