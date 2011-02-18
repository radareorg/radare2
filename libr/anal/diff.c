/* radare - LGPL - Copyright 2010 - nibble<.ds@gmail.com> */

#include <r_anal.h>
#include <r_util.h>

R_API RAnalDiff *r_anal_diff_new() {
	RAnalDiff *diff = R_NEW (RAnalDiff);
	if (diff) {
		diff->type = R_ANAL_DIFF_TYPE_NULL;
		diff->addr = -1;
		diff->name = NULL;
	}
	return diff;
}


R_API void* r_anal_diff_free(RAnalDiff *diff) {
	if (diff && diff->name)
		free (diff->name);
	free (diff);
	return NULL;
}
