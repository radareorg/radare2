/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_bp.h>

/* TODO */
R_API void r_bp_watch_add() {
	// set steppy continuations
	// after each iteration we must check the conditions of
	// all the RBreakpointWatch
}

R_API void r_bp_watch_del() {
}

/* TODO: move into _watch */
R_API int r_bp_add_cond(struct r_bp_t *bp, const char *cond) {
	// TODO: implement contitional breakpoints
	bp->stepcont = R_TRUE;
	return 0;
}

R_API int r_bp_del_cond(struct r_bp_t *bp, int idx) {
	// add contitional
	bp->stepcont = R_FALSE;
	return R_TRUE;
}

