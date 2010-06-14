/* radare - LGPL - Copyright 2010 */
/*   pancake<nopcode.org> */

#include <r_anal.h>

R_API RAnalCond *r_anal_cond_new() {
	RAnalCond *cond = R_NEW (RAnalCond);
	memset (cond, 0, sizeof (RAnalCond));
	return cond;
}
