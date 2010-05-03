/* radare - LGPL - Copyright 2009 */
/*   nibble<.ds@gmail.com> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include "x86/dislen/dislen.h"

static int aop(RAnal *anal, RAnalAop *aop, ut64 addr, const ut8 *data, int len) {
	return 0;
}

struct r_anal_handle_t r_anal_plugin_x86_x86im = {
	.name = "x86_x86im",
	.desc = "X86 x86im analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_x86im
};
#endif
